"""Wire format and cryptography of the MiniVPN protocol.

Nothing in this module touches a socket or a clock, so every rule can be
exercised directly by the tests.

Wire format (all integers big-endian):

    ClientHello  type(1) | eC_pub(32) | nC(32) | timestamp_ms(8) | signature(64)
    ServerHello  type(1) | eS_pub(32) | nS(32) | signature(64)
    Data         type(1) | counter(8) | ciphertext + tag(16)

Failures never produce a reply and never say why they happened: every rejected
message ends as a single `HandshakeRejected` or a `None` from `Session.open`.
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol import DH
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from Crypto.Signature import eddsa

TYPE_CLIENT_HELLO = 0x01
TYPE_SERVER_HELLO = 0x02
TYPE_IP = 0x03
TYPE_MESSAGE = 0x04
TYPE_KEEPALIVE = 0x05
DATA_TYPES = frozenset({TYPE_IP, TYPE_MESSAGE, TYPE_KEEPALIVE})

KDF_INFO = b"minivpn v1"
CLIENT_SIGNATURE_CONTEXT = b"minivpn v1 client hello\x00"
SERVER_SIGNATURE_CONTEXT = b"minivpn v1 server hello\x00"

KEY_SIZE = 32
NONCE_SIZE = 32
SIGNATURE_SIZE = 64
TAG_SIZE = 16

_CLIENT_HELLO = struct.Struct(f">B{KEY_SIZE}s{NONCE_SIZE}sQ")
_SERVER_HELLO = struct.Struct(f">B{KEY_SIZE}s{NONCE_SIZE}s")
_DATA_HEADER = struct.Struct(">BQ")
_AEAD_NONCE = struct.Struct(">4xQ")

CLIENT_HELLO_SIZE = _CLIENT_HELLO.size + SIGNATURE_SIZE
SERVER_HELLO_SIZE = _SERVER_HELLO.size + SIGNATURE_SIZE
DATA_HEADER_SIZE = _DATA_HEADER.size

MAX_COUNTER = 2**64 - 1
REPLAY_WINDOW_SIZE = 64


class HandshakeRejected(Exception):
    """A handshake message was invalid. Deliberately carries no reason."""


class CounterExhausted(Exception):
    """The send counter ran out; sending more would reuse a nonce."""


def generate_identity() -> EccKey:
    """A fresh long-term Ed25519 key pair."""
    return ECC.generate(curve="ed25519")


def identity_from_seed(seed: bytes) -> EccKey:
    """Rebuild an Ed25519 private key from its 32-byte seed (RFC 8032)."""
    return eddsa.import_private_key(seed)


def identity_seed(identity: EccKey) -> bytes:
    return identity.seed


def public_key_from_bytes(raw: bytes) -> EccKey:
    """Parse a raw 32-byte Ed25519 public key; raises ValueError if invalid."""
    return eddsa.import_public_key(raw)


def raw_public_bytes(key: EccKey) -> bytes:
    """The raw 32-byte public key (works for private keys too)."""
    if key.has_private():
        key = key.public_key()
    return key.export_key(format="raw")


def sign(identity: EccKey, message: bytes) -> bytes:
    return eddsa.new(identity, "rfc8032").sign(message)


def _verify(public_key: EccKey, signature: bytes, message: bytes) -> None:
    try:
        eddsa.new(public_key, "rfc8032").verify(message, signature)
    except ValueError:
        raise HandshakeRejected from None


def _derive_directional_keys(
    ephemeral_private: EccKey,
    peer_ephemeral_public: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
) -> tuple[bytes, bytes]:
    """Return (k_client_to_server, k_server_to_client)."""
    try:
        peer = DH.import_x25519_public_key(peer_ephemeral_public)
        shared_secret = DH.key_agreement(
            eph_priv=ephemeral_private, eph_pub=peer, kdf=lambda secret: secret
        )
    except ValueError:
        raise HandshakeRejected from None
    if shared_secret == bytes(len(shared_secret)):
        raise HandshakeRejected
    return HKDF(
        shared_secret,
        KEY_SIZE,
        client_nonce + server_nonce,
        SHA256,
        num_keys=2,
        context=KDF_INFO,
    )


@dataclass
class ClientHandshake:
    """What the client remembers between sending ClientHello and the reply."""

    ephemeral_private: EccKey
    client_nonce: bytes
    hello: bytes


def create_client_hello(
    identity: EccKey,
    server_public: EccKey,
    timestamp_ms: int,
) -> ClientHandshake:
    ephemeral = ECC.generate(curve="curve25519")
    nonce = secrets.token_bytes(NONCE_SIZE)
    unsigned = _CLIENT_HELLO.pack(
        TYPE_CLIENT_HELLO,
        raw_public_bytes(ephemeral.public_key()),
        nonce,
        timestamp_ms,
    )
    signature = sign(
        identity, CLIENT_SIGNATURE_CONTEXT + raw_public_bytes(server_public) + unsigned
    )
    return ClientHandshake(ephemeral, nonce, unsigned + signature)


def client_hello_timestamp(hello: bytes) -> int:
    """Read the (still unauthenticated) timestamp of a ClientHello."""
    if len(hello) != CLIENT_HELLO_SIZE:
        raise HandshakeRejected
    return _CLIENT_HELLO.unpack_from(hello)[3]


def accept_client_hello(
    identity: EccKey,
    client_public: EccKey,
    hello: bytes,
) -> tuple[bytes, tuple[bytes, bytes]]:
    """Verify a ClientHello; return (ServerHello, directional keys).

    The caller is responsible for the freshness check on the timestamp. The
    server's ephemeral private key lives only inside this call.
    """
    if len(hello) != CLIENT_HELLO_SIZE:
        raise HandshakeRejected
    unsigned, signature = hello[:-SIGNATURE_SIZE], hello[-SIGNATURE_SIZE:]
    _verify(
        client_public,
        signature,
        CLIENT_SIGNATURE_CONTEXT + raw_public_bytes(identity.public_key()) + unsigned,
    )
    _, client_ephemeral, client_nonce, _ = _CLIENT_HELLO.unpack(unsigned)

    ephemeral = ECC.generate(curve="curve25519")
    server_nonce = secrets.token_bytes(NONCE_SIZE)
    reply_unsigned = _SERVER_HELLO.pack(
        TYPE_SERVER_HELLO,
        raw_public_bytes(ephemeral.public_key()),
        server_nonce,
    )
    signature = sign(
        identity,
        SERVER_SIGNATURE_CONTEXT
        + raw_public_bytes(client_public)
        + hello
        + reply_unsigned
    )
    keys = _derive_directional_keys(
        ephemeral, client_ephemeral, client_nonce, server_nonce
    )
    return reply_unsigned + signature, keys


def finish_client_handshake(
    identity: EccKey,
    server_public: EccKey,
    handshake: ClientHandshake,
    reply: bytes,
) -> tuple[bytes, bytes]:
    """Verify a ServerHello against our ClientHello; return directional keys."""
    if len(reply) != SERVER_HELLO_SIZE:
        raise HandshakeRejected
    unsigned, signature = reply[:-SIGNATURE_SIZE], reply[-SIGNATURE_SIZE:]
    _verify(
        server_public,
        signature,
        SERVER_SIGNATURE_CONTEXT
        + raw_public_bytes(identity.public_key())
        + handshake.hello
        + unsigned,
    )
    _, server_ephemeral, server_nonce = _SERVER_HELLO.unpack(unsigned)
    return _derive_directional_keys(
        handshake.ephemeral_private,
        server_ephemeral,
        handshake.client_nonce,
        server_nonce,
    )


class ReplayWindow:
    """Sliding bitmap of the most recently accepted counters."""

    def __init__(self, size: int = REPLAY_WINDOW_SIZE) -> None:
        self._size = size
        self._full_mask = (1 << size) - 1
        self._highest = -1
        self._seen = 0

    def is_acceptable(self, counter: int) -> bool:
        if counter > self._highest:
            return True
        age = self._highest - counter
        return age < self._size and not (self._seen >> age) & 1

    def mark(self, counter: int) -> None:
        if counter > self._highest:
            shift = counter - self._highest
            self._seen = (
                1 if shift >= self._size else ((self._seen << shift) | 1) & self._full_mask
            )
            self._highest = counter
        else:
            self._seen |= 1 << (self._highest - counter)


def _aead_nonce(counter: int) -> bytes:
    return _AEAD_NONCE.pack(counter)


class Session:
    """One set of directional traffic keys with their counters."""

    def __init__(self, send_key: bytes, receive_key: bytes, created_at: float) -> None:
        self._send_key = send_key
        self._receive_key = receive_key
        self._next_counter = 0
        self._window = ReplayWindow()
        self.created_at = created_at
        self.packets_received = 0

    @property
    def packets_sent(self) -> int:
        return self._next_counter

    def seal(self, packet_type: int, payload: bytes) -> bytes:
        if self._next_counter > MAX_COUNTER:
            raise CounterExhausted
        counter = self._next_counter
        self._next_counter += 1
        header = _DATA_HEADER.pack(packet_type, counter)
        cipher = ChaCha20_Poly1305.new(key=self._send_key, nonce=_aead_nonce(counter))
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        return header + ciphertext + tag

    def open(self, packet: bytes) -> tuple[int, bytes] | None:
        """Authenticate and decrypt a data packet, or return None."""
        if len(packet) < DATA_HEADER_SIZE + TAG_SIZE:
            return None
        header = packet[:DATA_HEADER_SIZE]
        packet_type, counter = _DATA_HEADER.unpack(header)
        if not self._window.is_acceptable(counter):
            return None
        ciphertext, tag = packet[DATA_HEADER_SIZE:-TAG_SIZE], packet[-TAG_SIZE:]
        cipher = ChaCha20_Poly1305.new(key=self._receive_key, nonce=_aead_nonce(counter))
        cipher.update(header)
        try:
            payload = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            return None
        self._window.mark(counter)
        self.packets_received += 1
        return packet_type, payload
