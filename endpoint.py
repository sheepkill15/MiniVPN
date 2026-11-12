"""Client and server state machines (no sockets: datagrams in, datagrams out)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from Crypto.PublicKey.ECC import EccKey

from . import protocol
from .protocol import (
    DATA_TYPES,
    TYPE_CLIENT_HELLO,
    TYPE_KEEPALIVE,
    TYPE_SERVER_HELLO,
    ClientHandshake,
    CounterExhausted,
    HandshakeRejected,
    Session,
)

Address = tuple[str, int]

EVENT_ESTABLISHED = "established"
EVENT_REKEYED = "rekeyed"
EVENT_LOST = "lost"


@dataclass(frozen=True)
class Settings:
    timestamp_tolerance: float = 30.0
    handshake_retry: float = 2.0
    keepalive_interval: float = 10.0
    peer_timeout: float = 35.0
    old_key_grace: float = 10.0
    rekey_after_seconds: float = 600.0
    rekey_after_packets: int = 1_000_000


@dataclass
class Result:
    outgoing: list[tuple[bytes, Address]] = field(default_factory=list)
    delivered: list[tuple[int, bytes]] = field(default_factory=list)
    events: list[str] = field(default_factory=list)


class Endpoint:
    """State shared by both roles: key slots, data handling, expiry."""

    def __init__(
        self,
        identity: EccKey,
        peer_public: EccKey,
        settings: Settings | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.identity = identity
        self.peer_public = peer_public
        self.settings = settings or Settings()
        self.clock = clock
        self.peer_address: Address | None = None
        self.current: Session | None = None
        self.previous: Session | None = None
        self.pending: Session | None = None
        self.dropped = 0
        self._previous_expires = 0.0
        self._last_received = 0.0

    @property
    def established(self) -> bool:
        return self.current is not None

    def send(self, packet_type: int, payload: bytes) -> tuple[bytes, Address] | None:
        """Encrypt a packet for the peer, or return None if there is no session."""
        if self.current is None or self.peer_address is None:
            return None
        try:
            return self.current.seal(packet_type, payload), self.peer_address
        except CounterExhausted:
            self.current = None
            return None

    def receive(self, datagram: bytes, source: Address) -> Result:
        result = Result()
        if not datagram:
            self.dropped += 1
            return result
        packet_type = datagram[0]
        if packet_type in DATA_TYPES:
            self._receive_data(datagram, source, result)
        else:
            self._receive_handshake(packet_type, datagram, source, result)
        return result

    def tick(self) -> Result:
        """Run timers. Call a few times per second."""
        result = Result()
        now = self.clock()
        if self.previous is not None and now >= self._previous_expires:
            self.previous = None
        self._tick_role(now, result)
        return result

    def _receive_handshake(
        self, packet_type: int, datagram: bytes, source: Address, result: Result
    ) -> None:
        raise NotImplementedError

    def _tick_role(self, now: float, result: Result) -> None:
        raise NotImplementedError

    def _on_keepalive(self, result: Result) -> None:
        pass

    def _install_session(self, session: Session, result: Result) -> None:
        now = self.clock()
        rekeyed = self.current is not None
        self.previous = self.current
        self._previous_expires = now + self.settings.old_key_grace
        self.current = session
        self._last_received = now
        result.events.append(EVENT_REKEYED if rekeyed else EVENT_ESTABLISHED)

    def _drop_sessions(self, result: Result) -> None:
        self.current = None
        self.previous = None
        result.events.append(EVENT_LOST)

    def _receive_data(self, packet: bytes, source: Address, result: Result) -> None:
        opened = None
        if source == self.peer_address:
            for session in (self.current, self.previous):
                if session is not None:
                    opened = session.open(packet)
                    if opened is not None:
                        break
        if opened is None and self.pending is not None:
            opened = self.pending.open(packet)
            if opened is not None:
                session, self.pending = self.pending, None
                self.peer_address = source
                self._install_session(session, result)
        if opened is None:
            self.dropped += 1
            return

        self._last_received = self.clock()
        packet_type, payload = opened
        if packet_type == TYPE_KEEPALIVE:
            self._on_keepalive(result)
        else:
            result.delivered.append((packet_type, payload))


class ServerEndpoint(Endpoint):
    """Responder.

    A two-message handshake gives the server no proof that the client is live,
    so a verified hello only creates a *pending* session. It replaces the
    running one when a data packet authenticates under the new keys, which a
    replayed hello cannot produce.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._newest_hello_ms = -1
        self._pending_expires = 0.0

    def _receive_handshake(
        self, packet_type: int, datagram: bytes, source: Address, result: Result
    ) -> None:
        if packet_type != TYPE_CLIENT_HELLO:
            self.dropped += 1
            return
        now = self.clock()
        try:
            timestamp_ms = protocol.client_hello_timestamp(datagram)
            age = abs(now - timestamp_ms / 1000)
            if age > self.settings.timestamp_tolerance:
                raise HandshakeRejected
            if timestamp_ms <= self._newest_hello_ms:
                raise HandshakeRejected
            reply, (client_to_server, server_to_client) = protocol.accept_client_hello(
                self.identity, self.peer_public, datagram
            )
        except HandshakeRejected:
            self.dropped += 1
            return
        self._newest_hello_ms = timestamp_ms
        self.pending = Session(server_to_client, client_to_server, now)
        self._pending_expires = now + self.settings.handshake_retry * 5
        result.outgoing.append((reply, source))

    def _on_keepalive(self, result: Result) -> None:
        reply = self.send(TYPE_KEEPALIVE, b"")
        if reply is not None:
            result.outgoing.append(reply)

    def _tick_role(self, now: float, result: Result) -> None:
        if self.pending is not None and now >= self._pending_expires:
            self.pending = None
        if (
            self.current is not None
            and now - self._last_received >= self.settings.peer_timeout
        ):
            self._drop_sessions(result)


class ClientEndpoint(Endpoint):
    """Initiator: drives handshakes, retries, keepalives and rekeying."""

    def __init__(
        self,
        identity: EccKey,
        peer_public: EccKey,
        server_address: Address,
        settings: Settings | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(identity, peer_public, settings, clock)
        self.peer_address = server_address
        self._handshake: ClientHandshake | None = None
        self._handshake_sent = 0.0
        self._last_keepalive = 0.0

    def _start_handshake(self, now: float, result: Result) -> None:
        self._handshake = protocol.create_client_hello(
            self.identity, self.peer_public, int(now * 1000)
        )
        self._handshake_sent = now
        result.outgoing.append((self._handshake.hello, self.peer_address))

    def _receive_handshake(
        self, packet_type: int, datagram: bytes, source: Address, result: Result
    ) -> None:
        if (
            packet_type != TYPE_SERVER_HELLO
            or source != self.peer_address
            or self._handshake is None
        ):
            self.dropped += 1
            return
        try:
            client_to_server, server_to_client = protocol.finish_client_handshake(
                self.identity, self.peer_public, self._handshake, datagram
            )
        except HandshakeRejected:
            self.dropped += 1
            return
        self._handshake = None
        self._install_session(
            Session(client_to_server, server_to_client, self.clock()), result
        )
        self._send_keepalive(self.clock(), result)

    def _send_keepalive(self, now: float, result: Result) -> None:
        self._last_keepalive = now
        packet = self.send(TYPE_KEEPALIVE, b"")
        if packet is not None:
            result.outgoing.append(packet)

    def _needs_rekey(self, session: Session, now: float) -> bool:
        return (
            now - session.created_at >= self.settings.rekey_after_seconds
            or session.packets_sent + session.packets_received
            >= self.settings.rekey_after_packets
        )

    def _tick_role(self, now: float, result: Result) -> None:
        settings = self.settings
        if (
            self.current is not None
            and now - self._last_received >= settings.peer_timeout
        ):
            self._drop_sessions(result)

        if self._handshake is not None:
            if now - self._handshake_sent >= settings.handshake_retry:
                self._start_handshake(now, result)
        elif self.current is None or self._needs_rekey(self.current, now):
            self._start_handshake(now, result)
        if (
            self.current is not None
            and now - self._last_keepalive >= settings.keepalive_interval
        ):
            self._send_keepalive(now, result)
