"""Key files and the INI configuration file."""

from __future__ import annotations

import base64
import binascii
import configparser
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from Crypto.PublicKey.ECC import EccKey

from .endpoint import Address, Settings
from .protocol import (
    generate_identity,
    identity_from_seed,
    identity_seed,
    public_key_from_bytes,
    raw_public_bytes,
)

log = logging.getLogger("minivpn")

DEFAULT_PORT = 51820
DEFAULT_TUN_ADDRESS = {"server": "10.8.0.1/24", "client": "10.8.0.2/24"}


class ConfigError(Exception):
    pass


def encode_public_key(key: EccKey) -> str:
    return base64.b64encode(raw_public_bytes(key)).decode()


def _decode_key_bytes(text: str, what: str) -> bytes:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise ConfigError(f"{what} is not valid base64") from None
    if len(raw) != 32:
        raise ConfigError(f"{what} must decode to 32 bytes")
    return raw


def decode_public_key(text: str) -> EccKey:
    raw = _decode_key_bytes(text, "peer_public_key")
    try:
        return public_key_from_bytes(raw)
    except ValueError:
        raise ConfigError("peer_public_key is not a valid Ed25519 public key") from None


def generate_keypair(prefix: str) -> tuple[Path, Path, str]:
    """Create <prefix>.key (owner-only) and <prefix>.pub; never overwrite."""
    private_path = Path(f"{prefix}.key")
    public_path = Path(f"{prefix}.pub")
    private_path.parent.mkdir(parents=True, exist_ok=True)

    key = generate_identity()
    private_raw = identity_seed(key)
    public_text = encode_public_key(key.public_key())

    try:
        descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ConfigError(f"{private_path} already exists, not overwriting") from None
    with os.fdopen(descriptor, "w") as handle:
        handle.write(base64.b64encode(private_raw).decode() + "\n")
    public_path.write_text(public_text + "\n")
    return private_path, public_path, public_text


def load_private_key(path: Path) -> EccKey:
    try:
        text = path.read_text()
        mode = path.stat().st_mode
    except OSError as error:
        raise ConfigError(f"cannot read private key {path}: {error.strerror}") from None
    if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
        log.warning("private key %s is readable by other users", path)
    return identity_from_seed(_decode_key_bytes(text, str(path)))


def parse_address(text: str, what: str) -> Address:
    host, separator, port = text.strip().rpartition(":")
    if not separator or not host:
        raise ConfigError(f"{what} must look like host:port")
    try:
        number = int(port)
    except ValueError:
        raise ConfigError(f"{what} has an invalid port") from None
    if not 0 <= number <= 65535:
        raise ConfigError(f"{what} has an invalid port")
    return host, number


@dataclass(frozen=True)
class Config:
    role: str
    identity: EccKey
    peer_public: EccKey
    listen: Address
    remote: Address | None
    tun_name: str
    tun_address: str
    tun_mtu: int
    settings: Settings


def load_config(path: str, role: str) -> Config:
    config_path = Path(path)
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with config_path.open(encoding="utf-8") as handle:
            parser.read_file(handle)
    except OSError as error:
        raise ConfigError(f"cannot read {path}: {error.strerror}") from None
    except configparser.Error as error:
        raise ConfigError(f"{path} is malformed: {error}") from None
    if "minivpn" not in parser:
        raise ConfigError(f"{path} has no [minivpn] section")
    section = parser["minivpn"]

    def required(name: str) -> str:
        try:
            return section[name]
        except KeyError:
            raise ConfigError(f"{path}: missing setting '{name}'") from None

    identity = load_private_key(config_path.parent / required("private_key"))
    peer_public = decode_public_key(required("peer_public_key"))

    if role == "server":
        listen = parse_address(section.get("listen", f"0.0.0.0:{DEFAULT_PORT}"), "listen")
        remote = None
    else:
        listen = ("0.0.0.0", 0)
        remote = parse_address(required("remote"), "remote")

    defaults = Settings()
    try:
        settings = Settings(
            rekey_after_seconds=section.getfloat(
                "rekey_after_seconds", defaults.rekey_after_seconds
            ),
            rekey_after_packets=section.getint(
                "rekey_after_packets", defaults.rekey_after_packets
            ),
        )
        mtu = section.getint("tun_mtu", 1400)
    except ValueError as error:
        raise ConfigError(f"{path}: {error}") from None

    return Config(
        role=role,
        identity=identity,
        peer_public=peer_public,
        listen=listen,
        remote=remote,
        tun_name=section.get("tun_name", "minivpn0"),
        tun_address=section.get("tun_address", DEFAULT_TUN_ADDRESS[role]),
        tun_mtu=mtu,
        settings=settings,
    )
