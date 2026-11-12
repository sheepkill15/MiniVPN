"""Command line entry point: one program, --server or --client."""

from __future__ import annotations

import argparse
import logging
import socket
import sys

from .apps import ChatApplication, TunError, open_tun
from .config import Config, ConfigError, generate_keypair, load_config
from .endpoint import ClientEndpoint, Endpoint, ServerEndpoint
from .runner import Runner

log = logging.getLogger("minivpn")


def _parse_arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="minivpn", description="Simple encrypted, mutually authenticated UDP tunnel."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--server", action="store_true", help="run as the server")
    mode.add_argument("--client", action="store_true", help="run as the client")
    mode.add_argument(
        "--keygen",
        metavar="PREFIX",
        help="create PREFIX.key and PREFIX.pub (an Ed25519 key pair) and exit",
    )
    parser.add_argument("-c", "--config", help="path to the configuration file")
    parser.add_argument(
        "--chat", action="store_true", help="send text messages instead of IP packets"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    arguments = parser.parse_args(argv)
    if not arguments.keygen and not arguments.config:
        parser.error("--server and --client require --config")
    return arguments


def _keygen(prefix: str) -> None:
    private_path, public_path, public_text = generate_keypair(prefix)
    print(f"private key: {private_path} (keep this secret)")
    print(f"public key:  {public_path}")
    print(f"give this to the peer as peer_public_key:\n{public_text}")


def _build_endpoint(config: Config) -> Endpoint:
    if config.role == "server":
        return ServerEndpoint(config.identity, config.peer_public, config.settings)
    host, port = config.remote
    address = (socket.gethostbyname(host), port)
    return ClientEndpoint(config.identity, config.peer_public, address, config.settings)


def _run(arguments: argparse.Namespace) -> None:
    config = load_config(arguments.config, "server" if arguments.server else "client")
    endpoint = _build_endpoint(config)
    application = (
        ChatApplication()
        if arguments.chat
        else open_tun(config.tun_name, config.tun_address, config.tun_mtu)
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(config.listen)
            log.info("%s listening on UDP port %d", config.role, sock.getsockname()[1])
            Runner(endpoint, sock, application).run()
    finally:
        application.close()


def main(argv: list[str] | None = None) -> int:
    arguments = _parse_arguments(argv)
    logging.basicConfig(
        level=logging.DEBUG if arguments.verbose else logging.INFO,
        format="%(asctime)s %(message)s",
        datefmt="%H:%M:%S",
    )
    for stream in (sys.stdin, sys.stdout):
        stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        if arguments.keygen:
            _keygen(arguments.keygen)
        else:
            _run(arguments)
    except (ConfigError, TunError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"error: {error.strerror or error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass
    return 0
