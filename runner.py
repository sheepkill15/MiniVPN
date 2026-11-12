"""Connects an endpoint to a UDP socket and an application (TUN or chat)."""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Protocol

from .endpoint import (
    EVENT_ESTABLISHED,
    EVENT_LOST,
    EVENT_REKEYED,
    Address,
    Endpoint,
    Result,
)

log = logging.getLogger("minivpn")

TICK_SECONDS = 0.25
_EVENT_TEXT = {
    EVENT_ESTABLISHED: "secure session established, peer authenticated",
    EVENT_REKEYED: "session keys replaced by a new handshake",
    EVENT_LOST: "peer stopped responding, session discarded",
}


class Application(Protocol):
    def run(self, runner: "Runner") -> None:
        """Read local input and call runner.submit until runner.stopping is set."""

    def deliver(self, packet_type: int, payload: bytes) -> None:
        """Handle a packet that was authenticated and decrypted."""

    def close(self) -> None:
        """Release what the application holds (called once, after run stops)."""


class Runner:
    def __init__(
        self, endpoint: Endpoint, sock: socket.socket, application: Application
    ) -> None:
        self.endpoint = endpoint
        self.sock = sock
        self.application = application
        self.stopping = threading.Event()
        self._lock = threading.Lock()
        self._reported_drops = 0

    def submit(self, packet_type: int, payload: bytes) -> bool:
        """Encrypt and send application data. False means no session yet."""
        with self._lock:
            packet = self.endpoint.send(packet_type, payload)
        if packet is None:
            return False
        self._transmit(*packet)
        return True

    def stop(self) -> None:
        self.stopping.set()

    def run(self) -> None:
        for target in (self._network_loop, self._timer_loop, self._application_loop):
            threading.Thread(target=target, daemon=True).start()
        while not self.stopping.wait(0.5):
            pass

    def _transmit(self, datagram: bytes, address: Address) -> None:
        try:
            self.sock.sendto(datagram, address)
        except OSError as error:
            log.debug("send failed: %s", error.strerror)

    def _apply(self, result: Result) -> None:
        for datagram, address in result.outgoing:
            self._transmit(datagram, address)
        for packet_type, payload in result.delivered:
            self.application.deliver(packet_type, payload)
        for event in result.events:
            log.info(_EVENT_TEXT[event])

    def _network_loop(self) -> None:
        self.sock.settimeout(0.5)
        while not self.stopping.is_set():
            try:
                datagram, address = self.sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                time.sleep(0.05)
                continue
            with self._lock:
                result = self.endpoint.receive(datagram, address)
            self._apply(result)

    def _timer_loop(self) -> None:
        while not self.stopping.wait(TICK_SECONDS):
            with self._lock:
                result = self.endpoint.tick()
                drops = self.endpoint.dropped
            self._apply(result)
            if drops != self._reported_drops:
                log.debug("dropped %d invalid packet(s)", drops - self._reported_drops)
                self._reported_drops = drops

    def _application_loop(self) -> None:
        try:
            self.application.run(self)
        finally:
            self.stop()
