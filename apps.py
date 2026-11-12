"""The two things a tunnel can carry: IP packets (TUN) and chat text."""

from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import select
import struct
import subprocess
import sys
import threading
import uuid
from pathlib import Path

from .protocol import TYPE_IP, TYPE_MESSAGE
from .runner import Runner

log = logging.getLogger("minivpn")

MAX_MESSAGE_BYTES = 1200

_TUNSETIFF = 0x400454CA
_IFF_TUN = 0x0001
_IFF_NO_PI = 0x1000


class TunError(Exception):
    pass


def open_tun(name: str, address: str, mtu: int) -> "LinuxTunApplication | WintunApplication":
    """Create the virtual interface the way this operating system supports."""
    if sys.platform.startswith("linux"):
        return LinuxTunApplication(name, address, mtu)
    if sys.platform == "win32":
        return WintunApplication(name, address, mtu)
    raise TunError("TUN mode needs Linux or Windows; use --chat on this system")


class LinuxTunApplication:
    """Moves IP packets between a Linux TUN interface and the tunnel."""

    def __init__(self, name: str, address: str, mtu: int) -> None:
        import fcntl

        self.mtu = mtu
        try:
            self.descriptor = os.open("/dev/net/tun", os.O_RDWR)
            request = struct.pack("16sH", name.encode(), _IFF_TUN | _IFF_NO_PI)
            fcntl.ioctl(self.descriptor, _TUNSETIFF, request)
            for command in (
                ["ip", "addr", "add", address, "dev", name],
                ["ip", "link", "set", name, "mtu", str(mtu), "up"],
            ):
                subprocess.run(command, check=True, capture_output=True)
        except PermissionError:
            raise TunError(
                "creating a TUN interface needs root; run with sudo or use --chat"
            ) from None
        except (OSError, subprocess.CalledProcessError) as error:
            raise TunError(f"could not set up {name}: {error}") from None
        log.info("interface %s is up with address %s", name, address)

    def run(self, runner: Runner) -> None:
        while not runner.stopping.is_set():
            ready, _, _ = select.select([self.descriptor], [], [], 0.5)
            if ready:
                runner.submit(TYPE_IP, os.read(self.descriptor, self.mtu + 64))

    def deliver(self, packet_type: int, payload: bytes) -> None:
        if packet_type != TYPE_IP:
            return
        try:
            os.write(self.descriptor, payload)
        except OSError:
            log.debug("kernel rejected a packet from the tunnel")

    def close(self) -> None:
        """Nothing to do: the kernel removes the interface when the process exits."""

_WINTUN_RING_CAPACITY = 0x400000  # 4 MiB, a power of two as Wintun requires
_WINTUN_MAX_PACKET = 0xFFFF
_ERROR_NO_MORE_ITEMS = 259
_WAIT_MILLISECONDS = 250


def adapter_guid(name: str) -> bytes:
    """A fixed GUID per adapter name, in the byte order Windows expects.

    With a random GUID Windows would treat every run as a brand new network
    ("Network 2", "Network 3", ...).
    """
    return uuid.uuid5(uuid.NAMESPACE_URL, f"minivpn:{name}").bytes_le


def netsh_commands(index: int, address: str, mtu: int) -> list[list[str]]:
    """The Windows counterpart of `ip addr add` and `ip link set mtu`."""
    try:
        interface = ipaddress.IPv4Interface(address)
    except ValueError:
        raise TunError(
            f"tun_address {address!r} must be an IPv4 address with a prefix, like 10.8.0.1/24"
        ) from None
    return [
        [
            "netsh", "interface", "ipv4", "set", "address", f"name={index}",
            "source=static", f"address={interface.ip}", f"mask={interface.netmask}",
        ],
        ["netsh", "interface", "ipv4", "set", "subinterface", str(index), f"mtu={mtu}"],
    ]


def _load_wintun() -> ctypes.CDLL:
    package = Path(__file__).resolve().parent
    candidates = (package / "wintun.dll", package.parent / "wintun.dll")
    path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        raise TunError(
            "wintun.dll not found: download it from https://www.wintun.net and copy "
            f"bin/amd64/wintun.dll to {package.parent}"
        )
    try:
        dll = ctypes.WinDLL(str(path), use_last_error=True)
    except OSError as error:
        raise TunError(
            f"could not load {path} ({error}); it must match Python's architecture"
        ) from None

    handle, dword = ctypes.c_void_p, ctypes.c_uint32
    signatures = {
        "WintunCreateAdapter": (handle, [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]),
        "WintunCloseAdapter": (None, [handle]),
        "WintunGetAdapterLUID": (None, [handle, ctypes.POINTER(ctypes.c_uint64)]),
        "WintunStartSession": (handle, [handle, dword]),
        "WintunEndSession": (None, [handle]),
        "WintunGetReadWaitEvent": (handle, [handle]),
        "WintunReceivePacket": (ctypes.c_void_p, [handle, ctypes.POINTER(dword)]),
        "WintunReleaseReceivePacket": (None, [handle, ctypes.c_void_p]),
        "WintunAllocateSendPacket": (ctypes.c_void_p, [handle, dword]),
        "WintunSendPacket": (None, [handle, ctypes.c_void_p]),
    }
    for function_name, (restype, argtypes) in signatures.items():
        function = getattr(dll, function_name)
        function.restype = restype
        function.argtypes = argtypes
    return dll


def _last_error_text() -> str:
    return ctypes.FormatError(ctypes.get_last_error()).strip()


class WintunApplication:
    """Moves IP packets between a Wintun adapter and the tunnel (Windows)."""

    def __init__(self, name: str, address: str, mtu: int) -> None:
        self._adapter = None
        self._session = None
        self._send_lock = threading.Lock() 
        self._state_lock = threading.Lock()
        self._closing = threading.Event()
        self._idle = threading.Event()
        self._idle.set()

        commands = netsh_commands(0, address, mtu)
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise TunError(
                "creating a Wintun adapter needs an Administrator terminal; or use --chat"
            )
        self._wintun = _load_wintun()
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self._kernel32.WaitForSingleObject.restype = ctypes.c_uint32
        iphlpapi = ctypes.WinDLL("iphlpapi")
        iphlpapi.ConvertInterfaceLuidToIndex.argtypes = [
            ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint32)
        ]
        iphlpapi.ConvertInterfaceLuidToIndex.restype = ctypes.c_uint32

        guid = (ctypes.c_char * 16).from_buffer_copy(adapter_guid(name))
        self._adapter = self._wintun.WintunCreateAdapter(name, "MiniVPN", guid)
        if not self._adapter:
            raise TunError(f"could not create adapter {name}: {_last_error_text()}")
        try:
            self._session = self._wintun.WintunStartSession(
                self._adapter, _WINTUN_RING_CAPACITY
            )
            if not self._session:
                raise TunError(f"could not start a session on {name}: {_last_error_text()}")
            self._read_event = self._wintun.WintunGetReadWaitEvent(self._session)

            luid = ctypes.c_uint64()
            self._wintun.WintunGetAdapterLUID(self._adapter, ctypes.byref(luid))
            index = ctypes.c_uint32()
            status = iphlpapi.ConvertInterfaceLuidToIndex(ctypes.byref(luid), ctypes.byref(index))
            if status:
                raise TunError(f"could not find the index of {name}: {ctypes.FormatError(status)}")
            commands = netsh_commands(index.value, address, mtu)
            for command in commands:
                done = subprocess.run(command, capture_output=True, text=True, errors="replace")
                if done.returncode:
                    raise TunError(
                        f"could not set up {name}: {' '.join(command[:5])} said "
                        f"{(done.stdout or done.stderr).strip()}"
                    )
        except BaseException:
            self.close()
            raise
        log.info("adapter %s is up with address %s", name, address)

    def run(self, runner: Runner) -> None:
        with self._state_lock:
            if self._closing.is_set():
                return
            self._idle.clear()
        try:
            while not runner.stopping.is_set() and not self._closing.is_set():
                packet = self._receive()
                if packet is None:
                    self._kernel32.WaitForSingleObject(self._read_event, _WAIT_MILLISECONDS)
                else:
                    runner.submit(TYPE_IP, packet)
        except TunError as error:
            log.error("%s", error)
        finally:
            self._idle.set()

    def _receive(self) -> bytes | None:
        size = ctypes.c_uint32()
        pointer = self._wintun.WintunReceivePacket(self._session, ctypes.byref(size))
        if not pointer:
            if ctypes.get_last_error() == _ERROR_NO_MORE_ITEMS:
                return None
            raise TunError(f"the adapter stopped: {_last_error_text()}")
        try:
            return ctypes.string_at(pointer, size.value)
        finally:
            self._wintun.WintunReleaseReceivePacket(self._session, pointer)

    def deliver(self, packet_type: int, payload: bytes) -> None:
        if packet_type != TYPE_IP or not 0 < len(payload) <= _WINTUN_MAX_PACKET:
            return
        with self._send_lock:
            if not self._session:
                return
            pointer = self._wintun.WintunAllocateSendPacket(self._session, len(payload))
            if not pointer:
                log.debug("Wintun send ring is full, packet dropped")
                return
            ctypes.memmove(pointer, payload, len(payload))
            self._wintun.WintunSendPacket(self._session, pointer)

    def close(self) -> None:
        """End the session and remove the adapter, so no stale one is left behind."""
        with self._state_lock:
            self._closing.set()
        self._idle.wait(2 * _WAIT_MILLISECONDS / 1000 + 1)
        with self._send_lock:
            if self._session:
                self._wintun.WintunEndSession(self._session)
                self._session = None
        if self._adapter:
            self._wintun.WintunCloseAdapter(self._adapter)
            self._adapter = None


class ChatApplication:
    """Plan B: same handshake and encryption, carrying lines of text."""

    def run(self, runner: Runner) -> None:
        print("Type a message and press Enter. Ctrl-C quits.", flush=True)
        for line in sys.stdin:
            text = line.rstrip("\r\n")
            if not text:
                continue
            data = text.encode("utf-8")
            if len(data) > MAX_MESSAGE_BYTES:
                print(f"[!] too long (limit is {MAX_MESSAGE_BYTES} bytes)", flush=True)
            elif not runner.submit(TYPE_MESSAGE, data):
                print("[!] no secure session yet, message not sent", flush=True)
            if runner.stopping.is_set():
                break

    def deliver(self, packet_type: int, payload: bytes) -> None:
        if packet_type != TYPE_MESSAGE:
            return
        text = payload.decode("utf-8", errors="replace")
        safe = "".join(c if c.isprintable() else "?" for c in text)
        print(f"[peer] {safe}", flush=True)

    def close(self) -> None:
        """Nothing to release."""
