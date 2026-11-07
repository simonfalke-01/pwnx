"""Bounded, synchronous byte-stream transports.

Public reads preserve partial data across timeout and EOF. Public writes either
complete or report their partial byte count.
"""

from __future__ import annotations

import abc
import errno
import os
import re
import selectors
import socket
import ssl
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from typing import Any, BinaryIO, NoReturn, cast

from .errors import EndOfStream, ProtocolError, ReadTimeout

_termios: Any
try:
    import termios as _termios
except ImportError:  # pragma: no cover - Windows import boundary
    _termios = None


def _deadline(timeout: float | None, default: float) -> float:
    duration = default if timeout is None else timeout
    if duration < 0:
        raise ValueError("timeout cannot be negative")
    return time.monotonic() + duration


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


class Tube(abc.ABC):
    """A buffered, bounded, full-duplex byte stream."""

    def __init__(self, *, timeout: float = 3.0) -> None:
        if timeout < 0:
            raise ValueError("timeout cannot be negative")
        self.default_timeout = float(timeout)
        self._buffer = bytearray()
        self._closed = False

    @property
    def buffered_bytes(self) -> bytes:
        return bytes(self._buffer)

    @property
    def closed(self) -> bool:
        return self._closed

    # Familiar tube verbs remain strict aliases: timeouts raise and buffered
    # bytes are retained. They do not reproduce pwntools' empty-byte timeout.
    def recv(self, n: int = 4096, timeout: float | None = None) -> bytes:
        return self.read_some(n, timeout)

    def recvn(self, n: int, timeout: float | None = None) -> bytes:
        return self.read_exact(n, timeout)

    def recvuntil(
        self,
        delimiters: bytes | Sequence[bytes],
        *,
        drop: bool = False,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        if isinstance(delimiters, (bytes, bytearray, memoryview)):
            delimiter = bytes(delimiters)
            result = self.read_until(delimiter, timeout, max_bytes)
            return result[: -len(delimiter)] if drop else result
        choices = tuple(bytes(item) for item in delimiters)
        if not choices or any(not item for item in choices):
            raise ValueError("delimiters must contain non-empty byte strings")
        deadline = _deadline(timeout, self.default_timeout)
        consumed = bytearray()
        try:
            while max_bytes is None or len(consumed) < max_bytes:
                consumed.extend(self.read_some(1, _remaining(deadline)))
                matches = [item for item in choices if consumed.endswith(item)]
                if matches:
                    matched = max(matches, key=len)
                    result = bytes(consumed)
                    return result[: -len(matched)] if drop else result
        except (ReadTimeout, EndOfStream):
            self.unrecv(consumed)
            raise
        self.unrecv(consumed)
        raise ProtocolError(
            f"none of {choices!r} found within {max_bytes} bytes; data remains buffered"
        )

    def recvline(
        self,
        *,
        keepends: bool = True,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        return self.recvuntil(
            b"\n", drop=not keepends, timeout=timeout, max_bytes=max_bytes
        )

    def recvregex(
        self,
        expression: bytes | str | re.Pattern[bytes],
        *,
        exact: bool = False,
        capture: bool = False,
        timeout: float | None = None,
        max_bytes: int = 1024 * 1024,
    ) -> bytes | re.Match[bytes]:
        if isinstance(expression, str):
            compiled = re.compile(expression.encode())
        elif isinstance(expression, bytes):
            compiled = re.compile(expression)
        else:
            compiled = expression
        deadline = _deadline(timeout, self.default_timeout)
        consumed = bytearray()
        matcher = compiled.fullmatch if exact else compiled.search
        try:
            while len(consumed) < max_bytes:
                consumed.extend(self.read_some(1, _remaining(deadline)))
                match = matcher(bytes(consumed))
                if match is not None:
                    result = bytes(consumed)
                    return match if capture else result
        except (ReadTimeout, EndOfStream):
            self.unrecv(consumed)
            raise
        self.unrecv(consumed)
        raise ProtocolError(
            f"regular expression was not matched within {max_bytes} bytes"
        )

    def clean(self, timeout: float = 0.05, max_bytes: int = 1024 * 1024) -> bytes:
        result = bytearray()
        if self._buffer:
            result.extend(self._buffer)
            self._buffer.clear()
        while len(result) < max_bytes:
            try:
                result.extend(
                    self.read_some(min(4096, max_bytes - len(result)), timeout)
                )
            except (ReadTimeout, EndOfStream):
                break
        return bytes(result)

    def unrecv(self, data: bytes | bytearray | memoryview) -> None:
        raw = bytes(data)
        if raw:
            self._buffer[:0] = raw

    unread = unrecv

    def read_exact(self, n: int, timeout: float | None = None) -> bytes:
        if n < 0:
            raise ValueError("read size cannot be negative")
        if n == 0:
            return b""
        deadline = _deadline(timeout, self.default_timeout)
        while len(self._buffer) < n:
            self._receive_into_buffer(max(4096, n - len(self._buffer)), deadline)
        result = bytes(self._buffer[:n])
        del self._buffer[:n]
        return result

    def read_until(
        self,
        delimiter: bytes,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        delimiter = bytes(delimiter)
        if not delimiter:
            raise ValueError("delimiter cannot be empty")
        if max_bytes is not None and max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        deadline = _deadline(timeout, self.default_timeout)
        while True:
            end = self._buffer.find(delimiter)
            if end >= 0:
                end += len(delimiter)
                if max_bytes is not None and end > max_bytes:
                    raise ProtocolError(
                        f"delimiter ended at byte {end}, beyond limit {max_bytes}; "
                        f"{len(self._buffer)} bytes remain buffered"
                    )
                result = bytes(self._buffer[:end])
                del self._buffer[:end]
                return result
            if max_bytes is not None and len(self._buffer) >= max_bytes:
                raise ProtocolError(
                    f"delimiter {delimiter!r} not found within {max_bytes} bytes; "
                    "data remains buffered"
                )
            request = 4096
            if max_bytes is not None:
                request = max(1, min(request, max_bytes - len(self._buffer)))
            self._receive_into_buffer(request, deadline)

    def read_some(self, n: int = 4096, timeout: float | None = None) -> bytes:
        if n <= 0:
            raise ValueError("read size must be positive")
        if not self._buffer:
            self._receive_into_buffer(n, _deadline(timeout, self.default_timeout))
        result = bytes(self._buffer[:n])
        del self._buffer[:n]
        return result

    def send(self, data: bytes, timeout: float | None = None) -> None:
        if self._closed:
            raise EndOfStream("cannot send: transport is closed")
        payload = memoryview(bytes(data))
        deadline = _deadline(timeout, self.default_timeout)
        sent = 0
        while sent < len(payload):
            if _remaining(deadline) <= 0:
                self._raise_send_error("send timed out", sent)
            try:
                count = self._send_raw(payload[sent:], _remaining(deadline))
            except TimeoutError:
                self._raise_send_error("send timed out", sent)
            except (BrokenPipeError, ConnectionError, OSError) as exc:
                if isinstance(exc, OSError) and exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                self._raise_send_error(f"send failed: {exc}", sent)
            if count is None:
                self._raise_send_error("send timed out", sent)
            if count <= 0:
                self._raise_send_error("transport closed during send", sent)
            sent += count

    def sendline(
        self,
        data: bytes | bytearray | memoryview = b"",
        timeout: float | None = None,
        *,
        newline: bytes = b"\n",
    ) -> None:
        self.send(bytes(data) + bytes(newline), timeout)

    def sendafter(
        self,
        delimiter: bytes | Sequence[bytes],
        data: bytes,
        *,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        observed = self.recvuntil(
            delimiter, timeout=timeout, max_bytes=max_bytes
        )
        self.send(data, timeout)
        return observed

    def sendlineafter(
        self,
        delimiter: bytes | Sequence[bytes],
        data: bytes = b"",
        *,
        timeout: float | None = None,
        max_bytes: int | None = None,
        newline: bytes = b"\n",
    ) -> bytes:
        observed = self.recvuntil(
            delimiter, timeout=timeout, max_bytes=max_bytes
        )
        self.sendline(data, timeout, newline=newline)
        return observed

    def wait(self, timeout: float | None = None) -> int | None:
        deadline = _deadline(timeout, self.default_timeout)
        preserved = bytearray()
        try:
            while True:
                preserved.extend(self.read_some(4096, _remaining(deadline)))
        except EndOfStream:
            return None
        except ReadTimeout:
            raise
        finally:
            self.unrecv(preserved)

    def shutdown(self, direction: str = "both") -> None:
        if direction not in {"send", "receive", "both"}:
            raise ValueError("direction must be 'send', 'receive', or 'both'")
        self._shutdown_raw(direction)
        if direction == "both":
            self._closed = True

    def interactive(self) -> None:
        output: Any = getattr(sys.stdout, "buffer", sys.stdout)
        pending = self.buffered_bytes
        self._buffer.clear()
        if pending:
            output.write(pending)
            output.flush()
        try:
            while not self.closed:
                try:
                    chunk = self.read_some(4096, timeout=0.05)
                except ReadTimeout:
                    chunk = b""
                except EndOfStream:
                    return
                if chunk:
                    output.write(chunk)
                    output.flush()
                select_module = __import__("select")
                readable, _, _ = select_module.select([sys.stdin], [], [], 0)
                if readable:
                    source: Any = getattr(sys.stdin, "buffer", sys.stdin)
                    user_data = source.read1(4096) if hasattr(source, "read1") else source.read(4096)
                    if not user_data:
                        return
                    self.send(user_data)
        except KeyboardInterrupt:
            return

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._close_raw()

    def _receive_into_buffer(self, max_bytes: int, deadline: float) -> None:
        if self._closed:
            self._raise_eof()
        remaining = _remaining(deadline)
        if remaining <= 0:
            self._raise_timeout()
        try:
            chunk = self._recv_raw(max_bytes, remaining)
        except TimeoutError:
            self._raise_timeout()
        except (ConnectionError, OSError) as exc:
            if isinstance(exc, OSError) and exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._raise_timeout()
            self._raise_eof(str(exc))
        if chunk is None:
            self._raise_timeout()
        if not chunk:
            self._raise_eof()
        self._buffer.extend(chunk)

    def _raise_timeout(self) -> NoReturn:
        exc = ReadTimeout(f"read timed out with {len(self._buffer)} byte(s) buffered")
        exc.buffered = bytes(self._buffer)
        raise exc

    def _raise_eof(self, detail: str | None = None) -> NoReturn:
        message = f"stream ended with {len(self._buffer)} byte(s) buffered"
        if detail:
            message += f": {detail}"
        exc = EndOfStream(message)
        exc.buffered = bytes(self._buffer)
        raise exc

    @staticmethod
    def _raise_send_error(message: str, sent: int) -> NoReturn:
        exc = ProtocolError(f"{message} after {sent} byte(s)")
        exc.sent = sent
        raise exc

    @abc.abstractmethod
    def _recv_raw(self, max_bytes: int, timeout: float) -> bytes | None:
        """Return bytes, an empty byte string for EOF, or None for timeout."""

    @abc.abstractmethod
    def _send_raw(self, data: memoryview, timeout: float) -> int | None:
        """Return bytes written, zero for EOF, or None for timeout."""

    @abc.abstractmethod
    def _close_raw(self) -> None:
        pass

    def _shutdown_raw(self, direction: str) -> None:
        if direction == "both":
            self._close_raw()
            return
        raise ProtocolError(
            f"{type(self).__name__} does not support half-close"
        )

    def __enter__(self) -> Tube:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class ProcessTube(Tube):
    """A subprocess with raw stdin and merged stdout/stderr pipes."""

    def __init__(
        self,
        argv: str | os.PathLike[str] | Sequence[str | os.PathLike[str]],
        *,
        env: Mapping[str, str] | None = None,
        cwd: str | os.PathLike[str] | None = None,
        timeout: float = 3.0,
    ) -> None:
        super().__init__(timeout=timeout)
        command = [os.fspath(argv)] if isinstance(argv, (str, os.PathLike)) else [
            os.fspath(item) for item in argv
        ]
        if not command:
            raise ValueError("argv cannot be empty")
        process_env = None
        if env is not None:
            process_env = os.environ.copy()
            process_env.update(env)
        try:
            self.process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=os.fspath(cwd) if cwd is not None else None,
                env=process_env,
                bufsize=0,
            )
        except OSError as exc:
            self._closed = True
            raise ProtocolError(f"could not start {command[0]!r}: {exc}") from exc
        assert self.process.stdin is not None and self.process.stdout is not None
        self._stdin = cast(BinaryIO, self.process.stdin)
        self._stdout = cast(BinaryIO, self.process.stdout)
        os.set_blocking(self._stdin.fileno(), False)
        os.set_blocking(self._stdout.fileno(), False)

    @property
    def pid(self) -> int:
        return self.process.pid

    def _recv_raw(self, max_bytes: int, timeout: float) -> bytes | None:
        if not _wait_fd(self._stdout.fileno(), selectors.EVENT_READ, timeout):
            return None
        try:
            return os.read(self._stdout.fileno(), max_bytes)
        except BlockingIOError:
            return None

    def _send_raw(self, data: memoryview, timeout: float) -> int | None:
        if not _wait_fd(self._stdin.fileno(), selectors.EVENT_WRITE, timeout):
            return None
        try:
            return os.write(self._stdin.fileno(), data)
        except BlockingIOError:
            return None

    def _close_raw(self) -> None:
        for stream in (getattr(self, "_stdin", None), getattr(self, "_stdout", None)):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        process = getattr(self, "process", None)
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)

    def wait(self, timeout: float | None = None) -> int:
        duration = self.default_timeout if timeout is None else timeout
        try:
            return self.process.wait(timeout=duration)
        except subprocess.TimeoutExpired as exc:
            error = ReadTimeout(f"process {self.pid} did not exit within {duration}s")
            error.buffered = self.buffered_bytes
            raise error from exc

    def _shutdown_raw(self, direction: str) -> None:
        if direction in {"send", "both"} and not self._stdin.closed:
            self._stdin.close()
        if direction in {"receive", "both"} and not self._stdout.closed:
            self._stdout.close()

    def maps(self):
        self._require_linux_process()
        from .diagnostics import ProcessMaps

        parser = getattr(ProcessMaps, "from_proc", None)
        if not callable(parser):
            parser = getattr(ProcessMaps, "from_pid", None)
        if callable(parser):
            return parser(self.pid)
        with open(f"/proc/{self.pid}/maps", encoding="utf-8") as stream:
            text = stream.read()
        parse = getattr(ProcessMaps, "parse", None)
        if callable(parse):
            return parse(text)
        raise ProtocolError("installed ProcessMaps implementation cannot parse /proc maps")

    def libs(self) -> dict[str, int]:
        maps = self.maps()
        libraries = getattr(maps, "libraries", None)
        if callable(libraries):
            libraries = libraries()
        if isinstance(libraries, Mapping):
            return dict(libraries)
        result: dict[str, int] = {}
        for item in maps:
            path = getattr(item, "path", None)
            start = getattr(item, "start", None)
            if path and isinstance(start, int) and str(path).startswith("/"):
                result.setdefault(str(path), start)
        return result

    def read_memory(self, address: int, size: int) -> bytes:
        self._require_linux_process()
        if address < 0 or size < 0:
            raise ValueError("address and size must be non-negative")
        try:
            descriptor = os.open(f"/proc/{self.pid}/mem", os.O_RDONLY)
            try:
                data = os.pread(descriptor, size, address)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise ProtocolError(
                f"cannot read process {self.pid} memory at {address:#x}: {exc}"
            ) from exc
        if len(data) != size:
            raise ProtocolError(
                f"short process-memory read: expected {size}, received {len(data)}"
            )
        return data

    def write_memory(self, address: int, data: bytes) -> None:
        self._require_linux_process()
        if address < 0:
            raise ValueError("address must be non-negative")
        payload = bytes(data)
        try:
            descriptor = os.open(f"/proc/{self.pid}/mem", os.O_WRONLY)
            try:
                written = os.pwrite(descriptor, payload, address)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise ProtocolError(
                f"cannot write process {self.pid} memory at {address:#x}: {exc}"
            ) from exc
        if written != len(payload):
            raise ProtocolError(
                f"short process-memory write: expected {len(payload)}, wrote {written}"
            )

    def _require_linux_process(self) -> None:
        if not sys.platform.startswith("linux"):
            raise ProtocolError("process maps and memory require Linux /proc")
        if self.process.poll() is not None:
            raise EndOfStream(f"process {self.pid} has exited")


class SocketTube(Tube):
    """A TCP or TLS client using bounded non-blocking I/O."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float = 3.0,
        tls: bool = False,
        _socket: socket.socket | None = None,
    ) -> None:
        super().__init__(timeout=timeout)
        if not 0 < int(port) < 65536:
            raise ValueError("port must be between 1 and 65535")
        try:
            raw = (
                _socket
                if _socket is not None
                else socket.create_connection((host, int(port)), timeout=timeout)
            )
            if tls:
                context = ssl.create_default_context()
                self.socket: socket.socket = context.wrap_socket(raw, server_hostname=host)
            else:
                self.socket = raw
            self.socket.setblocking(False)
        except (OSError, ssl.SSLError) as exc:
            self._closed = True
            raise ProtocolError(f"could not connect to {host}:{port}: {exc}") from exc

    @classmethod
    def from_socket(
        cls, sock: socket.socket, *, timeout: float = 3.0
    ) -> "SocketTube":
        peer = sock.getpeername()
        host = str(peer[0]) if isinstance(peer, tuple) else "accepted"
        port = int(peer[1]) if isinstance(peer, tuple) else 1
        return cls(host, port, timeout=timeout, _socket=sock)

    def _recv_raw(self, max_bytes: int, timeout: float) -> bytes | None:
        deadline = time.monotonic() + timeout
        while True:
            if not _wait_socket(self.socket, read=True, timeout=_remaining(deadline)):
                return None
            try:
                return self.socket.recv(max_bytes)
            except (BlockingIOError, ssl.SSLWantReadError):
                if _remaining(deadline) <= 0:
                    return None
            except ssl.SSLWantWriteError:
                if not _wait_socket(self.socket, read=False, timeout=_remaining(deadline)):
                    return None

    def _send_raw(self, data: memoryview, timeout: float) -> int | None:
        deadline = time.monotonic() + timeout
        while True:
            if not _wait_socket(self.socket, read=False, timeout=_remaining(deadline)):
                return None
            try:
                return self.socket.send(data)
            except (BlockingIOError, ssl.SSLWantWriteError):
                if _remaining(deadline) <= 0:
                    return None
            except ssl.SSLWantReadError:
                if not _wait_socket(self.socket, read=True, timeout=_remaining(deadline)):
                    return None

    def _close_raw(self) -> None:
        sock = getattr(self, "socket", None)
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    def _shutdown_raw(self, direction: str) -> None:
        how = {
            "send": socket.SHUT_WR,
            "receive": socket.SHUT_RD,
            "both": socket.SHUT_RDWR,
        }[direction]
        try:
            self.socket.shutdown(how)
        except OSError:
            pass
        if direction == "both":
            self.socket.close()


class DatagramTube(Tube):
    """A connected UDP endpoint with explicit message-oriented operations."""

    message_oriented = True

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        *,
        timeout: float = 3.0,
        bind: tuple[str, int] | None = None,
        _socket: socket.socket | None = None,
    ) -> None:
        super().__init__(timeout=timeout)
        self.socket = _socket or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if bind is not None:
            self.socket.bind(bind)
        if host is not None:
            if port is None or not 0 < int(port) < 65536:
                raise ValueError("UDP port must be between 1 and 65535")
            self.socket.connect((host, int(port)))
            self.peer: tuple[str, int] | None = (host, int(port))
        else:
            self.peer = None
        self.socket.setblocking(False)
        self.last_peer: tuple[str, int] | None = None

    @property
    def address(self) -> tuple[str, int]:
        value = self.socket.getsockname()
        return str(value[0]), int(value[1])

    def recv_datagram(
        self, max_size: int = 65535, timeout: float | None = None
    ) -> tuple[bytes, tuple[str, int] | None]:
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        deadline = _deadline(timeout, self.default_timeout)
        if not _wait_socket(self.socket, read=True, timeout=_remaining(deadline)):
            self._raise_timeout()
        try:
            if self.peer is None:
                data, peer = self.socket.recvfrom(max_size)
                self.last_peer = (str(peer[0]), int(peer[1]))
            else:
                data = self.socket.recv(max_size)
                self.last_peer = self.peer
        except BlockingIOError:
            self._raise_timeout()
        return data, self.last_peer

    def send_datagram(
        self,
        data: bytes,
        *,
        peer: tuple[str, int] | None = None,
        timeout: float | None = None,
    ) -> None:
        payload = bytes(data)
        deadline = _deadline(timeout, self.default_timeout)
        if not _wait_socket(self.socket, read=False, timeout=_remaining(deadline)):
            self._raise_send_error("datagram send timed out", 0)
        destination = peer or self.peer or self.last_peer
        if destination is None:
            raise ProtocolError("unconnected UDP endpoint requires a peer")
        try:
            sent = (
                self.socket.send(payload)
                if self.peer is not None and destination == self.peer
                else self.socket.sendto(payload, destination)
            )
        except OSError as exc:
            self._raise_send_error(f"datagram send failed: {exc}", 0)
        if sent != len(payload):
            self._raise_send_error("partial UDP datagram send", sent)

    @staticmethod
    def _stream_error() -> NoReturn:
        raise ProtocolError(
            "DatagramTube is message-oriented; use recv_datagram() and "
            "send_datagram() to preserve packet boundaries"
        )

    def read_exact(self, n: int, timeout: float | None = None) -> bytes:
        self._stream_error()

    def read_until(
        self,
        delimiter: bytes,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        self._stream_error()

    def read_some(self, n: int = 4096, timeout: float | None = None) -> bytes:
        self._stream_error()

    def send(self, data: bytes, timeout: float | None = None) -> None:
        self._stream_error()

    def _recv_raw(self, max_bytes: int, timeout: float) -> bytes | None:
        try:
            data, _peer = self.recv_datagram(max_bytes, timeout)
            return data
        except ReadTimeout:
            return None

    def _send_raw(self, data: memoryview, timeout: float) -> int | None:
        self.send_datagram(bytes(data), timeout=timeout)
        return len(data)

    def _close_raw(self) -> None:
        self.socket.close()


class ListenerTube:
    """A bounded inbound TCP listener."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        backlog: int = 1,
        timeout: float = 3.0,
    ) -> None:
        self.default_timeout = timeout
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, port))
        self.socket.listen(backlog)
        self.socket.setblocking(False)
        self.closed = False

    @property
    def address(self) -> tuple[str, int]:
        value = self.socket.getsockname()
        return str(value[0]), int(value[1])

    def accept(self, timeout: float | None = None) -> SocketTube:
        deadline = _deadline(timeout, self.default_timeout)
        if not _wait_socket(self.socket, read=True, timeout=_remaining(deadline)):
            raise ReadTimeout("listener accept timed out")
        connection, _peer = self.socket.accept()
        return SocketTube.from_socket(connection, timeout=self.default_timeout)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.socket.close()

    def __enter__(self) -> "ListenerTube":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


_BAUD_RATES = (
    {
        9600: _termios.B9600,
        19200: _termios.B19200,
        38400: _termios.B38400,
        57600: _termios.B57600,
        115200: _termios.B115200,
    }
    if _termios is not None
    else {}
)


class SerialTube(Tube):
    """A dependency-free Unix serial endpoint."""

    def __init__(
        self,
        device: str | os.PathLike[str],
        *,
        baud: int = 115200,
        timeout: float = 3.0,
    ) -> None:
        super().__init__(timeout=timeout)
        if _termios is None or os.name != "posix":
            raise ProtocolError("SerialTube requires a POSIX termios platform")
        if baud not in _BAUD_RATES:
            raise ValueError(f"unsupported baud rate {baud}")
        self.fd = os.open(os.fspath(device), os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        attributes = _termios.tcgetattr(self.fd)
        attributes[0] = 0
        attributes[1] = 0
        attributes[2] = _termios.CS8 | _termios.CREAD | _termios.CLOCAL
        attributes[3] = 0
        attributes[4] = _BAUD_RATES[baud]
        attributes[5] = _BAUD_RATES[baud]
        attributes[6][_termios.VMIN] = 0
        attributes[6][_termios.VTIME] = 0
        _termios.tcsetattr(self.fd, _termios.TCSANOW, attributes)

    def _recv_raw(self, max_bytes: int, timeout: float) -> bytes | None:
        if not _wait_fd(self.fd, selectors.EVENT_READ, timeout):
            return None
        try:
            return os.read(self.fd, max_bytes)
        except BlockingIOError:
            return None

    def _send_raw(self, data: memoryview, timeout: float) -> int | None:
        if not _wait_fd(self.fd, selectors.EVENT_WRITE, timeout):
            return None
        try:
            return os.write(self.fd, data)
        except BlockingIOError:
            return None

    def _close_raw(self) -> None:
        os.close(self.fd)


def _wait_fd(fd: int, event: int, timeout: float) -> bool:
    if timeout <= 0:
        return False
    selector = selectors.DefaultSelector()
    try:
        selector.register(fd, event)
        return bool(selector.select(timeout))
    finally:
        selector.close()


def _wait_socket(sock: socket.socket, *, read: bool, timeout: float) -> bool:
    event = selectors.EVENT_READ if read else selectors.EVENT_WRITE
    return _wait_fd(sock.fileno(), event, timeout)
