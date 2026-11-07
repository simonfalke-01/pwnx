from __future__ import annotations

import socket
import os
import sys
import threading
import time

import pytest

from pwnx.errors import EndOfStream, ProtocolError, ReadTimeout
from pwnx.transport import (
    DatagramTube,
    ListenerTube,
    ProcessTube,
    SerialTube,
    SocketTube,
    Tube,
)


class ScriptedTube(Tube):
    def __init__(self, reads=(), *, write_limit=None, fail_write_after=None):
        super().__init__(timeout=0.1)
        self.reads = list(reads)
        self.written = bytearray()
        self.write_limit = write_limit
        self.fail_write_after = fail_write_after

    def _recv_raw(self, max_bytes, timeout):
        del max_bytes, timeout
        if not self.reads:
            return b""
        return self.reads.pop(0)

    def _send_raw(self, data, timeout):
        del timeout
        if self.fail_write_after is not None and len(self.written) >= self.fail_write_after:
            return None
        count = len(data) if self.write_limit is None else min(len(data), self.write_limit)
        self.written.extend(data[:count])
        return count

    def _close_raw(self):
        pass


def test_partial_reads_survive_timeout():
    tube = ScriptedTube([b"ab", None, b"cd"])

    with pytest.raises(ReadTimeout) as error:
        tube.read_exact(4)

    assert error.value.buffered == b"ab"
    assert tube.buffered_bytes == b"ab"
    assert tube.read_exact(4) == b"abcd"
    assert tube.buffered_bytes == b""


def test_partial_reads_survive_eof():
    tube = ScriptedTube([b"ab", b""])

    with pytest.raises(EndOfStream) as error:
        tube.read_exact(4)

    assert error.value.buffered == b"ab"
    assert tube.read_exact(2) == b"ab"


def test_read_until_limit_does_not_consume():
    tube = ScriptedTube([b"abcdefgh"])

    with pytest.raises(ProtocolError, match="not found within 5"):
        tube.read_until(b"!", max_bytes=5)

    # The limit rejects the match without discarding data already returned by
    # the transport, even when a custom transport returns an oversized chunk.
    assert tube.buffered_bytes == b"abcdefgh"


def test_send_retries_partial_writes():
    tube = ScriptedTube(write_limit=2)
    tube.send(b"abcdef")
    assert tube.written == b"abcdef"


def test_send_reports_partial_count_on_timeout():
    tube = ScriptedTube(write_limit=2, fail_write_after=2)

    with pytest.raises(ProtocolError) as error:
        tube.send(b"abcdef")

    assert error.value.sent == 2
    assert tube.written == b"ab"


def test_tube_convenience_methods_are_strict_and_preserve_data():
    tube = ScriptedTube([b"banner> ", b"line one\ntrailer"])
    assert tube.sendlineafter(b"> ", b"go") == b"banner> "
    assert tube.written == b"go\n"
    assert tube.recvline(keepends=False) == b"line one"
    assert tube.recvregex(rb"trail..") == b"trailer"
    tube.unrecv(b"again")
    assert tube.recvn(5) == b"again"


def test_sendafter_never_sends_after_timeout():
    tube = ScriptedTube([b"partial", None])
    with pytest.raises(ReadTimeout):
        tube.sendlineafter(b"> ", b"unsafe")
    assert tube.written == b""
    assert tube.buffered_bytes == b"partial"


def test_multiple_delimiters_and_regex_failure_restore_buffer():
    tube = ScriptedTube([b"abcENDtail"])
    assert tube.recvuntil((b"NO", b"END"), drop=True) == b"abc"

    crlf = ScriptedTube([b"line\r\n"])
    assert crlf.recvuntil((b"\n", b"\r\n"), drop=True) == b"line"
    with pytest.raises(EndOfStream):
        tube.recvregex(rb"missing")
    assert tube.buffered_bytes == b"tail"


def test_process_tube_round_trip_and_fragmentation():
    program = (
        "import sys,time;"
        "sys.stdout.write('pro');sys.stdout.flush();"
        "time.sleep(.03);sys.stdout.write('mpt> ');sys.stdout.flush();"
        "line=sys.stdin.buffer.readline();"
        "sys.stdout.buffer.write(b'ack:'+line);sys.stdout.flush()"
    )
    with ProcessTube([sys.executable, "-u", "-c", program], timeout=1) as tube:
        assert tube.read_until(b"> ") == b"prompt> "
        tube.send(b"hello\n")
        assert tube.read_until(b"\n") == b"ack:hello\n"


def test_process_timeout_retains_real_pipe_bytes():
    program = (
        "import sys,time;"
        "sys.stdout.buffer.write(b'READYab');sys.stdout.flush();"
        "time.sleep(.15);"
        "sys.stdout.buffer.write(b'cd');sys.stdout.flush()"
    )
    with ProcessTube([sys.executable, "-u", "-c", program], timeout=1) as tube:
        tube.read_until(b"READY", timeout=1)
        with pytest.raises(ReadTimeout):
            tube.read_exact(4, timeout=0.03)
        assert tube.buffered_bytes == b"ab"
        assert tube.read_exact(4, timeout=1) == b"abcd"


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux /proc process memory"
)
def test_process_memory_read_write_and_wait():
    program = (
        "import ctypes,sys;"
        "buf=ctypes.create_string_buffer(b'hello');"
        "print(hex(ctypes.addressof(buf)),flush=True);"
        "sys.stdin.readline();"
        "print(buf.raw[:5].decode(),flush=True)"
    )
    with ProcessTube([sys.executable, "-u", "-c", program], timeout=1) as tube:
        address = int(tube.recvline().strip(), 16)
        assert tube.read_memory(address, 5) == b"hello"
        maps = tube.maps()
        assert maps.at(address) is not None
        assert any(path for path in tube.libs())
        tube.write_memory(address, b"WORLD")
        tube.sendline()
        assert tube.recvline() == b"WORLD\n"
        assert tube.wait(timeout=1) == 0


def test_socket_tube_round_trip_with_fragmented_server():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    received = bytearray()

    def server():
        connection, _ = listener.accept()
        with connection:
            connection.sendall(b"hel")
            time.sleep(0.02)
            connection.sendall(b"lo> ")
            while not received.endswith(b"\n"):
                chunk = connection.recv(16)
                if not chunk:
                    break
                received.extend(chunk)
            connection.sendall(b"OK")
        listener.close()

    worker = threading.Thread(target=server)
    worker.start()
    try:
        with SocketTube("127.0.0.1", port, timeout=1) as tube:
            assert tube.read_until(b"> ") == b"hello> "
            tube.send(b"go\n")
            assert tube.read_exact(2) == b"OK"
    finally:
        worker.join(timeout=2)

    assert not worker.is_alive()
    assert received == b"go\n"


def test_listener_tube_accepts_socket_connection():
    with ListenerTube() as listener:
        received = []

        def client():
            with SocketTube(*listener.address, timeout=1) as tube:
                tube.sendline(b"hello")
                received.append(tube.recvline())

        worker = threading.Thread(target=client)
        worker.start()
        with listener.accept(timeout=1) as connection:
            assert connection.recvline() == b"hello\n"
            connection.sendline(b"world")
        worker.join(timeout=2)
        assert not worker.is_alive()
        assert received == [b"world\n"]


def test_udp_datagram_round_trip_preserves_messages():
    with DatagramTube(bind=("127.0.0.1", 0), timeout=1) as server:
        with DatagramTube(*server.address, timeout=1) as client:
            client.send_datagram(b"one")
            data, peer = server.recv_datagram()
            assert data == b"one"
            assert peer is not None
            server.send_datagram(b"two", peer=peer)
            assert client.recv_datagram()[0] == b"two"
            with pytest.raises(ProtocolError, match="message-oriented"):
                client.recv(1)
            with pytest.raises(ProtocolError, match="message-oriented"):
                client.send(b"stream")


@pytest.mark.skipif(os.name != "posix", reason="POSIX serial fixture")
def test_serial_tube_round_trip_with_pty():
    master, slave = os.openpty()
    path = os.ttyname(slave)
    os.close(slave)
    try:
        with SerialTube(path, timeout=1) as tube:
            os.write(master, b"in")
            assert tube.recvn(2) == b"in"
            tube.send(b"out")
            assert os.read(master, 3) == b"out"
    finally:
        os.close(master)


@pytest.mark.parametrize("delimiter", [b"", bytearray()])
def test_empty_delimiter_rejected(delimiter):
    with pytest.raises(ValueError):
        ScriptedTube().read_until(delimiter)

