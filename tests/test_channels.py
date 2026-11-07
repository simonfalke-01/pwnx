from __future__ import annotations

import dataclasses

import pytest

from pwnx.channels import Channel, line, raw
from pwnx.errors import ConstraintError


def test_line_channel_frames_payload() -> None:
    channel = line(b"payload: ")
    assert channel.encode(b"hello") == b"hello\n"
    assert channel.prompt == b"payload: "
    assert channel.terminator == b"\n"
    assert channel.framed


def test_line_accepts_ascii_prompt_sugar() -> None:
    channel = line("name: ", name="username")
    assert channel.prompt == b"name: "
    assert "named 'username'" in channel.describe()
    assert "after b'name: '" in channel.describe()

    with pytest.raises(ValueError, match="ASCII"):
        line("λ: ")


def test_line_rejects_embedded_terminator() -> None:
    channel = line(terminator=b"\r\n")
    with pytest.raises(ConstraintError, match="offset 1"):
        channel.encode(b"a\r\nb")


def test_channel_rejects_forbidden_bytes_before_framing() -> None:
    channel = line(forbidden=b"\0\xff")
    with pytest.raises(ConstraintError, match=r"0x00, 0xff"):
        channel.encode(b"\xffA\0")


def test_channel_enforces_payload_size_excluding_terminator() -> None:
    channel = line(max_size=3)
    assert channel.encode(b"abc") == b"abc\n"
    with pytest.raises(ConstraintError, match="4 bytes"):
        channel.encode(b"abcd")


def test_raw_channel_has_no_terminator() -> None:
    channel = raw(b"data: ", max_size=4)
    assert channel.encode(b"abcd") == b"abcd"
    assert channel.terminator is None
    assert not channel.framed
    assert channel.describe().startswith("raw channel")


def test_channel_is_immutable() -> None:
    channel = line()
    with pytest.raises(dataclasses.FrozenInstanceError):
        channel.timeout = 4  # type: ignore[misc]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_size": -1}, "max_size"),
        ({"timeout": 0}, "timeout"),
        ({"max_receive": 0}, "max_receive"),
        ({"terminator": b""}, "terminator"),
        ({"name": ""}, "name"),
    ],
)
def test_invalid_channel_contracts_fail_early(kwargs: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Channel(**kwargs)


def test_payload_must_be_bytes_like() -> None:
    with pytest.raises(TypeError, match="bytes-like"):
        line().encode("not bytes")  # type: ignore[arg-type]


def test_describe_includes_constraints() -> None:
    description = line(
        b"> ",
        max_size=32,
        forbidden=b"\0",
        terminator=b"\r\n",
    ).describe()
    assert description == (
        "line channel, after b'> ', max 32 bytes, forbids 0x00, "
        "terminates with b'\\r\\n'"
    )
