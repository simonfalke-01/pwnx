"""Pwntools-shaped conveniences backed by explicit pwnx implementations."""

from ..packing import (
    bits, cyclic, cyclic_find, cyclic_metasploit, cyclic_metasploit_find, dd,
    de_bruijn, enhex, fit, flat, hexdump, layout, offset_from, p8, p16, p32,
    p64, pack, rol, ror, u8, u16, u32, u64, unbits, unhex, unpack,
    unpack_many, xor_bytes,
)
from ..transport import (
    DatagramTube, ListenerTube, ProcessTube, SerialTube, SocketTube, Tube,
)

process = ProcessTube
remote = SocketTube
listen = ListenerTube
serialtube = SerialTube
tube = Tube

__all__ = [
    "DatagramTube", "ListenerTube", "ProcessTube", "SerialTube", "SocketTube",
    "Tube", "bits", "cyclic", "cyclic_find", "cyclic_metasploit",
    "cyclic_metasploit_find", "dd", "de_bruijn", "enhex", "fit", "flat",
    "hexdump", "layout", "listen", "offset_from", "p8", "p16", "p32",
    "p64", "pack", "process", "remote", "rol", "ror", "serialtube",
    "tube", "u8", "u16", "u32", "u64", "unbits", "unhex", "unpack",
    "unpack_many", "xor_bytes",
]
