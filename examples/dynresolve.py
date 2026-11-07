from pwnx.backends.memory import DynResolver, MemoryOracle


def arbitrary_read(address: int, size: int) -> bytes:
    raise NotImplementedError("connect this to the challenge's declared read primitive")


memory = MemoryOracle(
    arbitrary_read,
    instance_id="remote-process-1",
    max_read=0x100,
)
resolver = DynResolver(memory, pointer=0x7F0000001234)
system = resolver.lookup("system", module="libc")
print(system.explain())
