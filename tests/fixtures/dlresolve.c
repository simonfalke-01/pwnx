#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

char dlresolve_scratch[4096];

__attribute__((naked, used))
void gadget_ret(void) {
    __asm__("ret");
}

__attribute__((naked, used))
void gadget_pop_rdi(void) {
    __asm__("pop %rdi; ret");
}

__attribute__((naked, used))
void gadget_pop_rsi(void) {
    __asm__("pop %rsi; ret");
}

__attribute__((naked, used))
void gadget_pop_rdx(void) {
    __asm__("pop %rdx; ret");
}

static void raw_write(const char *data, size_t size) {
    register long number __asm__("rax") = 1;
    register long fd __asm__("rdi") = STDOUT_FILENO;
    register const char *buffer __asm__("rsi") = data;
    register size_t count __asm__("rdx") = size;

    __asm__ volatile(
        "syscall"
        : "+a"(number)
        : "D"(fd), "S"(buffer), "d"(count)
        : "rcx", "r11", "memory"
    );
}

__attribute__((noinline))
static void vulnerable(void) {
    char buffer[64];
    static const char prompt[] = "payload: ";

    raw_write(prompt, sizeof(prompt) - 1);
    (void)read(STDIN_FILENO, buffer, 512);
}

int main(void) {
    vulnerable();
    return 0;
}

