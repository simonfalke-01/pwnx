#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((naked, used))
void gadget_ret(void) {
    __asm__("ret");
}

__attribute__((noinline, noreturn, used))
void win(void) {
    static const char marker[] = "PWNX_RET2WIN_OK\n";
    (void)write(STDOUT_FILENO, marker, sizeof(marker) - 1);
    _exit(0);
}

__attribute__((noinline))
static void vulnerable(void) {
    char buffer[64];
    static const char prompt[] = "payload: ";

    (void)write(STDOUT_FILENO, prompt, sizeof(prompt) - 1);
    (void)read(STDIN_FILENO, buffer, 512);
}

int main(void) {
    vulnerable();
    return 0;
}

