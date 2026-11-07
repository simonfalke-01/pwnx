#include <stdio.h>
#include <unistd.h>

const char stage2_command[] = "echo PWNX_STAGE2_OK";

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

__attribute__((noinline))
static void vulnerable(void) {
    char buffer[64];
    static const char prompt[] = "payload: ";

    (void)write(STDOUT_FILENO, prompt, sizeof(prompt) - 1);
    (void)read(STDIN_FILENO, buffer, 512);
}

int main(void) {
    (void)setvbuf(stdout, NULL, _IONBF, 0);
    puts("ready");
    vulnerable();
    return 0;
}

