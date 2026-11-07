#include <stdio.h>
#include <unistd.h>

const char direct_command[] = "echo PWNX_DIRECT_OK";

__attribute__((naked, used))
void gadget_ret(void) {
    __asm__("ret");
}

__attribute__((naked, used))
void gadget_pop_rdi(void) {
    __asm__("pop %rdi; ret");
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
    printf("puts: %p\n", (void *)puts);
    vulnerable();
    return 0;
}

