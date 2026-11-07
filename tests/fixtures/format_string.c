#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void safe(void) {
    static const char marker[] = "PWNX_FMT_SAFE\n";
    (void)write(STDOUT_FILENO, marker, sizeof(marker) - 1);
}

void win(void) {
    static const char marker[] = "PWNX_FMT_OK\n";
    (void)write(STDOUT_FILENO, marker, sizeof(marker) - 1);
}

void (*volatile hook)(void) = safe;

int main(void) {
    char buffer[512] = {0};
    static const char prompt[] = "format: ";

    (void)setvbuf(stdout, NULL, _IONBF, 0);
    (void)write(STDOUT_FILENO, prompt, sizeof(prompt) - 1);
    if (read(STDIN_FILENO, buffer, sizeof(buffer) - 1) <= 0) {
        return 1;
    }
    printf(buffer);
    hook();
    return 0;
}

