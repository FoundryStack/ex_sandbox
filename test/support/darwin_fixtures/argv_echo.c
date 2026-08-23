/* Prints argc and each argument on its own line, byte for byte.
 *
 * The Darwin composition routes the target through `/bin/sh -c`, which
 * `Hardening.Linux` never does. This program is how a test proves that shell
 * metacharacters in a tenant-influenced argument arrive at the target as
 * literal bytes rather than being parsed by the intervening shell.
 */
#include <stdio.h>

int main(int argc, char **argv) {
    printf("argc=%d\n", argc);
    for (int i = 0; i < argc; i++) printf("argv[%d]=%s\n", i, argv[i]);
    fflush(stdout);
    return 0;
}
