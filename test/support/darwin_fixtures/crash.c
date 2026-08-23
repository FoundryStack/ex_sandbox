/* Dies of SIGSEGV promptly, with no allocation and no CPU burn — the
 * "ordinary crash" outcome, which must be distinguishable from a cap breach.
 */
#include <stdio.h>

int main(void) {
    fprintf(stderr, "crashing\n");
    fflush(stderr);
    volatile int *p = (int *)0;
    *p = 1;
    return 0;
}
