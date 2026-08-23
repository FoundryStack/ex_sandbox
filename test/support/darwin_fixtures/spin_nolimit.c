/* Burns CPU forever and NEVER limits itself.
 *
 * ⚠️ This is deliberately NOT the spike's `spin.c`. That one calls
 * `setrlimit(RLIMIT_CPU, 2)` on ITSELF, so an assertion of exit 152 against it
 * passes whether or not the platform imposed anything — a check that cannot
 * fail (014 T002 Finding 1). Tenant code will not ask to be limited, so the
 * spinner used to verify the platform must not either.
 */
#include <stdio.h>

int main(void) {
    fprintf(stderr, "spinning\n");
    fflush(stderr);
    volatile double x = 0;
    for (long i = 0;; i++) { x += i * 1.000001; }
    return 0;
}
