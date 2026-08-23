/* Allocates and TOUCHES memory 1 MB at a time, reporting progress on stderr.
 *
 * ⚠️ The progress line is the point, not decoration. `005` R9 recorded three
 * isolation tests passing against a mechanism that never ran, because a program
 * that dies instantly allocates nothing and the suite read that as the cap
 * holding. A caller asserting only on exit status cannot tell "killed at the
 * cap" from "never started". The `mb <n>` lines let it tell.
 *
 * `memset` is required: on Darwin `malloc` of untouched pages costs no
 * resident memory, so an allocate-only loop never reaches the cap.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: hog <mb>\n"); return 2; }
    long mb = atol(argv[1]);
    for (long i = 0; i < mb; i++) {
        char *p = malloc(1024 * 1024);
        if (!p) { fprintf(stderr, "malloc failed at %ld MB\n", i); return 42; }
        memset(p, 1, 1024 * 1024);
        fprintf(stderr, "mb %ld\n", i + 1);
        fflush(stderr);
    }
    fprintf(stderr, "allocated %ld MB OK\n", mb);
    return 0;
}
