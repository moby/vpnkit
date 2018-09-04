#include <stdlib.h>
#include <stdio.h>

extern int verbose;
#define ERROR(...)                                                      \
    do {                                                                \
		printf(__VA_ARGS__);                                            \
        printf("\n");                                                   \
		fflush(stdout);                                                 \
    } while (0)
#define INFO(...)                                                       \
    do {                                                                \
        printf(__VA_ARGS__);                                            \
        printf("\n");                                                   \
        fflush(stdout);                                                 \
    } while (0)
#define DBG(...)                                                        \
    do {                                                                \
        if (verbose > 1) {                                              \
            printf(__VA_ARGS__);                                        \
            printf("\n");                                               \
            fflush(stdout);                                             \
        }                                                               \
    } while (0)
#define TRC(...)                                                        \
    do {                                                                \
        if (verbose > 2) {                                              \
            printf(__VA_ARGS__);                                        \
            printf("\n");                                               \
            fflush(stdout);                                             \
        }                                                               \
    } while (0)

extern void fatal(const char *msg);
