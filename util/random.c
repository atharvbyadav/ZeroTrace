#include "random.h"

#include <sys/random.h>
#include <unistd.h>

int zt_random_fill(
    unsigned char *buf,
    size_t len
)
{
    ssize_t r =
        getrandom(
            buf,
            len,
            0
        );

    if (r < 0)
        return -1;

    if ((size_t)r != len)
        return -1;

    return 0;
}
