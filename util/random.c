#include <unistd.h>
#include <sys/random.h>
#include <errno.h>

int zt_random_fill(unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t r = getrandom(buf + off, len - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += r;
    }
    return 0;
}
