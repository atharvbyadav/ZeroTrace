#include "engine.h"
#include "registry.h"

#include "../util/random.h"

#include <fcntl.h>
#include <unistd.h>

static int overwrite_erase(zt_context_t *ctx)
{
    int fd;
    unsigned char buf[4096];
    uint64_t remaining;

    fd = open(ctx->device.path, O_WRONLY);
    if (fd < 0)
        return -1;

    remaining = ctx->device.size_bytes;

    while (remaining)
    {
        size_t w = remaining > sizeof(buf) ? sizeof(buf) : (size_t) remaining;
        ssize_t wrote;

        if (zt_random_fill(buf, w) != 0)
        {
            close(fd);
            return -1;
        }

        wrote = write(fd, buf, w);
        if (wrote < 0 || (size_t) wrote != w)
        {
            close(fd);
            return -1;
        }

        remaining -= w;
    }

    if (fsync(fd) != 0)
    {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

const zt_erase_engine_t overwrite_engine =
{
    .name = "overwrite",
    .description = "Single-pass random overwrite",
    .flags = ZT_ENGINE_FLAG_DETERMINISTIC,
    .erase = overwrite_erase,
    .verify = NULL
};

__attribute__((constructor))
static void register_overwrite(void)
{
    zt_engine_register(&overwrite_engine);
}
