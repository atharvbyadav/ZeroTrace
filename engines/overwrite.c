#include "engine.h"
#include "../util/random.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

static int overwrite_erase(
    zt_context_t *ctx
)
{
    int fd = open(ctx->device.path,O_WRONLY);

    unsigned char buf[4096];

    uint64_t remaining =
        ctx->device.size_bytes;

    while(remaining)
    {
        size_t w =
            remaining>sizeof(buf)?
            sizeof(buf):remaining;

        zt_random_fill(buf,w);

        write(fd,buf,w);

        remaining-=w;
    }

    close(fd);

    return 0;
}

const zt_erase_engine_t overwrite_engine =
{
    .name="overwrite",
    .erase=overwrite_erase
};
