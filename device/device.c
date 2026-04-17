#include "device.h"

#include <sys/stat.h>

int zt_discover_device(zt_context_t *ctx)
{
    struct stat st;

    if (!ctx || !ctx->device.path[0])
        return -1;

    if (stat(ctx->device.path, &st) != 0)
        return -1;

    ctx->device.size_bytes = (uint64_t) st.st_size;
    ctx->status = ZT_STATUS_READY;

    return 0;
}
