#include "device.h"

#include <sys/stat.h>

int zt_discover_device(
    zt_context_t *ctx
)
{
    struct stat st;

    stat(ctx->device.path,&st);

    ctx->device.size_bytes =
        st.st_size;

    return 0;
}
