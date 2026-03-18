#include "context.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

zt_context_t *zt_context_create(void)
{
    zt_context_t *ctx =
        calloc(1,sizeof(zt_context_t));

    strncpy(
        ctx->zerotrace_version,
        ZEROTRACE_VERSION,
        sizeof(ctx->zerotrace_version)-1
    );

    ctx->threads = 1;
    ctx->chunk_bytes = 1024*1024;
    ctx->start_time = time(NULL);

    return ctx;
}

void zt_context_destroy(zt_context_t *ctx)
{
    free(ctx);
}

void zt_context_set_error(
    zt_context_t *ctx,
    int code,
    const char *msg
)
{
    ctx->status = ZT_STATUS_ERROR;
    ctx->error_code = code;
    strncpy(ctx->error_msg,msg,255);
}
