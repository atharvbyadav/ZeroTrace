#include "context.h"
#include <stdlib.h>
#include <string.h>

#define ZEROTRACE_VERSION "1.3-mvp"

zt_context_t *zt_context_create(void) {
    zt_context_t *ctx = calloc(1, sizeof(zt_context_t));
    if (!ctx) return NULL;

    strncpy(ctx->zerotrace_version, ZEROTRACE_VERSION,
            sizeof(ctx->zerotrace_version) - 1);

    ctx->mode = ZT_MODE_ERASE;
    ctx->engine = ZT_ENGINE_OVERWRITE;
    ctx->status = ZT_STATUS_INIT;

    ctx->passes = 1;
    ctx->threads = 1;
    ctx->chunk_bytes = 1024 * 1024;

    ctx->start_time = time(NULL);
    return ctx;
}

void zt_context_destroy(zt_context_t *ctx) {
    if (!ctx) return;
    free(ctx->engine_ctx);
    free(ctx);
}

void zt_context_set_error(zt_context_t *ctx, int code, const char *msg) {
    if (!ctx) return;
    ctx->status = ZT_STATUS_ERROR;
    ctx->error_code = code;
    if (msg) {
        strncpy(ctx->error_msg, msg, sizeof(ctx->error_msg) - 1);
    }
}
