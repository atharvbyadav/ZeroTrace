#include "workflow.h"
#include "../device/device.h"
#include <stdio.h>

int zt_run_workflow(zt_context_t *ctx) {
    if (!ctx) return -1;

    if (zt_discover_device(ctx) != 0)
        return -1;

    ctx->status = ZT_STATUS_READY;

    if (ctx->mode == ZT_MODE_DRY_RUN) {
        printf("[DRY-RUN] Device: %s\n", ctx->device.path);
        printf("[DRY-RUN] Size: %jd bytes\n",
               (intmax_t)ctx->device.size_bytes);
        printf("[DRY-RUN] Engine: %d\n", ctx->engine);
        printf("[DRY-RUN] No data was modified.\n");

        ctx->status = ZT_STATUS_COMPLETE;
        ctx->end_time = time(NULL);
        return 0;
    }

    zt_context_set_error(ctx, 99, "Erase engines not implemented yet");
    return -1;
}
