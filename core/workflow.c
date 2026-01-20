#include "workflow.h"
#include "../device/device.h"
#include "../engines/engine.h"
#include "../cert/cert.h"
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
        printf("[DRY-RUN] No data was modified.\n");

        ctx->status = ZT_STATUS_COMPLETE;
        ctx->end_time = time(NULL);

        zt_write_json_certificate(ctx, "zerotrace_cert.json");
        return 0;
    }

    const zt_erase_engine_t *engine = zt_get_engine("overwrite");
    if (!engine || !engine->probe(ctx)) {
        zt_context_set_error(ctx, 20, "No suitable erase engine");
        return -1;
    }

    if (engine->erase(ctx) != 0)
        return -1;

    zt_write_json_certificate(ctx, "zerotrace_cert.json");
    return 0;
}
