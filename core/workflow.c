#include "workflow.h"

#include <time.h>

int zt_run_workflow(
    zt_context_t *ctx,
    const zt_erase_engine_t *engine
)
{
    int rc;

    if (!ctx || !engine || !engine->erase)
        return -1;

    ctx->status = ZT_STATUS_ERASING;
    ctx->start_time = time(NULL);

    rc = engine->erase(ctx);
    ctx->end_time = time(NULL);

    if (rc == 0)
        ctx->status = ZT_STATUS_COMPLETE;

    return rc;
}
