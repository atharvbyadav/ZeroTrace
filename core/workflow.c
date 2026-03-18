#include "workflow.h"

int zt_run_workflow(
    zt_context_t *ctx,
    const zt_erase_engine_t *engine
)
{
    ctx->status = ZT_STATUS_ERASING;

    int rc = engine->erase(ctx);

    if (rc == 0)
        ctx->status = ZT_STATUS_COMPLETE;

    return rc;
}
