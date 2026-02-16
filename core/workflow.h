#ifndef ZT_WORKFLOW_H
#define ZT_WORKFLOW_H

#include "context.h"
#include "../engines/engine.h"

int zt_run_workflow(
    zt_context_t *,
    const zt_erase_engine_t *
);

#endif
