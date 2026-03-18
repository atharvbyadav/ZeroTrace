#include "ipax_engine.h"
#include "../registry.h"

#include <stdio.h>

static int ipax_erase(
    zt_context_t *ctx
)
{
    printf(
        "IPAX erase running on %s\n",
        ctx->device.path
    );

    return 0;
}

const zt_erase_engine_t ipax_engine =
{
    .name = "ipax",
    .erase = ipax_erase
};
