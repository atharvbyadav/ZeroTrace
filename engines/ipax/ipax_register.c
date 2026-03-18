#include "ipax_engine.h"
#include "../registry.h"


__attribute__((constructor))
static void register_ipax(void)
{
    zt_engine_register(
        &ipax_engine
    );
}
