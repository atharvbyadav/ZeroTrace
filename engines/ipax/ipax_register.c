#include "../engine.h"

extern const zt_erase_engine_t ipax_engine;

const zt_erase_engine_t *
zt_ipax_engine_register(void)
{
    return &ipax_engine;
}
