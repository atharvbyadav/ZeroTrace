#ifndef ZT_REGISTRY_H
#define ZT_REGISTRY_H

#include "engine.h"

#define ZT_MAX_ENGINES 32

void zt_engine_register(
    const zt_erase_engine_t *
);

const zt_erase_engine_t *
zt_get_engine(
    const char *
);

#endif
