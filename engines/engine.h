#ifndef ZT_ENGINE_H
#define ZT_ENGINE_H

#include "../core/context.h"

typedef struct zt_erase_engine
{
    const char *name;

    int (*erase)(
        zt_context_t *
    );

} zt_erase_engine_t;


const zt_erase_engine_t *
zt_get_engine(
    const char *
);

#endif
