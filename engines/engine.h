#ifndef ZT_ENGINE_H
#define ZT_ENGINE_H

#include "../core/context.h"

#include <stdint.h>

#define ZT_ENGINE_FLAG_DETERMINISTIC 0x01u
#define ZT_ENGINE_FLAG_AUDITABLE     0x02u
#define ZT_ENGINE_FLAG_CRYPTOGRAPHIC 0x04u
#define ZT_ENGINE_FLAG_VERIFIABLE    0x08u

typedef struct zt_erase_engine
{
    const char *name;
    const char *description;
    uint64_t flags;
    int (*erase)(zt_context_t *);
    int (*verify)(zt_context_t *);
} zt_erase_engine_t;

const zt_erase_engine_t *zt_get_engine(const char *);

#endif
