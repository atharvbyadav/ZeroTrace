#ifndef ZT_REGISTRY_H
#define ZT_REGISTRY_H

#include "engine.h"

#include <stddef.h>

#define ZT_MAX_ENGINES 32

void zt_engine_register(const zt_erase_engine_t *);

const zt_erase_engine_t *zt_get_engine(const char *);

size_t zt_engine_count(void);

const zt_erase_engine_t *zt_engine_at(size_t index);

#endif
