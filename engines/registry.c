#include "registry.h"

#include <string.h>

static const zt_erase_engine_t *engine_list[ZT_MAX_ENGINES];
static size_t engine_count = 0;

void zt_engine_register(const zt_erase_engine_t *engine)
{
    size_t i;

    if (!engine || !engine->name)
        return;

    for (i = 0; i < engine_count; i++)
    {
        if (strcmp(engine_list[i]->name, engine->name) == 0)
            return;
    }

    if (engine_count >= ZT_MAX_ENGINES)
        return;

    engine_list[engine_count++] = engine;
}

const zt_erase_engine_t *zt_get_engine(const char *name)
{
    size_t i;

    if (!name)
        return NULL;

    for (i = 0; i < engine_count; i++)
    {
        if (strcmp(engine_list[i]->name, name) == 0)
            return engine_list[i];
    }

    return NULL;
}

size_t zt_engine_count(void)
{
    return engine_count;
}

const zt_erase_engine_t *zt_engine_at(size_t index)
{
    if (index >= engine_count)
        return NULL;

    return engine_list[index];
}
