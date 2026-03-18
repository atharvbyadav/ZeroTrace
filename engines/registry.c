#include "registry.h"

#include <string.h>

static const zt_erase_engine_t *
engine_list[ZT_MAX_ENGINES];

static int engine_count = 0;


/*
 * Called by core and plugins
 */
void zt_engine_register(
    const zt_erase_engine_t *engine
)
{
    if (!engine)
        return;

    if (engine_count >= ZT_MAX_ENGINES)
        return;

    engine_list[engine_count++] = engine;
}


/*
 * Lookup engine
 */
const zt_erase_engine_t *
zt_get_engine(const char *name)
{
    for (int i = 0; i < engine_count; i++)
    {
        if (strcmp(
                engine_list[i]->name,
                name
            ) == 0)
        {
            return engine_list[i];
        }
    }

    return NULL;
}
