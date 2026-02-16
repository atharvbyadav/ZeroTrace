#include "engine.h"
#include <string.h>

extern const zt_erase_engine_t overwrite_engine;

static const zt_erase_engine_t *engines[] =
{
    &overwrite_engine,
    NULL
};

const zt_erase_engine_t *
zt_get_engine(const char *name)
{
    for (int i = 0; engines[i]; i++)
    {
        if (strcmp(name, engines[i]->name) == 0)
            return engines[i];
    }

    return NULL;
}
