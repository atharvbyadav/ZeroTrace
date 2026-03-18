#ifndef ZT_IPAX_STATE_H
#define ZT_IPAX_STATE_H

#include <stddef.h>

typedef struct
{
    unsigned char hash[32];

} ipax_state_t;

void ipax_state_init(
    ipax_state_t *
);

void ipax_state_update(
    ipax_state_t *,
    unsigned char *,
    size_t
);

void ipax_state_finalize(
    ipax_state_t *,
    unsigned char *
);

#endif
