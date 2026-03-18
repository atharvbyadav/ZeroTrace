#include "ipax_state.h"

#include <openssl/sha.h>

void ipax_state_init(
    ipax_state_t *s
)
{
    SHA256(
        (unsigned char*)"IPAX",
        4,
        s->hash
    );
}


void ipax_state_update(
    ipax_state_t *s,
    unsigned char *data,
    size_t len
)
{
    SHA256(
        data,
        len,
        s->hash
    );
}


void ipax_state_finalize(
    ipax_state_t *s,
    unsigned char *out
)
{
    for(int i=0;i<32;i++)
        out[i] = s->hash[i];
}
