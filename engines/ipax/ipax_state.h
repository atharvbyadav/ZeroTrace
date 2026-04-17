#ifndef ZT_IPAX_STATE_H
#define ZT_IPAX_STATE_H

#include <openssl/evp.h>
#include <stddef.h>

typedef struct
{
    EVP_MD_CTX *mdctx;
} ipax_state_t;

int ipax_state_init(ipax_state_t *);

int ipax_state_update(ipax_state_t *, const void *, size_t);

int ipax_state_finalize(ipax_state_t *, unsigned char *);

void ipax_state_cleanup(ipax_state_t *);

#endif
