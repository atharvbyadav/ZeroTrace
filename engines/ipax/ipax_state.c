#include "ipax_state.h"

#include <string.h>

int ipax_state_init(ipax_state_t *s)
{
    if (!s)
        return -1;

    memset(s, 0, sizeof(*s));
    s->mdctx = EVP_MD_CTX_new();
    if (!s->mdctx)
        return -1;

    if (EVP_DigestInit_ex(s->mdctx, EVP_sha256(), NULL) != 1)
    {
        EVP_MD_CTX_free(s->mdctx);
        s->mdctx = NULL;
        return -1;
    }

    return 0;
}

int ipax_state_update(ipax_state_t *s, const void *data, size_t len)
{
    if (!s || !s->mdctx)
        return -1;

    if (len == 0)
        return 0;

    return EVP_DigestUpdate(s->mdctx, data, len) == 1 ? 0 : -1;
}

int ipax_state_finalize(ipax_state_t *s, unsigned char *out)
{
    unsigned int out_len = 0;

    if (!s || !s->mdctx || !out)
        return -1;

    return EVP_DigestFinal_ex(s->mdctx, out, &out_len) == 1 && out_len == 32
        ? 0
        : -1;
}

void ipax_state_cleanup(ipax_state_t *s)
{
    if (!s)
        return;

    EVP_MD_CTX_free(s->mdctx);
    s->mdctx = NULL;
}
