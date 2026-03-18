#include "ipax_transform.h"

#include <openssl/evp.h>

static unsigned char key[32] = {0};

static unsigned char nonce[24] = {0};


void ipax_transform(
    unsigned char *data,
    size_t len,
    uint64_t offset
)
{
    nonce[0] = offset & 0xff;

    EVP_CIPHER_CTX *ctx =
        EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(
        ctx,
        EVP_chacha20(),
        NULL,
        key,
        nonce
    );

    int out;

    EVP_EncryptUpdate(
        ctx,
        data,
        &out,
        data,
        len
    );

    EVP_CIPHER_CTX_free(ctx);
}
