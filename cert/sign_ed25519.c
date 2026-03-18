#include "sign_ed25519.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#define SIG_FILE "signature.bin"


static int read_file(
    const char *path,
    unsigned char **data,
    size_t *len
)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    rewind(f);

    *data = malloc(*len);
    if (!*data)
    {
        fclose(f);
        return -1;
    }

    fread(*data, 1, *len, f);
    fclose(f);

    return 0;
}


int zt_ed25519_keygen(
    const char *priv_path,
    const char *pub_path
)
{
    EVP_PKEY_CTX *ctx =
        EVP_PKEY_CTX_new_id(
            EVP_PKEY_ED25519,
            NULL
        );

    EVP_PKEY *pkey = NULL;

    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);

    FILE *priv = fopen(priv_path, "wb");
    FILE *pub = fopen(pub_path, "wb");

    PEM_write_PrivateKey(
        priv,
        pkey,
        NULL,
        NULL,
        0,
        NULL,
        NULL
    );

    PEM_write_PUBKEY(
        pub,
        pkey
    );

    fclose(priv);
    fclose(pub);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return 0;
}


int zt_ed25519_sign_file(
    const char *file,
    const char *priv_key
)
{
    unsigned char *data;
    size_t data_len;

    if (read_file(file, &data, &data_len) != 0)
        return -1;

    FILE *f = fopen(priv_key, "rb");

    EVP_PKEY *key =
        PEM_read_PrivateKey(f, NULL, NULL, NULL);

    fclose(f);

    EVP_MD_CTX *ctx =
        EVP_MD_CTX_new();

    EVP_DigestSignInit(
        ctx,
        NULL,
        NULL,
        NULL,
        key
    );

    unsigned char sig[128];
    size_t sig_len;

    EVP_DigestSign(
        ctx,
        sig,
        &sig_len,
        data,
        data_len
    );

    FILE *out = fopen(SIG_FILE, "wb");

    fwrite(sig, 1, sig_len, out);

    fclose(out);

    free(data);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);

    return 0;
}


int zt_ed25519_verify_file(
    const char *file,
    const char *pub_key
)
{
    unsigned char *data;
    size_t data_len;

    if (read_file(file, &data, &data_len) != 0)
        return -1;

    FILE *f = fopen(pub_key, "rb");

    EVP_PKEY *key =
        PEM_read_PUBKEY(f, NULL, NULL, NULL);

    fclose(f);

    unsigned char sig[128];
    size_t sig_len;

    FILE *sigf = fopen(SIG_FILE, "rb");

    sig_len =
        fread(sig, 1, sizeof(sig), sigf);

    fclose(sigf);

    EVP_MD_CTX *ctx =
        EVP_MD_CTX_new();

    EVP_DigestVerifyInit(
        ctx,
        NULL,
        NULL,
        NULL,
        key
    );

    int rc =
        EVP_DigestVerify(
            ctx,
            sig,
            sig_len,
            data,
            data_len
        );

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    free(data);

    return rc == 1 ? 0 : -1;
}
