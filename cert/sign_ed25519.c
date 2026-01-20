#include "sign_ed25519.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>

int zt_ed25519_keygen(const char *priv_path, const char *pub_path) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY *pkey = NULL;

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0)
        return -1;

    FILE *fp = fopen(priv_path, "w");
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

    fp = fopen(pub_path, "w");
    PEM_write_PUBKEY(fp, pkey);
    fclose(fp);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

static int load_key(const char *path, int priv, EVP_PKEY **out) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    *out = priv ? PEM_read_PrivateKey(fp, NULL, NULL, NULL)
                : PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return *out ? 0 : -1;
}

int zt_ed25519_sign_file(const char *file, const char *priv_key) {
    EVP_PKEY *pkey = NULL;
    if (load_key(priv_key, 1, &pkey) != 0)
        return -1;

    FILE *f = fopen(file, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    unsigned char *buf = malloc(len);
    fread(buf, 1, len, f);
    fclose(f);

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    size_t siglen = 0;
    unsigned char sig[64];

    EVP_DigestSignInit(md, NULL, NULL, NULL, pkey);
    EVP_DigestSign(md, sig, &siglen, buf, len);

    FILE *sf = fopen("signature.bin", "wb");
    fwrite(sig, 1, siglen, sf);
    fclose(sf);

    EVP_MD_CTX_free(md);
    EVP_PKEY_free(pkey);
    free(buf);
    return 0;
}

int zt_ed25519_verify_file(const char *file, const char *pub_key) {
    EVP_PKEY *pkey = NULL;
    if (load_key(pub_key, 0, &pkey) != 0)
        return -1;

    FILE *f = fopen(file, "rb");
    FILE *sf = fopen("signature.bin", "rb");
    if (!f || !sf) return -1;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    unsigned char *buf = malloc(len);
    fread(buf, 1, len, f);

    unsigned char sig[64];
    size_t siglen = fread(sig, 1, sizeof(sig), sf);

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(md, NULL, NULL, NULL, pkey);

    int ok = EVP_DigestVerify(md, sig, siglen, buf, len);

    EVP_MD_CTX_free(md);
    EVP_PKEY_free(pkey);
    free(buf);
    fclose(f);
    fclose(sf);

    return ok == 1 ? 0 : -1;
}
