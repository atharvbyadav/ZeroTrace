#include "ipax_transform.h"

#include "../../util/random.h"

#include <openssl/evp.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static uint32_t load32_le(const unsigned char in[4])
{
    return ((uint32_t) in[0]) |
        ((uint32_t) in[1] << 8) |
        ((uint32_t) in[2] << 16) |
        ((uint32_t) in[3] << 24);
}

static void store32_le(unsigned char out[4], uint32_t value)
{
    out[0] = (unsigned char) (value & 0xffu);
    out[1] = (unsigned char) ((value >> 8) & 0xffu);
    out[2] = (unsigned char) ((value >> 16) & 0xffu);
    out[3] = (unsigned char) ((value >> 24) & 0xffu);
}

static uint32_t rotl32(uint32_t value, int shift)
{
    return (value << shift) | (value >> (32 - shift));
}

static void quarter_round(
    uint32_t *a,
    uint32_t *b,
    uint32_t *c,
    uint32_t *d
)
{
    *a += *b;
    *d ^= *a;
    *d = rotl32(*d, 16);
    *c += *d;
    *b ^= *c;
    *b = rotl32(*b, 12);
    *a += *b;
    *d ^= *a;
    *d = rotl32(*d, 8);
    *c += *d;
    *b ^= *c;
    *b = rotl32(*b, 7);
}

static void hchacha20(
    const unsigned char key[IPAX_KEY_BYTES],
    const unsigned char nonce[16],
    unsigned char out[IPAX_KEY_BYTES]
)
{
    static const unsigned char sigma[16] = "expand 32-byte k";
    uint32_t state[16];
    int round;

    state[0] = load32_le(&sigma[0]);
    state[1] = load32_le(&sigma[4]);
    state[2] = load32_le(&sigma[8]);
    state[3] = load32_le(&sigma[12]);

    for (round = 0; round < 8; round++)
        state[4 + round] = load32_le(&key[round * 4]);

    for (round = 0; round < 4; round++)
        state[12 + round] = load32_le(&nonce[round * 4]);

    for (round = 0; round < 10; round++)
    {
        quarter_round(&state[0], &state[4], &state[8], &state[12]);
        quarter_round(&state[1], &state[5], &state[9], &state[13]);
        quarter_round(&state[2], &state[6], &state[10], &state[14]);
        quarter_round(&state[3], &state[7], &state[11], &state[15]);
        quarter_round(&state[0], &state[5], &state[10], &state[15]);
        quarter_round(&state[1], &state[6], &state[11], &state[12]);
        quarter_round(&state[2], &state[7], &state[8], &state[13]);
        quarter_round(&state[3], &state[4], &state[9], &state[14]);
    }

    store32_le(&out[0], state[0]);
    store32_le(&out[4], state[1]);
    store32_le(&out[8], state[2]);
    store32_le(&out[12], state[3]);
    store32_le(&out[16], state[12]);
    store32_le(&out[20], state[13]);
    store32_le(&out[24], state[14]);
    store32_le(&out[28], state[15]);
}

static int xchacha20_poly1305_init(
    EVP_CIPHER_CTX *ctx,
    int encrypt,
    const unsigned char key[IPAX_KEY_BYTES],
    const unsigned char nonce[IPAX_NONCE_BYTES]
)
{
    unsigned char subkey[IPAX_KEY_BYTES];
    unsigned char nonce12[12] = {0};

    hchacha20(key, nonce, subkey);
    memcpy(&nonce12[4], &nonce[16], 8);

    if (encrypt)
    {
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
            return -1;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1)
            return -1;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, subkey, nonce12) != 1)
            return -1;
    }
    else
    {
        if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
            return -1;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1)
            return -1;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, subkey, nonce12) != 1)
            return -1;
    }

    return 0;
}

int ipax_load_hex_key_file(
    const char *path,
    unsigned char key[IPAX_KEY_BYTES]
)
{
    char buf[256];
    FILE *f;
    size_t n;
    size_t i;
    size_t out_i = 0;

    if (!path || !key)
        return -1;

    f = fopen(path, "r");
    if (!f)
        return -1;

    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

    if (n == 0)
        return -1;

    buf[n] = '\0';

    for (i = 0; i < n; i++)
    {
        if (isxdigit((unsigned char) buf[i]))
            buf[out_i++] = buf[i];
    }

    buf[out_i] = '\0';

    if (out_i != IPAX_KEY_BYTES * 2)
        return -1;

    return ipax_hex_decode(buf, key, IPAX_KEY_BYTES);
}

void ipax_make_nonce(unsigned char nonce[IPAX_NONCE_BYTES])
{
    zt_random_fill(nonce, IPAX_NONCE_BYTES);
}

int ipax_encrypt_chunk(
    const unsigned char key[IPAX_KEY_BYTES],
    const unsigned char nonce[IPAX_NONCE_BYTES],
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *ciphertext,
    unsigned char tag[IPAX_TAG_BYTES]
)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int final_len = 0;
    int ok = -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    if (xchacha20_poly1305_init(ctx, 1, key, nonce) != 0)
        goto done;

    if (aad_len > 0 && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int) aad_len) != 1)
        goto done;

    if (plaintext_len > 0 &&
        EVP_EncryptUpdate(
            ctx,
            ciphertext,
            &len,
            plaintext,
            (int) plaintext_len
        ) != 1)
    {
        goto done;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len) != 1)
        goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, IPAX_TAG_BYTES, tag) != 1)
        goto done;

    ok = 0;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int ipax_decrypt_verify_chunk(
    const unsigned char key[IPAX_KEY_BYTES],
    const unsigned char nonce[IPAX_NONCE_BYTES],
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char tag[IPAX_TAG_BYTES],
    unsigned char *plaintext
)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int final_len = 0;
    int ok = -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    if (xchacha20_poly1305_init(ctx, 0, key, nonce) != 0)
        goto done;

    if (aad_len > 0 && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int) aad_len) != 1)
        goto done;

    if (ciphertext_len > 0 &&
        EVP_DecryptUpdate(
            ctx,
            plaintext,
            &len,
            ciphertext,
            (int) ciphertext_len
        ) != 1)
    {
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_AEAD_SET_TAG,
            IPAX_TAG_BYTES,
            (void *) tag
        ) != 1)
    {
        goto done;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) != 1)
        goto done;

    ok = 0;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

void ipax_sha256(
    const unsigned char *data,
    size_t len,
    unsigned char digest[IPAX_DIGEST_BYTES]
)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int out_len = 0;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, digest, &out_len);
    EVP_MD_CTX_free(ctx);
}

void ipax_hex_encode(const unsigned char *src, size_t len, char *dst)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++)
    {
        dst[i * 2] = hex[src[i] >> 4];
        dst[i * 2 + 1] = hex[src[i] & 0x0f];
    }

    dst[len * 2] = '\0';
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int ipax_hex_decode(const char *src, unsigned char *dst, size_t len)
{
    size_t i;

    if (!src || !dst)
        return -1;

    for (i = 0; i < len; i++)
    {
        int hi = hex_value(src[i * 2]);
        int lo = hex_value(src[i * 2 + 1]);

        if (hi < 0 || lo < 0)
            return -1;

        dst[i] = (unsigned char) ((hi << 4) | lo);
    }

    return 0;
}
