#ifndef ZT_IPAX_TRANSFORM_H
#define ZT_IPAX_TRANSFORM_H

#include <stddef.h>
#include <stdint.h>

#define IPAX_KEY_BYTES 32
#define IPAX_NONCE_BYTES 24
#define IPAX_TAG_BYTES 16
#define IPAX_DIGEST_BYTES 32

int ipax_load_hex_key_file(
    const char *path,
    unsigned char key[IPAX_KEY_BYTES]
);

void ipax_make_nonce(unsigned char nonce[IPAX_NONCE_BYTES]);

int ipax_encrypt_chunk(
    const unsigned char key[IPAX_KEY_BYTES],
    const unsigned char nonce[IPAX_NONCE_BYTES],
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *ciphertext,
    unsigned char tag[IPAX_TAG_BYTES]
);

int ipax_decrypt_verify_chunk(
    const unsigned char key[IPAX_KEY_BYTES],
    const unsigned char nonce[IPAX_NONCE_BYTES],
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char tag[IPAX_TAG_BYTES],
    unsigned char *plaintext
);

void ipax_sha256(
    const unsigned char *data,
    size_t len,
    unsigned char digest[IPAX_DIGEST_BYTES]
);

void ipax_hex_encode(
    const unsigned char *src,
    size_t len,
    char *dst
);

int ipax_hex_decode(
    const char *src,
    unsigned char *dst,
    size_t len
);

#endif
