#ifndef ZT_IPAX_LEDGER_H
#define ZT_IPAX_LEDGER_H

#include "ipax_state.h"
#include "ipax_transform.h"

#include <stdint.h>
#include <stdio.h>

typedef struct
{
    uint64_t index;
    uint64_t offset;
    size_t size;
    unsigned char nonce[IPAX_NONCE_BYTES];
    unsigned char tag[IPAX_TAG_BYTES];
    unsigned char digest[IPAX_DIGEST_BYTES];
} ipax_ledger_chunk_t;

typedef struct
{
    char engine[16];
    char cipher[32];
    uint64_t file_size;
    size_t chunk_size;
    uint64_t total_chunks;
    unsigned char key_commitment[IPAX_DIGEST_BYTES];
    unsigned char state_digest[IPAX_DIGEST_BYTES];
} ipax_ledger_header_t;

typedef struct
{
    FILE *fp;
    ipax_state_t state;
    int first_chunk;
} ipax_ledger_writer_t;

int ipax_ledger_begin(
    ipax_ledger_writer_t *,
    const char *path,
    const ipax_ledger_header_t *
);

int ipax_ledger_append(
    ipax_ledger_writer_t *,
    const ipax_ledger_chunk_t *
);

int ipax_ledger_finalize(
    ipax_ledger_writer_t *,
    ipax_ledger_header_t *
);

void ipax_ledger_close(ipax_ledger_writer_t *);

int ipax_ledger_load(
    const char *path,
    ipax_ledger_header_t *,
    ipax_ledger_chunk_t **chunks_out
);

#endif
