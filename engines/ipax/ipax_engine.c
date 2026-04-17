#include "ipax_engine.h"

#include "ipax_ledger.h"
#include "ipax_transform.h"

#include "../../core/context.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct
{
    uint64_t index;
    uint64_t offset;
    uint64_t size;
} ipax_chunk_aad_t;

static void ipax_log(zt_context_t *ctx, const char *message)
{
    if (ctx && ctx->verbose)
        printf("[INFO] %s\n", message);
}

static int read_exact(int fd, unsigned char *buf, size_t len)
{
    size_t done = 0;

    while (done < len)
    {
        ssize_t n = read(fd, buf + done, len - done);
        if (n <= 0)
            return -1;
        done += (size_t) n;
    }

    return 0;
}

static int write_exact(int fd, const unsigned char *buf, size_t len)
{
    size_t done = 0;

    while (done < len)
    {
        ssize_t n = write(fd, buf + done, len - done);
        if (n <= 0)
            return -1;
        done += (size_t) n;
    }

    return 0;
}

static int ipax_require_paths(zt_context_t *ctx, int verify_mode)
{
    if (!ctx->device.path[0] || !ctx->key_path[0] || !ctx->ledger_path[0])
    {
        zt_context_set_error(
            ctx,
            2,
            verify_mode
                ? "verification requires --input, --key, and --ledger"
                : "IPAX requires --input, --key, and --ledger"
        );
        return -1;
    }

    return 0;
}

static int ipax_build_aad(
    uint64_t index,
    uint64_t offset,
    size_t size,
    unsigned char *out,
    size_t out_size
)
{
    ipax_chunk_aad_t aad;

    if (out_size < sizeof(aad))
        return -1;

    aad.index = index;
    aad.offset = offset;
    aad.size = (uint64_t) size;
    memcpy(out, &aad, sizeof(aad));
    return (int) sizeof(aad);
}

static int ipax_erase(zt_context_t *ctx)
{
    unsigned char key[IPAX_KEY_BYTES];
    ipax_ledger_header_t header;
    ipax_ledger_writer_t writer;
    unsigned char *plain = NULL;
    unsigned char *cipher = NULL;
    int fd = -1;
    uint64_t offset = 0;
    uint64_t index = 0;
    int rc = -1;
    int writer_open = 0;

    if (ipax_require_paths(ctx, 0) != 0)
        return -1;

    if (ipax_load_hex_key_file(ctx->key_path, key) != 0)
    {
        zt_context_set_error(ctx, 3, "failed to load 256-bit hex key");
        return -1;
    }

    fd = open(ctx->device.path, O_RDWR);
    if (fd < 0)
    {
        zt_context_set_error(ctx, 4, "failed to open input for read/write");
        return -1;
    }

    plain = malloc(ctx->chunk_bytes);
    cipher = malloc(ctx->chunk_bytes);
    if (!plain || !cipher)
    {
        zt_context_set_error(ctx, 5, "failed to allocate chunk buffers");
        goto done;
    }

    memset(&header, 0, sizeof(header));
    strncpy(header.engine, "IPAX", sizeof(header.engine) - 1);
    strncpy(header.cipher, "XChaCha20-Poly1305", sizeof(header.cipher) - 1);
    header.file_size = ctx->device.size_bytes;
    header.chunk_size = ctx->chunk_bytes;
    header.total_chunks = ctx->chunk_bytes == 0
        ? 0
        : (ctx->device.size_bytes + ctx->chunk_bytes - 1) / ctx->chunk_bytes;
    ipax_sha256(key, sizeof(key), header.key_commitment);

    if (ipax_ledger_begin(&writer, ctx->ledger_path, &header) != 0)
    {
        zt_context_set_error(ctx, 6, "failed to open ledger for writing");
        goto done;
    }
    writer_open = 1;

    ipax_log(ctx, "IPAX engine initialized");
    if (ctx->verbose)
    {
        printf("[INFO] chunk size: %zu bytes\n", ctx->chunk_bytes);
        printf("[INFO] cipher: %s\n", header.cipher);
        printf("[INFO] ledger recording enabled\n");
        printf("[INFO] processing %llu chunks\n",
            (unsigned long long) header.total_chunks);
    }

    while (offset < ctx->device.size_bytes)
    {
        size_t chunk_len = ctx->chunk_bytes;
        unsigned char aad[sizeof(ipax_chunk_aad_t)];
        int aad_len;
        ipax_ledger_chunk_t chunk;

        if ((uint64_t) chunk_len > ctx->device.size_bytes - offset)
            chunk_len = (size_t) (ctx->device.size_bytes - offset);

        if (lseek(fd, (off_t) offset, SEEK_SET) < 0 ||
            read_exact(fd, plain, chunk_len) != 0)
        {
            zt_context_set_error(ctx, 7, "failed to read input chunk");
            goto done;
        }

        memset(&chunk, 0, sizeof(chunk));
        chunk.index = index;
        chunk.offset = offset;
        chunk.size = chunk_len;
        ipax_make_nonce(chunk.nonce);

        aad_len = ipax_build_aad(index, offset, chunk_len, aad, sizeof(aad));
        if (aad_len < 0 ||
            ipax_encrypt_chunk(
                key,
                chunk.nonce,
                aad,
                (size_t) aad_len,
                plain,
                chunk_len,
                cipher,
                chunk.tag
            ) != 0)
        {
            zt_context_set_error(ctx, 8, "failed to encrypt chunk");
            goto done;
        }

        ipax_sha256(cipher, chunk_len, chunk.digest);

        if (lseek(fd, (off_t) offset, SEEK_SET) < 0 ||
            write_exact(fd, cipher, chunk_len) != 0)
        {
            zt_context_set_error(ctx, 9, "failed to write transformed chunk");
            goto done;
        }

        if (ipax_ledger_append(&writer, &chunk) != 0)
        {
            zt_context_set_error(ctx, 10, "failed to append ledger entry");
            goto done;
        }

        ctx->processed_chunks++;
        offset += chunk_len;
        index++;
    }

    if (fsync(fd) != 0)
    {
        zt_context_set_error(ctx, 11, "failed to flush transformed file");
        goto done;
    }

    if (ipax_ledger_finalize(&writer, &header) != 0)
    {
        zt_context_set_error(ctx, 12, "failed to finalize ledger");
        goto done;
    }

    ipax_log(ctx, "authenticated transformation complete");
    if (ctx->verbose)
        printf("[INFO] ledger saved -> %s\n", ctx->ledger_path);

    rc = 0;

done:
    if (writer_open)
        ipax_ledger_close(&writer);
    free(plain);
    free(cipher);
    if (fd >= 0)
        close(fd);
    return rc;
}

static int ipax_verify(zt_context_t *ctx)
{
    unsigned char key[IPAX_KEY_BYTES];
    unsigned char key_commitment[IPAX_DIGEST_BYTES];
    ipax_ledger_header_t header;
    ipax_ledger_chunk_t *chunks = NULL;
    ipax_state_t state;
    unsigned char *cipher = NULL;
    unsigned char *plain = NULL;
    unsigned char computed_state[IPAX_DIGEST_BYTES];
    int fd = -1;
    uint64_t i;
    int rc = -1;
    int state_open = 0;

    if (ipax_require_paths(ctx, 1) != 0)
        return -1;

    if (ipax_load_hex_key_file(ctx->key_path, key) != 0)
    {
        zt_context_set_error(ctx, 13, "failed to load verification key");
        return -1;
    }

    ipax_sha256(key, sizeof(key), key_commitment);

    if (ipax_ledger_load(ctx->ledger_path, &header, &chunks) != 0)
    {
        zt_context_set_error(ctx, 14, "failed to parse ledger");
        return -1;
    }

    if (memcmp(key_commitment, header.key_commitment, IPAX_DIGEST_BYTES) != 0)
    {
        zt_context_set_error(ctx, 15, "supplied key does not match ledger");
        goto done;
    }

    if (ctx->device.size_bytes != header.file_size)
    {
        zt_context_set_error(ctx, 16, "ledger file size does not match input");
        goto done;
    }

    fd = open(ctx->device.path, O_RDONLY);
    if (fd < 0)
    {
        zt_context_set_error(ctx, 17, "failed to open input for verification");
        goto done;
    }

    cipher = malloc(header.chunk_size);
    plain = malloc(header.chunk_size);
    if (!cipher || !plain)
    {
        zt_context_set_error(ctx, 18, "failed to allocate verification buffers");
        goto done;
    }

    if (ipax_state_init(&state) != 0)
    {
        zt_context_set_error(ctx, 19, "failed to initialize verification state");
        goto done;
    }
    state_open = 1;

    ipax_log(ctx, "verifying ledger integrity");
    ipax_log(ctx, "verifying Poly1305 MACs");

    for (i = 0; i < header.total_chunks; i++)
    {
        ipax_ledger_chunk_t *chunk = &chunks[i];
        unsigned char aad[sizeof(ipax_chunk_aad_t)];
        unsigned char digest[IPAX_DIGEST_BYTES];
        int aad_len;

        if (lseek(fd, (off_t) chunk->offset, SEEK_SET) < 0 ||
            read_exact(fd, cipher, chunk->size) != 0)
        {
            zt_context_set_error(ctx, 20, "failed to read chunk during verification");
            goto done;
        }

        aad_len = ipax_build_aad(chunk->index, chunk->offset, chunk->size, aad, sizeof(aad));
        if (aad_len < 0 ||
            ipax_decrypt_verify_chunk(
                key,
                chunk->nonce,
                aad,
                (size_t) aad_len,
                cipher,
                chunk->size,
                chunk->tag,
                plain
            ) != 0)
        {
            zt_context_set_error(ctx, 21, "MAC verification failed");
            goto done;
        }

        ipax_sha256(cipher, chunk->size, digest);
        if (memcmp(digest, chunk->digest, IPAX_DIGEST_BYTES) != 0)
        {
            zt_context_set_error(ctx, 22, "ciphertext digest mismatch");
            goto done;
        }

        ipax_state_update(&state, &chunk->index, sizeof(chunk->index));
        ipax_state_update(&state, &chunk->offset, sizeof(chunk->offset));
        ipax_state_update(&state, &chunk->size, sizeof(chunk->size));
        ipax_state_update(&state, chunk->nonce, sizeof(chunk->nonce));
        ipax_state_update(&state, chunk->tag, sizeof(chunk->tag));
        ipax_state_update(&state, chunk->digest, sizeof(chunk->digest));
        ctx->processed_chunks++;
    }

    if (ipax_state_finalize(&state, computed_state) != 0)
    {
        zt_context_set_error(ctx, 23, "failed to finalize verification state");
        goto done;
    }

    if (memcmp(computed_state, header.state_digest, IPAX_DIGEST_BYTES) != 0)
    {
        zt_context_set_error(ctx, 24, "ledger state digest mismatch");
        goto done;
    }

    ipax_log(ctx, "authenticated state confirmed");
    rc = 0;

done:
    if (state_open)
        ipax_state_cleanup(&state);
    if (fd >= 0)
        close(fd);
    free(cipher);
    free(plain);
    free(chunks);
    return rc;
}

const zt_erase_engine_t ipax_engine =
{
    .name = "ipax",
    .description = "Authenticated XChaCha20-Poly1305 transform with JSON ledger",
    .flags = ZT_ENGINE_FLAG_AUDITABLE |
        ZT_ENGINE_FLAG_CRYPTOGRAPHIC |
        ZT_ENGINE_FLAG_VERIFIABLE,
    .erase = ipax_erase,
    .verify = ipax_verify
};
