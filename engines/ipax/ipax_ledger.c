#include "ipax_ledger.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void ledger_state_update(
    ipax_state_t *state,
    const ipax_ledger_chunk_t *chunk
)
{
    ipax_state_update(state, &chunk->index, sizeof(chunk->index));
    ipax_state_update(state, &chunk->offset, sizeof(chunk->offset));
    ipax_state_update(state, &chunk->size, sizeof(chunk->size));
    ipax_state_update(state, chunk->nonce, sizeof(chunk->nonce));
    ipax_state_update(state, chunk->tag, sizeof(chunk->tag));
    ipax_state_update(state, chunk->digest, sizeof(chunk->digest));
}

int ipax_ledger_begin(
    ipax_ledger_writer_t *writer,
    const char *path,
    const ipax_ledger_header_t *header
)
{
    char key_hex[(IPAX_DIGEST_BYTES * 2) + 1];

    if (!writer || !path || !header)
        return -1;

    memset(writer, 0, sizeof(*writer));

    writer->fp = fopen(path, "w");
    if (!writer->fp)
        return -1;

    if (ipax_state_init(&writer->state) != 0)
    {
        fclose(writer->fp);
        writer->fp = NULL;
        return -1;
    }

    writer->first_chunk = 1;
    ipax_hex_encode(header->key_commitment, IPAX_DIGEST_BYTES, key_hex);

    fprintf(
        writer->fp,
        "{\n"
        "  \"engine\":\"%s\",\n"
        "  \"cipher\":\"%s\",\n"
        "  \"chunk_size\":%zu,\n"
        "  \"file_size\":%llu,\n"
        "  \"total_chunks\":%llu,\n"
        "  \"key_commitment\":\"%s\",\n"
        "  \"chunks\":[\n",
        header->engine,
        header->cipher,
        header->chunk_size,
        (unsigned long long) header->file_size,
        (unsigned long long) header->total_chunks,
        key_hex
    );

    return 0;
}

int ipax_ledger_append(
    ipax_ledger_writer_t *writer,
    const ipax_ledger_chunk_t *chunk
)
{
    char nonce_hex[(IPAX_NONCE_BYTES * 2) + 1];
    char tag_hex[(IPAX_TAG_BYTES * 2) + 1];
    char digest_hex[(IPAX_DIGEST_BYTES * 2) + 1];

    if (!writer || !writer->fp || !chunk)
        return -1;

    ledger_state_update(&writer->state, chunk);
    ipax_hex_encode(chunk->nonce, IPAX_NONCE_BYTES, nonce_hex);
    ipax_hex_encode(chunk->tag, IPAX_TAG_BYTES, tag_hex);
    ipax_hex_encode(chunk->digest, IPAX_DIGEST_BYTES, digest_hex);

    if (!writer->first_chunk)
        fprintf(writer->fp, ",\n");

    writer->first_chunk = 0;

    fprintf(
        writer->fp,
        "    {\"index\":%llu,\"offset\":%llu,\"size\":%zu,"
        "\"nonce\":\"%s\",\"mac\":\"%s\",\"digest\":\"%s\","
        "\"status\":\"verified\"}",
        (unsigned long long) chunk->index,
        (unsigned long long) chunk->offset,
        chunk->size,
        nonce_hex,
        tag_hex,
        digest_hex
    );

    fflush(writer->fp);
    return ferror(writer->fp) ? -1 : 0;
}

int ipax_ledger_finalize(
    ipax_ledger_writer_t *writer,
    ipax_ledger_header_t *header
)
{
    char state_hex[(IPAX_DIGEST_BYTES * 2) + 1];

    if (!writer || !writer->fp || !header)
        return -1;

    if (ipax_state_finalize(&writer->state, header->state_digest) != 0)
        return -1;

    ipax_hex_encode(header->state_digest, IPAX_DIGEST_BYTES, state_hex);

    fprintf(
        writer->fp,
        "\n  ],\n"
        "  \"state_digest\":\"%s\"\n"
        "}\n",
        state_hex
    );

    fflush(writer->fp);
    return ferror(writer->fp) ? -1 : 0;
}

void ipax_ledger_close(ipax_ledger_writer_t *writer)
{
    if (!writer)
        return;

    if (writer->fp)
        fclose(writer->fp);

    writer->fp = NULL;
    ipax_state_cleanup(&writer->state);
}

static char *skip_ws(char *p)
{
    while (*p && isspace((unsigned char) *p))
        p++;
    return p;
}

static int parse_u64_field(const char *line, const char *field, uint64_t *out)
{
    char pattern[64];
    char *pos;

    snprintf(pattern, sizeof(pattern), "\"%s\":", field);
    pos = strstr((char *) line, pattern);
    if (!pos)
        return -1;

    pos += strlen(pattern);
    pos = skip_ws(pos);

    return sscanf(pos, "%llu", (unsigned long long *) out) == 1 ? 0 : -1;
}

static int parse_size_field(const char *line, const char *field, size_t *out)
{
    uint64_t value = 0;

    if (parse_u64_field(line, field, &value) != 0)
        return -1;

    *out = (size_t) value;
    return 0;
}

static int parse_string_field(
    const char *line,
    const char *field,
    char *out,
    size_t out_size
)
{
    char pattern[64];
    char *pos;
    char *end;
    size_t len;

    snprintf(pattern, sizeof(pattern), "\"%s\":\"", field);
    pos = strstr((char *) line, pattern);
    if (!pos)
        return -1;

    pos += strlen(pattern);
    end = strchr(pos, '"');
    if (!end)
        return -1;

    len = (size_t) (end - pos);
    if (len >= out_size)
        return -1;

    memcpy(out, pos, len);
    out[len] = '\0';
    return 0;
}

int ipax_ledger_load(
    const char *path,
    ipax_ledger_header_t *header,
    ipax_ledger_chunk_t **chunks_out
)
{
    FILE *fp;
    char line[1024];
    ipax_ledger_chunk_t *chunks = NULL;
    uint64_t chunk_index = 0;

    if (!path || !header || !chunks_out)
        return -1;

    memset(header, 0, sizeof(*header));
    *chunks_out = NULL;

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp))
    {
        char tmp[128];

        if (parse_string_field(line, "engine", header->engine, sizeof(header->engine)) == 0)
            continue;

        if (parse_string_field(line, "cipher", header->cipher, sizeof(header->cipher)) == 0)
            continue;

        if (parse_size_field(line, "chunk_size", &header->chunk_size) == 0)
            continue;

        if (parse_u64_field(line, "file_size", &header->file_size) == 0)
            continue;

        if (parse_u64_field(line, "total_chunks", &header->total_chunks) == 0)
        {
            chunks = calloc((size_t) header->total_chunks, sizeof(*chunks));
            if (!chunks)
            {
                fclose(fp);
                return -1;
            }
            continue;
        }

        if (parse_string_field(line, "key_commitment", tmp, sizeof(tmp)) == 0)
        {
            if (ipax_hex_decode(tmp, header->key_commitment, IPAX_DIGEST_BYTES) != 0)
                goto fail;
            continue;
        }

        if (parse_string_field(line, "state_digest", tmp, sizeof(tmp)) == 0)
        {
            if (ipax_hex_decode(tmp, header->state_digest, IPAX_DIGEST_BYTES) != 0)
                goto fail;
            continue;
        }

        if (strstr(line, "\"index\":"))
        {
            ipax_ledger_chunk_t *chunk;
            char nonce_hex[(IPAX_NONCE_BYTES * 2) + 1];
            char mac_hex[(IPAX_TAG_BYTES * 2) + 1];
            char digest_hex[(IPAX_DIGEST_BYTES * 2) + 1];

            if (!chunks || chunk_index >= header->total_chunks)
                goto fail;

            chunk = &chunks[chunk_index];

            if (parse_u64_field(line, "index", &chunk->index) != 0 ||
                parse_u64_field(line, "offset", &chunk->offset) != 0 ||
                parse_size_field(line, "size", &chunk->size) != 0 ||
                parse_string_field(line, "nonce", nonce_hex, sizeof(nonce_hex)) != 0 ||
                parse_string_field(line, "mac", mac_hex, sizeof(mac_hex)) != 0 ||
                parse_string_field(line, "digest", digest_hex, sizeof(digest_hex)) != 0)
            {
                goto fail;
            }

            if (ipax_hex_decode(nonce_hex, chunk->nonce, IPAX_NONCE_BYTES) != 0 ||
                ipax_hex_decode(mac_hex, chunk->tag, IPAX_TAG_BYTES) != 0 ||
                ipax_hex_decode(digest_hex, chunk->digest, IPAX_DIGEST_BYTES) != 0)
            {
                goto fail;
            }

            chunk_index++;
        }
    }

    fclose(fp);

    if (!chunks || chunk_index != header->total_chunks)
        goto fail_no_close;

    *chunks_out = chunks;
    return 0;

fail:
    fclose(fp);
fail_no_close:
    free(chunks);
    return -1;
}
