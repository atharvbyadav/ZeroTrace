#include "cert.h"

#include <stdio.h>

int zt_write_json_certificate(
    zt_context_t *ctx,
    const char *path
)
{
    FILE *f;

    if (!ctx || !path)
        return -1;

    f = fopen(path, "w");
    if (!f)
        return -1;

    fprintf(
        f,
        "{\n"
        "  \"version\":\"%s\",\n"
        "  \"engine\":\"%s\",\n"
        "  \"device\":\"%s\",\n"
        "  \"size\":%llu,\n"
        "  \"chunk_size\":%zu,\n"
        "  \"processed_chunks\":%llu,\n"
        "  \"ledger\":\"%s\",\n"
        "  \"started_at\":%lld,\n"
        "  \"ended_at\":%lld,\n"
        "  \"status\":\"%s\"\n"
        "}\n",
        ctx->zerotrace_version,
        ctx->engine_name,
        ctx->device.path,
        (unsigned long long) ctx->device.size_bytes,
        ctx->chunk_bytes,
        (unsigned long long) ctx->processed_chunks,
        ctx->ledger_path[0] ? ctx->ledger_path : "",
        (long long) ctx->start_time,
        (long long) ctx->end_time,
        ctx->status == ZT_STATUS_COMPLETE ? "complete" : "error"
    );

    fclose(f);
    return 0;
}
