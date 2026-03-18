#include "cert.h"

#include <stdio.h>

int zt_write_json_certificate(
    zt_context_t *ctx,
    const char *path
)
{
    FILE *f=fopen(path,"w");

    fprintf(f,
        "{\n"
        "\"version\":\"%s\",\n"
        "\"device\":\"%s\",\n"
        "\"size\":%lu\n"
        "}\n",
        ctx->zerotrace_version,
        ctx->device.path,
        ctx->device.size_bytes
    );

    fclose(f);

    return 0;
}
