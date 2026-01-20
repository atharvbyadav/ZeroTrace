#include "cert.h"
#include <stdio.h>
#include <time.h>

static void iso_time(char *buf, size_t n, time_t t) {
    struct tm *tm = gmtime(&t);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", tm);
}

int zt_write_json_certificate(const zt_context_t *ctx, const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;

    char start[32], end[32];
    iso_time(start, sizeof(start), ctx->start_time);
    iso_time(end, sizeof(end), ctx->end_time);

    fprintf(f, "{\n");
    fprintf(f, "  \"zerotrace_version\": \"%s\",\n", ctx->zerotrace_version);
    fprintf(f, "  \"timestamps\": { \"start\": \"%s\", \"end\": \"%s\" },\n",
            start, end);

    fprintf(f, "  \"device\": {\n");
    fprintf(f, "    \"path\": \"%s\",\n", ctx->device.path);
    fprintf(f, "    \"size_bytes\": %jd\n",
            (intmax_t)ctx->device.size_bytes);
    fprintf(f, "  },\n");

    fprintf(f, "  \"erase\": {\n");
    fprintf(f, "    \"engine\": %d,\n", ctx->engine);
    fprintf(f, "    \"passes\": %d,\n", ctx->passes);
    fprintf(f, "    \"threads\": %d\n", ctx->threads);
    fprintf(f, "  }\n");

    fprintf(f, "}\n");
    fclose(f);
    return 0;
}
