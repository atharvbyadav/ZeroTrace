#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "core/context.h"
#include "core/workflow.h"

static void usage(const char *p) {
    printf("Usage:\n");
    printf("  %s erase --device <path> [--engine overwrite] [--dry-run]\n", p);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "erase") != 0) {
        usage(argv[0]);
        return 1;
    }

    zt_context_t *ctx = zt_context_create();
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            strncpy(ctx->device.path, argv[++i],
                    sizeof(ctx->device.path) - 1);
        } else if (strcmp(argv[i], "--engine") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "overwrite") == 0) {
                ctx->engine = ZT_ENGINE_OVERWRITE;
            }
            i++;
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            ctx->mode = ZT_MODE_DRY_RUN;
        }
    }

    if (ctx->device.path[0] == '\0') {
        fprintf(stderr, "No device specified\n");
        zt_context_destroy(ctx);
        return 1;
    }

    int rc = zt_run_workflow(ctx);

    if (rc != 0) {
        fprintf(stderr, "Error: %s\n", ctx->error_msg);
    }

    zt_context_destroy(ctx);
    return rc != 0;
}
