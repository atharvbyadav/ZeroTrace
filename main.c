#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "core/context.h"
#include "core/workflow.h"
#include "device/device.h"
#include "engines/engine.h"
#include "cert/cert.h"


static void usage(const char *prog)
{
    printf(
        "Usage:\n"
        "%s erase --device <path> [--engine overwrite]\n",
        prog
    );
}


int main(int argc, char **argv)
{
    if (argc < 4)
    {
        usage(argv[0]);
        return 1;
    }

    const char *device = NULL;
    const char *engine_name = "overwrite";

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--device") == 0)
            device = argv[++i];

        else if (strcmp(argv[i], "--engine") == 0)
            engine_name = argv[++i];
    }

    if (!device)
        return 1;

    zt_context_t *ctx = zt_context_create();

    strncpy(ctx->device.path, device, sizeof(ctx->device.path)-1);

    if (zt_discover_device(ctx) != 0)
        return 1;

    const zt_erase_engine_t *engine =
        zt_get_engine(engine_name);

    if (!engine)
    {
        printf("Invalid engine\n");
        return 1;
    }

    printf("ZeroTrace %s\n", ctx->zerotrace_version);
    printf("Device: %s (%lu bytes)\n",
           ctx->device.path,
           ctx->device.size_bytes);

    printf("Engine: %s\n", engine->name);

    int rc = zt_run_workflow(ctx, engine);

    if (rc != 0)
    {
        printf("Error: %s\n", ctx->error_msg);
        return 1;
    }

    zt_write_json_certificate(ctx, "zerotrace_cert.json");

    printf("Certificate written\n");

    zt_context_destroy(ctx);

    return 0;
}
