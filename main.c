#include <stdio.h>
#include <string.h>

#include "core/context.h"
#include "core/workflow.h"

#include "device/device.h"

#include "engines/engine.h"
#include "engines/registry.h"

#include "cert/cert.h"
#include "cert/sign_ed25519.h"


static void usage(void)
{
    printf(
        "\nZeroTrace CLI\n\n"

        "Commands:\n"

        "  erase   --device <path> [--engine overwrite]\n"
        "  keygen\n"
        "  sign    --cert <file> --key <private.pem>\n"
        "  verify  --cert <file> --key <public.pem>\n\n"
    );
}


static int cmd_keygen(void)
{
    return zt_ed25519_keygen(
        "zt_priv.pem",
        "zt_pub.pem"
    );
}


static int cmd_sign(
    const char *cert,
    const char *key
)
{
    return zt_ed25519_sign_file(
        cert,
        key
    );
}


static int cmd_verify(
    const char *cert,
    const char *key
)
{
    return zt_ed25519_verify_file(
        cert,
        key
    );
}


static int cmd_erase(
    const char *device,
    const char *engine_name
)
{
    zt_context_t *ctx =
        zt_context_create();

    strncpy(
        ctx->device.path,
        device,
        sizeof(ctx->device.path) - 1
    );

    if (zt_discover_device(ctx) != 0)
    {
        printf("Device discovery failed\n");
        return 1;
    }

    const zt_erase_engine_t *engine =
        zt_get_engine(engine_name);

    if (!engine)
    {
        printf("Invalid engine\n");
        return 1;
    }

    printf("ZeroTrace %s\n",
        ctx->zerotrace_version);

    printf("Device: %s (%lu bytes)\n",
        ctx->device.path,
        ctx->device.size_bytes);

    printf("Engine: %s\n",
        engine->name);

    int rc =
        zt_run_workflow(
            ctx,
            engine
        );

    if (rc == 0)
    {
        zt_write_json_certificate(
            ctx,
            "zerotrace_cert.json"
        );

        printf(
            "Certificate written: zerotrace_cert.json\n"
        );
    }

    zt_context_destroy(ctx);

    return rc;
}


int main(
    int argc,
    char **argv
)
{
    if (argc < 2)
    {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "keygen") == 0)
    {
        return cmd_keygen();
    }

    if (strcmp(argv[1], "sign") == 0)
    {
        const char *cert = NULL;
        const char *key = NULL;

        for (int i = 2; i < argc; i++)
        {
            if (strcmp(argv[i], "--cert") == 0)
                cert = argv[++i];

            else if (strcmp(argv[i], "--key") == 0)
                key = argv[++i];
        }

        if (!cert || !key)
        {
            usage();
            return 1;
        }

        return cmd_sign(cert, key);
    }

    if (strcmp(argv[1], "verify") == 0)
    {
        const char *cert = NULL;
        const char *key = NULL;

        for (int i = 2; i < argc; i++)
        {
            if (strcmp(argv[i], "--cert") == 0)
                cert = argv[++i];

            else if (strcmp(argv[i], "--key") == 0)
                key = argv[++i];
        }

        if (!cert || !key)
        {
            usage();
            return 1;
        }

        return cmd_verify(cert, key);
    }

    if (strcmp(argv[1], "erase") == 0)
    {
        const char *device = NULL;
        const char *engine = "overwrite";

        for (int i = 2; i < argc; i++)
        {
            if (strcmp(argv[i], "--device") == 0)
                device = argv[++i];

            else if (strcmp(argv[i], "--engine") == 0)
                engine = argv[++i];
        }

        if (!device)
        {
            usage();
            return 1;
        }

        return cmd_erase(device, engine);
    }

    usage();

    return 1;
}
