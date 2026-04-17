#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cert/cert.h"
#include "cert/sign_ed25519.h"
#include "core/context.h"
#include "core/workflow.h"
#include "device/device.h"
#include "engines/engine.h"
#include "engines/registry.h"

static void usage(void)
{
    printf(
        "\nZeroTrace CLI\n\n"
        "Modern workflow:\n"
        "  ./zerotrace --help\n"
        "  ./zerotrace --list-engines\n"
        "  ./zerotrace --engine ipax --input test_disk.img --key ipax.key "
        "--ledger ipax_ledger.json --chunk-size 4096 --verbose\n"
        "  ./zerotrace --verify --engine ipax --input test_disk.img --key "
        "ipax.key --ledger ipax_ledger.json --verbose\n\n"
        "Legacy commands:\n"
        "  erase   --device <path> [--engine overwrite]\n"
        "  keygen\n"
        "  sign    --cert <file> --key <private.pem>\n"
        "  verify  --cert <file> --key <public.pem>\n\n"
    );
}

static int cmd_keygen(void)
{
    int rc = zt_ed25519_keygen("zt_priv.pem", "zt_pub.pem");

    if (rc == 0)
    {
        printf("\nKey generation SUCCESS\n");
        printf("Private key: zt_priv.pem\n");
        printf("Public key : zt_pub.pem\n\n");
    }
    else
    {
        printf("\nKey generation FAILED\n\n");
    }

    return rc;
}

static int cmd_sign(const char *cert, const char *key)
{
    int rc = zt_ed25519_sign_file(cert, key);

    if (rc == 0)
    {
        printf("\nSigning SUCCESS\n");
        printf("Signature file created: signature.bin\n\n");
    }
    else
    {
        printf("\nSigning FAILED\n\n");
    }

    return rc;
}

static int cmd_verify_signature(const char *cert, const char *key)
{
    int rc = zt_ed25519_verify_file(cert, key);

    if (rc == 0)
        printf("\nVerification SUCCESS\n\n");
    else
        printf("\nVerification FAILED\n\n");

    return rc;
}

static void list_engines(void)
{
    size_t i;

    for (i = 0; i < zt_engine_count(); i++)
    {
        const zt_erase_engine_t *engine = zt_engine_at(i);
        printf("%s", engine->name);
        if (engine->description)
            printf(" - %s", engine->description);
        printf("\n");
    }
}

static int parse_common_args(
    int argc,
    char **argv,
    int start,
    zt_context_t *ctx
)
{
    int i;

    for (i = start; i < argc; i++)
    {
        if (strcmp(argv[i], "--engine") == 0 && i + 1 < argc)
        {
            strncpy(ctx->engine_name, argv[++i], sizeof(ctx->engine_name) - 1);
        }
        else if ((strcmp(argv[i], "--input") == 0 || strcmp(argv[i], "--device") == 0) && i + 1 < argc)
        {
            strncpy(ctx->device.path, argv[++i], sizeof(ctx->device.path) - 1);
        }
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
        {
            strncpy(ctx->key_path, argv[++i], sizeof(ctx->key_path) - 1);
        }
        else if (strcmp(argv[i], "--ledger") == 0 && i + 1 < argc)
        {
            strncpy(ctx->ledger_path, argv[++i], sizeof(ctx->ledger_path) - 1);
        }
        else if (strcmp(argv[i], "--chunk-size") == 0 && i + 1 < argc)
        {
            ctx->chunk_bytes = (size_t) strtoull(argv[++i], NULL, 10);
        }
        else if (strcmp(argv[i], "--verbose") == 0)
        {
            ctx->verbose = 1;
        }
        else if (strcmp(argv[i], "--verify") == 0)
        {
            ctx->verify_only = 1;
        }
        else if (strcmp(argv[i], "--certificate") == 0 && i + 1 < argc)
        {
            strncpy(ctx->certificate_path, argv[++i], sizeof(ctx->certificate_path) - 1);
        }
        else
        {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return -1;
        }
    }

    return 0;
}

static int run_engine_operation(zt_context_t *ctx)
{
    const zt_erase_engine_t *engine;
    int rc;

    if (!ctx->device.path[0])
    {
        fprintf(stderr, "Missing --input/--device\n");
        return 1;
    }

    if (ctx->chunk_bytes == 0)
    {
        fprintf(stderr, "--chunk-size must be greater than zero\n");
        return 1;
    }

    if (zt_discover_device(ctx) != 0)
    {
        fprintf(stderr, "Device discovery failed for %s\n", ctx->device.path);
        return 1;
    }

    engine = zt_get_engine(ctx->engine_name);
    if (!engine)
    {
        fprintf(stderr, "Invalid engine: %s\n", ctx->engine_name);
        return 1;
    }

    printf("\nZeroTrace %s\n", ctx->zerotrace_version);
    printf("Device: %s (%llu bytes)\n",
        ctx->device.path,
        (unsigned long long) ctx->device.size_bytes);
    printf("Engine: %s\n\n", engine->name);

    if (ctx->verify_only)
    {
        if (!engine->verify)
        {
            fprintf(stderr, "Engine %s does not support verification\n", engine->name);
            return 1;
        }

        ctx->status = ZT_STATUS_VERIFYING;
        rc = engine->verify(ctx);
        if (rc == 0)
        {
            printf("[PASS] cryptographic erasure verified\n\n");
            return 0;
        }

        fprintf(stderr, "[FAIL] %s\n\n",
            ctx->error_msg[0] ? ctx->error_msg : "verification failed");
        return 1;
    }

    rc = zt_run_workflow(ctx, engine);
    if (rc == 0)
    {
        zt_write_json_certificate(ctx, ctx->certificate_path);
        printf("\nErase SUCCESS\n");
        printf("Certificate written: %s\n\n", ctx->certificate_path);
        return 0;
    }

    fprintf(stderr, "\nErase FAILED\n");
    if (ctx->error_msg[0])
        fprintf(stderr, "%s\n", ctx->error_msg);
    fprintf(stderr, "\n");
    return 1;
}

static int handle_modern_cli(int argc, char **argv)
{
    zt_context_t *ctx = zt_context_create();
    int rc;

    if (!ctx)
        return 1;

    rc = parse_common_args(argc, argv, 1, ctx);
    if (rc == 0)
        rc = run_engine_operation(ctx);

    zt_context_destroy(ctx);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
    {
        usage();
        return 0;
    }

    if (strcmp(argv[1], "--list-engines") == 0)
    {
        list_engines();
        return 0;
    }

    if (strcmp(argv[1], "keygen") == 0)
        return cmd_keygen();

    if (strcmp(argv[1], "sign") == 0)
    {
        const char *cert = NULL;
        const char *key = NULL;
        int i;

        for (i = 2; i < argc; i++)
        {
            if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc)
                cert = argv[++i];
            else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
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
        int i;

        for (i = 2; i < argc; i++)
        {
            if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc)
                cert = argv[++i];
            else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
                key = argv[++i];
        }

        if (cert && key)
            return cmd_verify_signature(cert, key);
    }

    if (strcmp(argv[1], "erase") == 0)
    {
        zt_context_t *ctx = zt_context_create();
        int rc;

        if (!ctx)
            return 1;

        rc = parse_common_args(argc, argv, 2, ctx);
        if (rc == 0)
            rc = run_engine_operation(ctx);

        zt_context_destroy(ctx);
        return rc;
    }

    return handle_modern_cli(argc, argv);
}
