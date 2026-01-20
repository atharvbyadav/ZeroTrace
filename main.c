#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "core/context.h"
#include "core/workflow.h"
#include "cert/sign_ed25519.h"

static void usage(const char *p) {
    printf("Usage:\n");
    printf("  %s erase --device <path>\n", p);
    printf("  %s keygen\n", p);
    printf("  %s verify <cert.json>\n", p);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "keygen") == 0) {
        return zt_ed25519_keygen("zt_priv.pem", "zt_pub.pem");
    }

    if (strcmp(argv[1], "verify") == 0 && argc == 3) {
        int rc = zt_ed25519_verify_file(argv[2], "zt_pub.pem");
        printf(rc == 0 ? "Certificate valid\n" : "Certificate INVALID\n");
        return rc;
    }

    if (strcmp(argv[1], "erase") != 0) {
        usage(argv[0]);
        return 1;
    }

    zt_context_t *ctx = zt_context_create();
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            strncpy(ctx->device.path, argv[++i],
                    sizeof(ctx->device.path) - 1);
        }
    }

    int rc = zt_run_workflow(ctx);
    zt_context_destroy(ctx);

    if (rc == 0)
        zt_ed25519_sign_file("zerotrace_cert.json", "zt_priv.pem");

    return rc;
}
