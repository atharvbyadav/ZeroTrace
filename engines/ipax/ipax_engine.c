#include "ipax_engine.h"

#include "../../core/context.h"

#include "ipax_transform.h"
#include "ipax_ledger.h"
#include "ipax_state.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>


static int ipax_erase(
    zt_context_t *ctx
)
{
    int fd =
        open(
            ctx->device.path,
            O_RDWR
        );

    if (fd < 0)
    {
        zt_context_set_error(
            ctx,
            100,
            "IPAX open failed"
        );

        return -1;
    }

    uint64_t offset = 0;

    unsigned char *buffer =
        malloc(ctx->chunk_bytes);

    ipax_state_t state;

    ipax_state_init(&state);

    while (offset < ctx->device.size_bytes)
    {
        size_t size =
            ctx->chunk_bytes;

        if (offset + size >
            ctx->device.size_bytes)
        {
            size =
                ctx->device.size_bytes
                - offset;
        }

        pread(fd, buffer, size, offset);

        ipax_transform(
            buffer,
            size,
            offset
        );

        pwrite(fd, buffer, size, offset);

        ipax_ledger_record(
            offset,
            size,
            buffer
        );

        ipax_state_update(
            &state,
            buffer,
            size
        );

        offset += size;
    }

    ipax_state_finalize(
        &state,
        ctx->ipax_state_hash
    );

    close(fd);

    free(buffer);

    return 0;
}


const zt_erase_engine_t ipax_engine =
{
    .name = "ipax",
    .erase = ipax_erase
};
