#include "device.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <string.h>

int zt_discover_device(zt_context_t *ctx) {
    ctx->status = ZT_STATUS_DISCOVER_DEVICE;

    struct stat st;
    if (stat(ctx->device.path, &st) != 0) {
        zt_context_set_error(ctx, 1, "Failed to stat device");
        return -1;
    }

    int fd = open(ctx->device.path, O_RDONLY);
    if (fd < 0) {
        zt_context_set_error(ctx, 2, "Failed to open device");
        return -1;
    }

    if (S_ISBLK(st.st_mode)) {
        unsigned long long size;
        if (ioctl(fd, BLKGETSIZE64, &size) == 0)
            ctx->device.size_bytes = size;
    } else if (S_ISREG(st.st_mode)) {
        ctx->device.size_bytes = st.st_size;
    } else {
        close(fd);
        zt_context_set_error(ctx, 3, "Unsupported target type");
        return -1;
    }

    ctx->device.block_size = 512;
    strncpy(ctx->device.transport, "unknown",
            sizeof(ctx->device.transport) - 1);

    close(fd);
    ctx->status = ZT_STATUS_COLLECT_METADATA;
    return 0;
}
