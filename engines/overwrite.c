#include "engine.h"
#include "../util/random.c"

#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

typedef struct {
    int fd;
    off_t start;
    off_t end;
    size_t chunk;
} worker_arg_t;

static void *worker(void *arg) {
    worker_arg_t *w = arg;
    unsigned char *buf = malloc(w->chunk);
    if (!buf) return (void*)1;

    off_t pos = w->start;
    while (pos < w->end) {
        size_t n = w->chunk;
        if (pos + (off_t)n > w->end)
            n = w->end - pos;

        if (zt_random_fill(buf, n) != 0)
            break;

        if (pwrite(w->fd, buf, n, pos) != (ssize_t)n)
            break;

        pos += n;
    }

    free(buf);
    return NULL;
}

static int overwrite_probe(zt_context_t *ctx) {
    (void)ctx;
    return 1;
}

static int overwrite_erase(zt_context_t *ctx) {
    ctx->status = ZT_STATUS_ERASING;

    int fd = open(ctx->device.path, O_WRONLY);
    if (fd < 0) {
        zt_context_set_error(ctx, 10, "Failed to open device for writing");
        return -1;
    }

    pthread_t tids[ctx->threads];
    worker_arg_t args[ctx->threads];

    off_t span = ctx->device.size_bytes / ctx->threads;

    for (int t = 0; t < ctx->threads; t++) {
        args[t].fd = fd;
        args[t].start = span * t;
        args[t].end = (t == ctx->threads - 1)
                        ? ctx->device.size_bytes
                        : span * (t + 1);
        args[t].chunk = ctx->chunk_bytes;

        pthread_create(&tids[t], NULL, worker, &args[t]);
    }

    for (int t = 0; t < ctx->threads; t++)
        pthread_join(tids[t], NULL);

    fsync(fd);
    close(fd);

    ctx->status = ZT_STATUS_COMPLETE;
    ctx->end_time = time(NULL);
    return 0;
}

const zt_erase_engine_t overwrite_engine = {
    .name  = "overwrite",
    .probe = overwrite_probe,
    .erase = overwrite_erase
};
