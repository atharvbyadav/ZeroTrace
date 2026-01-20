#ifndef ZT_CONTEXT_H
#define ZT_CONTEXT_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define ZT_HASH_LEN 32

typedef enum {
    ZT_MODE_ERASE,
    ZT_MODE_DRY_RUN
} zt_mode_t;

typedef enum {
    ZT_ENGINE_OVERWRITE,
    ZT_ENGINE_ATA_SECURE,
    ZT_ENGINE_CRYPTO_ERASE,
    ZT_ENGINE_IPAX
} zt_engine_type_t;

typedef enum {
    ZT_STATUS_INIT,
    ZT_STATUS_DISCOVER_DEVICE,
    ZT_STATUS_COLLECT_METADATA,
    ZT_STATUS_READY,
    ZT_STATUS_ERASING,
    ZT_STATUS_COMPLETE,
    ZT_STATUS_ERROR
} zt_status_t;

typedef struct {
    char path[256];
    char model[128];
    char serial[128];
    char transport[32];

    off_t size_bytes;
    uint32_t block_size;
} zt_device_info_t;

typedef struct {
    char zerotrace_version[16];

    zt_mode_t mode;
    zt_engine_type_t engine;
    zt_status_t status;

    zt_device_info_t device;

    int passes;
    int threads;
    size_t chunk_bytes;

    time_t start_time;
    time_t end_time;

    int error_code;
    char error_msg[256];

    void *engine_ctx;

} zt_context_t;

zt_context_t *zt_context_create(void);
void zt_context_destroy(zt_context_t *ctx);
void zt_context_set_error(zt_context_t *ctx, int code, const char *msg);

#endif
