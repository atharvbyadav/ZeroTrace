#ifndef ZT_CONTEXT_H
#define ZT_CONTEXT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define ZEROTRACE_VERSION "2.1"

typedef enum
{
    ZT_STATUS_INIT = 0,
    ZT_STATUS_READY,
    ZT_STATUS_ERASING,
    ZT_STATUS_VERIFYING,
    ZT_STATUS_COMPLETE,
    ZT_STATUS_ERROR
} zt_status_t;

typedef struct
{
    char path[512];
    uint64_t size_bytes;
} zt_device_t;

typedef struct
{
    char zerotrace_version[32];
    zt_status_t status;
    zt_device_t device;
    char engine_name[64];
    char key_path[512];
    char ledger_path[512];
    char certificate_path[512];
    int passes;
    int threads;
    size_t chunk_bytes;
    int verbose;
    int verify_only;
    uint64_t processed_chunks;
    time_t start_time;
    time_t end_time;
    int error_code;
    char error_msg[256];
} zt_context_t;

zt_context_t *zt_context_create(void);

void zt_context_destroy(zt_context_t *);

void zt_context_set_error(
    zt_context_t *,
    int,
    const char *
);

#endif
