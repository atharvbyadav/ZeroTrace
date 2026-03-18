#include "ipax_ledger.h"

#include <stdio.h>

void ipax_ledger_record(
    uint64_t offset,
    size_t size,
    unsigned char *data
)
{
    FILE *f =
        fopen(
            "ipax_ledger.bin",
            "ab"
        );

    fwrite(
        &offset,
        sizeof(offset),
        1,
        f
    );

    fwrite(
        &size,
        sizeof(size),
        1,
        f
    );

    fwrite(
        data,
        size,
        1,
        f
    );

    fclose(f);
}
