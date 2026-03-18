#include "random.h"

#include <sys/random.h>
#include <unistd.h>

int zt_random_fill(unsigned char *buf, size_t len)
{
#if defined(_WIN32) || defined(__MINGW32__)
    #include <windows.h>
    #include <wincrypt.h>
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL,
            PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return -1;
    BOOL ok = CryptGenRandom(hProv, (DWORD)len, buf);
    CryptReleaseContext(hProv, 0);
    return ok ? 0 : -1;
#else
    #include <sys/random.h>
    ssize_t r = getrandom(buf, len, 0);
    return (r >= 0 && (size_t)r == len) ? 0 : -1;
#endif
}
