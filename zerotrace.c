// zerotrace.c
// Secure low-level eraser with per-pass hashes, final zeroing, and certificate.
// Compile: gcc -O2 -o zerotrace zerotrace.c -lcrypto -lpthread

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <getopt.h>
#include <sys/random.h>
#include <openssl/evp.h>

#define DEFAULT_THREADS 4
#define DEFAULT_CHUNK_MB 1
#define BUF_MB(x) ((size_t)(x) * 1024 * 1024)
#define HASH_LEN 32

typedef struct {
    int fd;
    off_t start;
    off_t end;
    size_t buf_size;
} worker_arg_t;

static int use_getrandom = 1;

// secure random fill: try getrandom, fall back to /dev/urandom
static int secure_random_fill(unsigned char *buf, size_t len) {
    size_t off = 0;
    if (use_getrandom) {
        while (off < len) {
            ssize_t r = getrandom(buf + off, len - off, 0);
            if (r < 0) {
                if (errno == EINTR) continue;
                // fall back
                use_getrandom = 0;
                break;
            }
            off += (size_t)r;
        }
        if (off == len) return 0;
    }
    // fallback
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(buf, 1, len, f);
    fclose(f);
    if (got != len) return -1;
    return 0;
}

// thread worker: fill its region with random bytes and write
static void *worker_fn(void *arg) {
    worker_arg_t *wa = (worker_arg_t*)arg;
    off_t pos = wa->start;
    unsigned char *buf = malloc(wa->buf_size);
    if (!buf) { perror("malloc"); pthread_exit((void*)1); }

    while (pos < wa->end) {
        size_t to_write = wa->buf_size;
        if ((off_t)pos + (off_t)to_write > wa->end) to_write = (size_t)(wa->end - pos);
        if (secure_random_fill(buf, to_write) != 0) {
            fprintf(stderr, "secure_random_fill failed\n");
            free(buf);
            pthread_exit((void*)1);
        }
        ssize_t w = pwrite(wa->fd, buf, to_write, pos);
        if (w < 0) {
            perror("pwrite");
            free(buf);
            pthread_exit((void*)1);
        } else if ((size_t)w != to_write) {
            fprintf(stderr, "short write\n");
            free(buf);
            pthread_exit((void*)1);
        }
        pos += w;
    }

    free(buf);
    pthread_exit(NULL);
}

// compute SHA256 of a file/device into hash_out (32 bytes) using EVP
static int compute_sha256(const char *path, size_t buf_size, unsigned char out[HASH_LEN]) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) { fprintf(stderr,"EVP_MD_CTX_new failed\n"); return -1; }
    if (1 != EVP_DigestInit_ex(md, EVP_sha256(), NULL)) { EVP_MD_CTX_free(md); return -1; }

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open for hash"); EVP_MD_CTX_free(md); return -1; }

    unsigned char *buf = malloc(buf_size);
    if (!buf) { perror("malloc"); close(fd); EVP_MD_CTX_free(md); return -1; }

    ssize_t r;
    while ((r = read(fd, buf, buf_size)) > 0) {
        if (1 != EVP_DigestUpdate(md, buf, r)) {
            fprintf(stderr,"DigestUpdate failed\n"); free(buf); close(fd); EVP_MD_CTX_free(md); return -1;
        }
    }
    if (r < 0) perror("read during hash");

    unsigned int outlen = 0;
    if (1 != EVP_DigestFinal_ex(md, out, &outlen)) { fprintf(stderr,"DigestFinal failed\n"); free(buf); close(fd); EVP_MD_CTX_free(md); return -1; }

    free(buf);
    close(fd);
    EVP_MD_CTX_free(md);
    return 0;
}

static void print_hex(const unsigned char *h, size_t n) {
    for (size_t i=0;i<n;i++) printf("%02x", h[i]);
}

// write certificate text file with metadata, per-pass hashes and final hash
static int write_certificate(const char *cert_path, const char *target, off_t dev_size,
                             int passes, size_t chunk_bytes, int threads,
                             unsigned char **pass_hashes, unsigned char final_hash[HASH_LEN]) {

    FILE *f = fopen(cert_path, "w");
    if (!f) { perror("fopen cert"); return -1; }

    time_t now = time(NULL);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f, "=================== ZeroTrace Secure Erasure Certificate ===================\n\n");
    fprintf(f, "Target: %s\n", target);
    fprintf(f, "Target Size: %jd bytes\n", (intmax_t)dev_size);
    fprintf(f, "Date/Time: %s\n", timestr);
    fprintf(f, "ZeroTrace Version: v1.2\n");
    fprintf(f, "Number of passes: %d\n", passes);
    fprintf(f, "Per-thread buffer (chunk): %zu bytes\n", chunk_bytes);
    fprintf(f, "Threads used: %d\n\n", threads);

    fprintf(f, "Hashes after each pass (SHA-256):\n");
    char hex[HASH_LEN*2+1];
    for (int p=0;p<passes;p++) {
        // convert to hex
        for (int i=0;i<HASH_LEN;i++) sprintf(&hex[i*2], "%02x", pass_hashes[p][i]);
        hex[HASH_LEN*2] = 0;
        fprintf(f, "Pass %d: %s\n", p+1, hex);
    }
    // final
    for (int i=0;i<HASH_LEN;i++) sprintf(&hex[i*2], "%02x", final_hash[i]);
    hex[HASH_LEN*2] = 0;
    fprintf(f, "\nFinal Zeroed Disk Hash (SHA-256): %s\n\n", hex);

    fprintf(f, "Notes:\n - Per-pass hashes are full-disk SHA-256 computed after each overwrite pass.\n - Final hash computed after final zeroing pass; it matches current disk contents.\n - This certificate is a textual record; convert to PDF as needed.\n");
    fprintf(f, "==============================================================================\n");
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    const char *target = NULL;
    const char *cert = NULL;
    int passes = 0;
    int threads = DEFAULT_THREADS;
    int chunk_mb = DEFAULT_CHUNK_MB;

    static struct option longopts[] = {
        {"cert", required_argument, NULL, 0},
        {0,0,0,0}
    };

    int opt;
    int longindex;
    while ((opt = getopt_long(argc, argv, "d:p:t:c:", longopts, &longindex)) != -1) {
        if (opt == 0) { // long opts
            if (strcmp(longopts[longindex].name, "cert")==0) cert = optarg;
        } else {
            switch (opt) {
                case 'd': target = optarg; break;
                case 'p': passes = atoi(optarg); break;
                case 't': threads = atoi(optarg); break;
                case 'c': chunk_mb = atoi(optarg); break;
                default:
                    fprintf(stderr, "Usage: %s -d <device/file> -p <passes> -t <threads> -c <chunk_MB> --cert <cert.txt>\n", argv[0]);
                    return 1;
            }
        }
    }

    if (!target || !cert || passes <= 0 || threads <= 0) {
        fprintf(stderr, "Missing required args.\nUsage: %s -d <device/file> -p <passes> -t <threads> -c <chunk_MB> --cert <cert.txt>\n", argv[0]);
        return 1;
    }

    size_t chunk_bytes = BUF_MB(chunk_mb);

    // stat target and open
    struct stat st;
    if (stat(target, &st) != 0) { perror("stat target"); return 1; }

    off_t dev_size = 0;
    int fd = open(target, O_RDWR);
    if (fd < 0) { perror("open target (need root)"); return 1; }

    if (S_ISBLK(st.st_mode)) {
        unsigned long long n;
        if (ioctl(fd, BLKGETSIZE64, &n) != 0) {
            perror("ioctl BLKGETSIZE64");
            close(fd);
            return 1;
        }
        dev_size = (off_t)n;
    } else if (S_ISREG(st.st_mode)) {
        dev_size = st.st_size;
    } else {
        fprintf(stderr, "Unsupported target type\n"); close(fd); return 1;
    }

    printf("Target: %s\nTarget size: %jd bytes\nPasses: %d Threads: %d Chunk_MB: %d\nCert: %s\n",
           target, (intmax_t)dev_size, passes, threads, chunk_mb, cert);

    // confirmation
    char confirm[16];
    fprintf(stderr, "WARNING: This will PERMANENTLY ERASE all data on %s\nType YES to confirm: ", target);
    if (!fgets(confirm, sizeof(confirm), stdin)) { fprintf(stderr,"No input\n"); close(fd); return 1; }
    // trim newline
    confirm[strcspn(confirm, "\r\n")] = 0;
    if (strcmp(confirm, "YES") != 0) { fprintf(stderr,"Aborted by user\n"); close(fd); return 1; }

    // allocate pass hashes
    unsigned char **pass_hashes = calloc(passes, sizeof(unsigned char*));
    if (!pass_hashes) { perror("calloc"); close(fd); return 1; }
    for (int i=0;i<passes;i++) {
        pass_hashes[i] = calloc(HASH_LEN,1);
        if (!pass_hashes[i]) { perror("calloc"); close(fd); return 1; }
    }

    // main passes
    for (int p=0;p<passes;p++) {
        fprintf(stderr, "Starting pass %d/%d\n", p+1, passes);

        // create workers
        pthread_t *tids = calloc(threads, sizeof(pthread_t));
        worker_arg_t *args = calloc(threads, sizeof(worker_arg_t));
        if (!tids || !args) { perror("calloc threads"); close(fd); return 1; }

        off_t span = dev_size / threads;
        for (int t=0;t<threads;t++) {
            args[t].fd = fd;
            args[t].start = (off_t)t * span;
            args[t].end = (t==threads-1) ? dev_size : (off_t)( (t+1) * span );
            args[t].buf_size = chunk_bytes;
            if (pthread_create(&tids[t], NULL, worker_fn, &args[t]) != 0) {
                perror("pthread_create"); close(fd); return 1;
            }
        }

        // progress loop: naive - print until reads equal dev_size via periodic fsync check
        // join threads
        for (int t=0;t<threads;t++) pthread_join(tids[t], NULL);

        // ensure flush
        fsync(fd);

        // compute hash of device after pass: compute_sha256 accepts a path string, so use target
        if (compute_sha256(target, chunk_bytes, pass_hashes[p]) != 0) {
            fprintf(stderr,"compute_sha256 failed after pass %d\n", p+1);
            close(fd); return 1;
        }
        char passhex[HASH_LEN*2+1];
        for (int i=0;i<HASH_LEN;i++) sprintf(&passhex[i*2], "%02x", pass_hashes[p][i]);
        passhex[HASH_LEN*2] = 0;
        fprintf(stderr, "Pass %d complete. SHA256: %s\n", p+1, passhex);

        free(tids);
        free(args);
    }

    // final zeroing
    fprintf(stderr, "Performing final zeroing pass (writing zeros to entire device)...\n");
    unsigned char *zero_buf = calloc(1, chunk_bytes);
    if (!zero_buf) { perror("calloc zero"); close(fd); return 1; }
    off_t pos = 0;
    while (pos < dev_size) {
        size_t to_write = chunk_bytes;
        if ((off_t)pos + (off_t)to_write > dev_size) to_write = (size_t)(dev_size - pos);
        ssize_t w = pwrite(fd, zero_buf, to_write, pos);
        if (w < 0) { perror("pwrite zero"); free(zero_buf); close(fd); return 1; }
        pos += w;
        double prog = (double)pos / (double)dev_size * 100.0;
        fprintf(stderr, "\rZeroing progress: %.2f%%", prog);
        fflush(stderr);
    }
    fprintf(stderr, "\n");
    fsync(fd);
    free(zero_buf);

    // compute final hash
    unsigned char final_hash[HASH_LEN];
    if (compute_sha256(target, chunk_bytes, final_hash) != 0) {
        fprintf(stderr,"compute_sha256 failed for final hash\n"); close(fd); return 1;
    }
    char finalhex[HASH_LEN*2+1];
    for (int i=0;i<HASH_LEN;i++) sprintf(&finalhex[i*2], "%02x", final_hash[i]);
    finalhex[HASH_LEN*2] = 0;
    fprintf(stderr, "Final zeroed SHA256: %s\n", finalhex);

    // write certificate
    if (write_certificate(cert, target, dev_size, passes, chunk_bytes, threads, pass_hashes, final_hash) != 0) {
        fprintf(stderr, "Failed to write certificate\n");
    } else {
        printf("Certificate written to: %s\n", cert);
    }

    // cleanup
    for (int i=0;i<passes;i++) free(pass_hashes[i]);
    free(pass_hashes);
    close(fd);
    return 0;
}
