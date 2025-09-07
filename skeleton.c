#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define DEFAULT_CHUNK 1048576 // 1 MB
#define DEFAULT_PASSES 3

void confirm_target(const char *disk) {
    printf("WARNING: All data on %s will be permanently erased!\n", disk);
    printf("Type YES to confirm: ");
    char input[10];
    scanf("%9s", input);
    if (strcmp(input, "YES") != 0) {
        printf("Aborted.\n");
        exit(1);
    }
}

void encrypt_chunk(unsigned char *plaintext, unsigned char *ciphertext, int len, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, len);
    int tmplen;
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
}

void overwrite_random(const char *disk, int passes, size_t chunk_size) {
    int fd = open(disk, O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("Failed to open disk");
        exit(1);
    }

    unsigned char *buffer = malloc(chunk_size);
    unsigned char *cipher = malloc(chunk_size);
    if (!buffer || !cipher) {
        perror("Memory allocation failed");
        close(fd);
        exit(1);
    }

    for (int p = 0; p < passes; p++) {
        printf("Pass %d/%d...\n", p+1, passes);
        lseek(fd, 0, SEEK_SET);

        ssize_t read_bytes;
        while ((read_bytes = read(fd, buffer, chunk_size)) > 0) {
            // Generate random key and IV for encryption
            unsigned char key[32], iv[12];
            RAND_bytes(key, sizeof(key));
            RAND_bytes(iv, sizeof(iv));

            // Fill buffer with random data
            FILE *urandom = fopen("/dev/urandom", "rb");
            fread(buffer, 1, read_bytes, urandom);
            fclose(urandom);

            // Encrypt chunk
            encrypt_chunk(buffer, cipher, read_bytes, key, iv);

            // Write encrypted random data
            lseek(fd, -read_bytes, SEEK_CUR);
            if (write(fd, cipher, read_bytes) != read_bytes) {
                perror("Write failed");
                break;
            }

            // Wipe key from memory
            memset(key, 0, sizeof(key));
            memset(iv, 0, sizeof(iv));
        }
    }

    free(buffer);
    free(cipher);
    close(fd);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <disk> [passes] [chunk_size]\n", argv[0]);
        return 1;
    }

    const char *disk = argv[1];
    int passes = (argc > 2) ? atoi(argv[2]) : DEFAULT_PASSES;
    size_t chunk_size = (argc > 3) ? atol(argv[3]) : DEFAULT_CHUNK;

    confirm_target(disk);
    overwrite_random(disk, passes, chunk_size);

    printf("Secure erase complete.\n");
    return 0;
}
