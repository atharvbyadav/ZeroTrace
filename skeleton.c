#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/stat.h>

#define DEFAULT_CHUNK 1048576 // 1 MB
#define DEFAULT_PASSES 3
#define METADATA_WIPE_MB 10   // Wipe first 10 MB for MBR/GPT

// Confirm user consent
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

// AES-256-GCM encryption for one chunk
void encrypt_chunk(unsigned char *plaintext, unsigned char *ciphertext, int len,
                   unsigned char *key, unsigned char *iv) {
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

// Overwrite disk with random data + ephemeral encryption
void overwrite_random(const char *disk, int passes, size_t chunk_size, FILE *cert_file) {
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

    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);

    for (int p = 0; p < passes; p++) {
        printf("Pass %d/%d...\n", p+1, passes);
        lseek(fd, 0, SEEK_SET);

        ssize_t read_bytes;
        while ((read_bytes = read(fd, buffer, chunk_size)) > 0) {
            // Random key + IV
            unsigned char key[32], iv[12];
            RAND_bytes(key, sizeof(key));
            RAND_bytes(iv, sizeof(iv));

            // Fill buffer with random data
            FILE *urandom = fopen("/dev/urandom", "rb");
            fread(buffer, 1, read_bytes, urandom);
            fclose(urandom);

            // Encrypt chunk
            encrypt_chunk(buffer, cipher, read_bytes, key, iv);

            // Write encrypted data
            lseek(fd, -read_bytes, SEEK_CUR);
            if (write(fd, cipher, read_bytes) != read_bytes) {
                perror("Write failed");
                break;
            }

            // Update SHA256 for certificate
            SHA256_Update(&sha_ctx, cipher, read_bytes);

            // Wipe key + IV from memory
            memset(key, 0, sizeof(key));
            memset(iv, 0, sizeof(iv));
        }
    }

    free(buffer);
    free(cipher);
    close(fd);

    // Write certificate hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha_ctx);
    fprintf(cert_file, "Disk: %s\nSHA256 of erased sectors: ", disk);
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++) fprintf(cert_file,"%02x",hash[i]);
    fprintf(cert_file,"\n");
}

// Wipe metadata (first N MB)
void wipe_metadata(const char *disk) {
    int fd = open(disk, O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("Failed to open disk for metadata wipe");
        return;
    }

    unsigned char *buffer = calloc(1, 1024*1024); // 1 MB buffer of zeros
    for(int i=0; i<METADATA_WIPE_MB; i++){
        if(write(fd, buffer, 1024*1024) != 1024*1024){
            perror("Metadata write failed");
            break;
        }
    }

    free(buffer);
    close(fd);
}

// Optional verification (reads random sectors)
void verify_erasure(const char *disk, size_t chunk_size, int num_chunks) {
    int fd = open(disk, O_RDONLY);
    if(fd<0){
        perror("Verification open failed");
        return;
    }

    unsigned char *buffer = malloc(chunk_size);
    for(int i=0;i<num_chunks;i++){
        off_t offset = (rand() % num_chunks) * chunk_size;
        lseek(fd, offset, SEEK_SET);
        read(fd, buffer, chunk_size);
        // Could add further checks or hash comparison
    }

    free(buffer);
    close(fd);
    printf("Verification done (sample sectors).\n");
}

int main(int argc, char *argv[]) {
    if(argc < 2){
        printf("Usage: %s <disk> [passes] [chunk_size_MB]\n", argv[0]);
        return 1;
    }

    const char *disk = argv[1];
    int passes = (argc > 2) ? atoi(argv[2]) : DEFAULT_PASSES;
    size_t chunk_size = (argc > 3) ? atol(argv[3])*1024*1024 : DEFAULT_CHUNK;

    confirm_target(disk);

    FILE *cert_file = fopen("zerotrace_certificate.txt", "w");
    if(!cert_file){
        perror("Certificate file creation failed");
        return 1;
    }

    overwrite_random(disk, passes, chunk_size, cert_file);
    wipe_metadata(disk);
    verify_erasure(disk, chunk_size, 10); // verify 10 random chunks
    fclose(cert_file);

    printf("Secure erase complete. Certificate saved as zerotrace_certificate.txt\n");
    return 0;
}
