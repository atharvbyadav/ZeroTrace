#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>

#define DEFAULT_CHUNK (1024*1024) // 1 MB
#define DEFAULT_PASSES 3

typedef struct {
    int fd;
    unsigned char *buffer;
    unsigned char *cipher;
    size_t chunk_size;
    size_t start_offset;
    size_t end_offset;
} thread_arg_t;

// Display usage
void usage(char *prog) {
    printf("ZeroTrace - Secure Disk Eraser\n");
    printf("Usage: %s -d <disk> [-p <passes>] [-c <chunk_MB>] [-v] [--verify] [--cert <file>]\n", prog);
    exit(1);
}

// Confirm dangerous operation
void confirm_target(const char *disk){
    printf("WARNING: All data on %s will be permanently erased!\n", disk);
    printf("Type YES to confirm: ");
    char input[10];
    scanf("%9s", input);
    if(strcmp(input,"YES")!=0){
        printf("Aborted.\n");
        exit(1);
    }
}

// AES-256-GCM encryption
void encrypt_chunk(unsigned char *plaintext, unsigned char *ciphertext, int len,
                   unsigned char *key, unsigned char *iv){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, len);
    int tmplen;
    EVP_EncryptFinal_ex(ctx, ciphertext+outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
}

// Overwrite a disk chunk (threaded)
void *thread_write(void *arg){
    thread_arg_t *targ = (thread_arg_t*)arg;
    size_t offset = targ->start_offset;
    while(offset < targ->end_offset){
        size_t write_size = targ->chunk_size;
        if(offset + write_size > targ->end_offset)
            write_size = targ->end_offset - offset;

        unsigned char key[32], iv[12];
        RAND_bytes(key, sizeof(key));
        RAND_bytes(iv, sizeof(iv));

        FILE *urandom = fopen("/dev/urandom","rb");
        fread(targ->buffer,1,write_size,urandom);
        fclose(urandom);

        encrypt_chunk(targ->buffer, targ->cipher, write_size, key, iv);

        lseek(targ->fd, offset, SEEK_SET);
        if(write(targ->fd, targ->cipher, write_size) != write_size){
            perror("Thread write failed");
            break;
        }

        memset(key,0,sizeof(key));
        memset(iv,0,sizeof(iv));

        offset += write_size;
    }
    return NULL;
}

// Multi-pass overwrite with threads
void overwrite_random_mt(const char *disk, int passes, size_t chunk_size, int threads, int verbose, off_t *disk_size_out){
    int fd = open(disk, O_RDWR | O_SYNC);
    if(fd<0){
        perror("Failed to open disk");
        exit(1);
    }

    off_t disk_size = lseek(fd,0,SEEK_END);
    if(disk_size<=0){
        perror("Failed to determine disk size");
        close(fd);
        exit(1);
    }
    lseek(fd,0,SEEK_SET);

    *disk_size_out = disk_size;

    unsigned char *buffer = malloc(chunk_size);
    unsigned char *cipher = malloc(chunk_size);
    if(!buffer || !cipher){
        perror("Memory allocation failed");
        close(fd);
        exit(1);
    }

    size_t chunk_per_thread = disk_size/threads;
    pthread_t *tids = malloc(sizeof(pthread_t)*threads);
    thread_arg_t *targs = malloc(sizeof(thread_arg_t)*threads);

    for(int p=0;p<passes;p++){
        if(verbose) printf("Pass %d/%d...\n",p+1,passes);

        for(int t=0;t<threads;t++){
            targs[t].fd = fd;
            targs[t].buffer = buffer;
            targs[t].cipher = cipher;
            targs[t].chunk_size = chunk_size;
            targs[t].start_offset = t*chunk_per_thread;
            targs[t].end_offset = (t==threads-1)?disk_size:(t+1)*chunk_per_thread;
            pthread_create(&tids[t],NULL,thread_write,&targs[t]);
        }
        for(int t=0;t<threads;t++) pthread_join(tids[t],NULL);
    }

    free(buffer);
    free(cipher);
    free(targs);
    free(tids);
    close(fd);
}

// Compute full-disk SHA-256 certificate
void compute_sha256_certificate(const char *disk, const char *cert_path){
    int fd = open(disk,O_RDONLY);
    if(fd<0){
        perror("Failed to open disk for certificate");
        exit(1);
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    unsigned char buf[1024*1024];
    ssize_t bytes;
    while((bytes = read(fd,buf,sizeof(buf))) > 0){
        EVP_DigestUpdate(mdctx, buf, bytes);
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    close(fd);

    FILE *cert_file = fopen(cert_path,"w");
    if(!cert_file){
        perror("Certificate file creation failed");
        exit(1);
    }
    fprintf(cert_file,"Disk: %s\nSHA256 of erased sectors: ",disk);
    for(unsigned int i=0;i<hash_len;i++)
        fprintf(cert_file,"%02x",hash[i]);
    fprintf(cert_file,"\n");
    fclose(cert_file);
}

// Final zeroing pass to leave disk empty
void final_zero_disk(const char *disk, off_t disk_size){
    int fd = open(disk,O_RDWR | O_SYNC);
    if(fd<0){
        perror("Final zeroing failed");
        return;
    }

    unsigned char buf[1024*1024];
    memset(buf,0,sizeof(buf));
    off_t total=0;
    while(total<disk_size){
        ssize_t write_bytes = (disk_size - total > sizeof(buf)) ? sizeof(buf) : disk_size - total;
        if(write(fd, buf, write_bytes) != write_bytes){
            perror("Final zeroing write failed");
            break;
        }
        total += write_bytes;
    }
    close(fd);
}

int main(int argc, char *argv[]){
    if(argc<3) usage(argv[0]);

    const char *disk=NULL;
    int passes=DEFAULT_PASSES;
    size_t chunk_size=DEFAULT_CHUNK;
    int verbose=0;
    int verify_flag=0;
    const char *cert_path="zerotrace_certificate.txt";

    // Argument parsing
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"-d")==0 && i+1<argc) disk=argv[++i];
        else if(strcmp(argv[i],"-p")==0 && i+1<argc) passes=atoi(argv[++i]);
        else if(strcmp(argv[i],"-c")==0 && i+1<argc) chunk_size=atol(argv[++i])*1024*1024;
        else if(strcmp(argv[i],"-v")==0) verbose=1;
        else if(strcmp(argv[i],"--verify")==0) verify_flag=1;
        else if(strcmp(argv[i],"--cert")==0 && i+1<argc) cert_path=argv[++i];
        else usage(argv[0]);
    }
    if(!disk) usage(argv[0]);

    confirm_target(disk);

    off_t disk_size;
    overwrite_random_mt(disk, passes, chunk_size, 4, verbose, &disk_size); // 4 threads

    if(verbose) printf("Computing SHA-256 certificate...\n");
    compute_sha256_certificate(disk, cert_path);

    if(verbose) printf("Performing final zeroing to leave disk empty...\n");
    final_zero_disk(disk, disk_size);

    if(verify_flag) printf("Verification requested: sample sectors not implemented in final zeroing version.\n");

    printf("Secure erase complete. Certificate saved at %s\n",cert_path);
    return 0;
}
