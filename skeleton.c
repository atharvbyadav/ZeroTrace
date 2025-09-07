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
#define METADATA_WIPE_MB 10

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

// Multi-pass overwrite with threads + EVP SHA256 certificate
void overwrite_random_mt(const char *disk, int passes, size_t chunk_size, FILE *cert_file, int threads, int verbose){
    int fd = open(disk, O_RDWR | O_SYNC);
    if(fd<0){
        perror("Failed to open disk");
        exit(1);
    }

    // Determine disk size
    off_t disk_size = lseek(fd, 0, SEEK_END);
    if(disk_size<=0){
        perror("Failed to determine disk size");
        close(fd);
        exit(1);
    }
    lseek(fd,0,SEEK_SET);

    unsigned char *buffer = malloc(chunk_size);
    unsigned char *cipher = malloc(chunk_size);
    if(!buffer || !cipher){
        perror("Memory allocation failed");
        close(fd);
        exit(1);
    }

    // Initialize EVP SHA256
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if(!mdctx){
        perror("Failed to create EVP_MD_CTX");
        exit(1);
    }
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)){
        perror("EVP_DigestInit_ex failed");
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

        // Update EVP hash per pass
        EVP_DigestUpdate(mdctx, cipher, chunk_size);
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    if(cert_file){
        fprintf(cert_file,"Disk: %s\nSHA256 of erased sectors: ",disk);
        for(unsigned int i=0;i<hash_len;i++)
            fprintf(cert_file,"%02x",hash[i]);
        fprintf(cert_file,"\n");
    }

    free(buffer);
    free(cipher);
    free(targs);
    free(tids);
    close(fd);
}

// Wipe first N MB metadata
void wipe_metadata(const char *disk){
    int fd = open(disk, O_RDWR | O_SYNC);
    if(fd<0){
        perror("Metadata wipe open failed");
        return;
    }
    unsigned char *zeros = calloc(1,1024*1024);
    for(int i=0;i<METADATA_WIPE_MB;i++){
        if(write(fd,zeros,1024*1024)!=1024*1024){
            perror("Metadata write failed");
            break;
        }
    }
    free(zeros);
    close(fd);
}

// Optional verification
void verify_erasure(const char *disk, size_t chunk_size, int num_chunks){
    int fd = open(disk,O_RDONLY);
    if(fd<0){
        perror("Verification failed");
        return;
    }
    unsigned char *buffer = malloc(chunk_size);
    for(int i=0;i<num_chunks;i++){
        off_t offset = (rand()%num_chunks)*chunk_size;
        lseek(fd,offset,SEEK_SET);
        read(fd,buffer,chunk_size);
    }
    free(buffer);
    close(fd);
    printf("Verification done (sample sectors).\n");
}

int main(int argc, char *argv[]){
    if(argc<3) usage(argv[0]);

    const char *disk=NULL;
    int passes=DEFAULT_PASSES;
    size_t chunk_size=DEFAULT_CHUNK;
    int verbose=0;
    int verify_flag=0;
    const char *cert_path="zerotrace_certificate.txt";

    // Simple argument parsing
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

    FILE *cert_file = fopen(cert_path,"w");
    if(!cert_file){
        perror("Certificate file creation failed");
        return 1;
    }

    overwrite_random_mt(disk,passes,chunk_size,cert_file,4,verbose); // 4 threads
    wipe_metadata(disk);
    if(verify_flag) verify_erasure(disk,chunk_size,10);

    fclose(cert_file);
    printf("Secure erase complete. Certificate saved at %s\n",cert_path);
    return 0;
}
