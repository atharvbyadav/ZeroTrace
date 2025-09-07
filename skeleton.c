#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>

#define DEFAULT_CHUNK (1024*1024) // 1 MB
#define DEFAULT_PASSES 3
#define DEFAULT_THREADS 4

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
    printf("Usage: %s -d <disk> [-p <passes>] [-c <chunk_MB>] [-v] [--cert <file>]\n", prog);
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

// AES-256-GCM encryption (dummy here for random + encrypted pass)
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

// Multi-pass overwrite with threads, returns SHA256 hashes per pass
void overwrite_random_mt(const char *disk, int passes, size_t chunk_size, int threads, int verbose,
                         unsigned char **pass_hashes, size_t hash_size, off_t *disk_size_out){

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

        // Compute SHA256 hash of disk after this pass
        lseek(fd,0,SEEK_SET);
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

        unsigned char read_buf[1024*1024];
        ssize_t bytes;
        lseek(fd,0,SEEK_SET);
        while((bytes=read(fd,read_buf,sizeof(read_buf)))>0)
            EVP_DigestUpdate(mdctx,read_buf,bytes);

        unsigned int len;
        EVP_DigestFinal_ex(mdctx, pass_hashes[p], &len);
        EVP_MD_CTX_free(mdctx);
    }

    free(buffer);
    free(cipher);
    free(targs);
    free(tids);
    close(fd);
}

// Final zeroing pass to leave disk empty
void final_zero_disk(const char *disk, off_t disk_size, int verbose){
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
        if(verbose) printf("\rZeroing progress: %.2f%%", (total*100.0)/disk_size);
        fflush(stdout);
    }
    if(verbose) printf("\n");
    close(fd);
}

// Write certificate with metadata
void write_certificate(const char *disk, off_t disk_size, int passes, size_t chunk_size, int threads,
                       unsigned char **pass_hashes, const char *cert_path){

    FILE *f = fopen(cert_path,"w");
    if(!f){
        perror("Failed to write certificate");
        exit(1);
    }

    time_t now = time(NULL);
    char datetime[64];
    strftime(datetime,sizeof(datetime),"%Y-%m-%d %H:%M:%S",localtime(&now));

    fprintf(f,"=================== ZeroTrace Secure Erasure Certificate ===================\n\n");
    fprintf(f,"Disk: %s\n",disk);
    fprintf(f,"Disk Size: %ld bytes\n",disk_size);
    fprintf(f,"Date/Time: %s\n",datetime);
    fprintf(f,"ZeroTrace Version: v1.0\n");
    fprintf(f,"Number of passes: %d\n",passes);
    fprintf(f,"Chunk Size: %ld bytes\n",chunk_size);
    fprintf(f,"Threads Used: %d\n\n",threads);

    fprintf(f,"Hashes after each pass:\n");
    for(int i=0;i<passes;i++){
        fprintf(f,"Pass %d: ",i+1);
        for(int j=0;j<32;j++) fprintf(f,"%02x",pass_hashes[i][j]);
        fprintf(f,"\n");
    }

    fprintf(f,"\nVerification Sample (first 256 bytes of random sectors):\n");
    fprintf(f,"(Optional: include samples if verify enabled)\n");

    fprintf(f,"\n==============================================================================\n");
    fclose(f);
}

int main(int argc, char *argv[]){
    if(argc<3) usage(argv[0]);

    const char *disk=NULL;
    int passes=DEFAULT_PASSES;
    size_t chunk_size=DEFAULT_CHUNK;
    int verbose=0;
    const char *cert_path="zerotrace_certificate.txt";

    // Argument parsing
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"-d")==0 && i+1<argc) disk=argv[++i];
        else if(strcmp(argv[i],"-p")==0 && i+1<argc) passes=atoi(argv[++i]);
        else if(strcmp(argv[i],"-c")==0 && i+1<argc) chunk_size=atol(argv[++i])*1024*1024;
        else if(strcmp(argv[i],"-v")==0) verbose=1;
        else if(strcmp(argv[i],"--cert")==0 && i+1<argc) cert_path=argv[++i];
        else usage(argv[0]);
    }
    if(!disk) usage(argv[0]);

    confirm_target(disk);

    unsigned char **pass_hashes = malloc(sizeof(unsigned char*)*passes);
    for(int i=0;i<passes;i++)
        pass_hashes[i] = malloc(32);

    off_t disk_size;
    overwrite_random_mt(disk, passes, chunk_size, DEFAULT_THREADS, verbose, pass_hashes, 32, &disk_size);

    if(verbose) printf("Writing certificate...\n");
    write_certificate(disk,disk_size,passes,chunk_size,DEFAULT_THREADS,pass_hashes,cert_path);

    if(verbose) printf("Performing final zeroing to leave disk empty...\n");
    final_zero_disk(disk,disk_size,verbose);

    for(int i=0;i<passes;i++) free(pass_hashes[i]);
    free(pass_hashes);

    printf("Secure erase complete. Certificate saved at %s\n",cert_path);
    return 0;
}
