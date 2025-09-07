#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#define CHUNK_SIZE 1048576 // 1 MB

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

void overwrite_random(const char *disk, int passes) {
    int fd = open(disk, O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("Failed to open disk");
        exit(1);
    }

    unsigned char *buffer = malloc(CHUNK_SIZE);
    if (!buffer) {
        perror("Memory allocation failed");
        close(fd);
        exit(1);
    }

    for (int p = 0; p < passes; p++) {
        printf("Pass %d/%d...\n", p + 1, passes);
        lseek(fd, 0, SEEK_SET);
        ssize_t written;
        while ((written = read(fd, buffer, CHUNK_SIZE)) > 0) {
            // Generate random data
            FILE *urandom = fopen("/dev/urandom", "rb");
            fread(buffer, 1, CHUNK_SIZE, urandom);
            fclose(urandom);

            lseek(fd, -written, SEEK_CUR);
            if (write(fd, buffer, written) != written) {
                perror("Write failed");
                break;
            }
        }
    }

    free(buffer);
    close(fd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <disk>\n", argv[0]);
        return 1;
    }

    confirm_target(argv[1]);
    overwrite_random(argv[1], 3); // default 3 passes

    printf("Erase complete.\n");
    return 0;
}
