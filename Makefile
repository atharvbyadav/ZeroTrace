CC=gcc
CFLAGS=-Wall -Wextra -O2 -pthread

SRC=main.c \
    core/context.c \
    core/workflow.c \
    device/device.c \
    engines/registry.c \
    engines/overwrite.c

OUT=zerotrace

all:
	$(CC) $(CFLAGS) $(SRC) -o $(OUT)

clean:
	rm -f $(OUT)
