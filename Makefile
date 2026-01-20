CC=gcc
CFLAGS=-Wall -Wextra -O2

SRC=main.c \
    core/context.c \
    core/workflow.c \
    device/device.c

OUT=zerotrace

all:
	$(CC) $(CFLAGS) $(SRC) -o $(OUT)

clean:
	rm -f $(OUT)
