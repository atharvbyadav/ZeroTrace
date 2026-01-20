CC=gcc
CFLAGS=-Wall -Wextra -O2 -pthread
LIBS=-lcrypto

SRC=main.c \
    core/context.c \
    core/workflow.c \
    device/device.c \
    engines/registry.c \
    engines/overwrite.c \
    cert/cert_json.c \
    cert/sign_ed25519.c

OUT=zerotrace

all:
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) $(LIBS)

clean:
	rm -f $(OUT) signature.bin zt_priv.pem zt_pub.pem zerotrace_cert.json
