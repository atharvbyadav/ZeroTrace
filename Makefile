CC=gcc

CFLAGS=-Wall -Wextra -O2 -pthread

SRC=\
main.c \
core/context.c \
core/workflow.c \
device/device.c \
engines/registry.c \
engines/overwrite.c \
util/random.c \
cert/cert_json.c \
cert/sign_ed25519.c


# Auto-load plugins
-include engines/*/*.mk


all:
	$(CC) $(CFLAGS) $(SRC) -o zerotrace -lcrypto


clean:
	rm -f zerotrace
	rm -f zerotrace_cert.json
	rm -f signature.bin
	rm -f zt_priv.pem zt_pub.pem
