CC = gcc

# common compile flags
CFLAGS = -Wall -Wextra -O2 -pthread

# libraries required
LIBS = -lcrypto -lz -lzstd -lpthread -ldl

# static flags for release binary
STATIC_FLAGS = -static

# core sources
SRC = \
main.c \
core/context.c \
core/workflow.c \
device/device.c \
engines/registry.c \
engines/overwrite.c \
util/random.c \
cert/cert_json.c \
cert/sign_ed25519.c

# auto-load plugin engines (like IPAX)
-include engines/*/*.mk


# normal fast developer build
all:
        $(CC) $(CFLAGS) $(SRC) -o zerotrace -lcrypto -lpthread


# fully portable static release build
release:
        $(CC) $(CFLAGS) $(STATIC_FLAGS) $(SRC) -o zerotrace $(LIBS)
        strip zerotrace


# debug build
debug:
        $(CC) -Wall -Wextra -O0 -g $(SRC) -o zerotrace -lcrypto -lpthread


# cleanup generated files
clean:
        rm -f zerotrace
        rm -f zerotrace_cert.json
        rm -f signature.bin
        rm -f zt_priv.pem
        rm -f zt_pub.pem
