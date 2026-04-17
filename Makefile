CC = gcc

CFLAGS = -Wall -Wextra -Werror -O2 -pthread
LIBS = -lcrypto -lpthread
STATIC_FLAGS = -static

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

-include engines/*/*.mk

all:
	$(CC) $(CFLAGS) $(SRC) -o zerotrace $(LIBS)

release:
	$(CC) $(CFLAGS) $(STATIC_FLAGS) $(SRC) -o zerotrace $(LIBS)
	strip zerotrace

debug:
	$(CC) -Wall -Wextra -O0 -g $(SRC) -o zerotrace $(LIBS)

clean:
	rm -f zerotrace
	rm -f zerotrace_cert.json
	rm -f signature.bin
	rm -f zt_priv.pem
	rm -f zt_pub.pem
