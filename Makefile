# Makefile for the external kernel module

# Set the name of your module
MODULE_NAME := netkit

# Set the list of source files
SRC_FILES := src/auth.c src/command.c src/device.c src/mem.c src/mutex.c src/netkit.c src/packet.c src/server.c

# Set the list of header files
HEADER_FILES := $(wildcard *.h)

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
