# libpurecrypt: freestanding SHA-512 + $6$ password hashing for PureC OS.
#
# Two build modes:
#   make            cross-compile freestanding static lib (for OS/userspace)
#   make test       host-compile + run tests (needs system cc + -lcrypt)
#   make clean      remove build artifacts

CROSS ?= x86_64-elf-
CC := $(CROSS)gcc
AR := $(CROSS)ar

CFLAGS := -std=c11 -Wall -Wextra -Werror -O2 -ffreestanding \
	-fno-stack-protector -fno-pic -m64 -mno-red-zone -Iinclude

HOST_CC ?= gcc
HOST_CFLAGS := -std=c11 -Wall -Wextra -O2 -Iinclude -D_GNU_SOURCE

BUILD := build
LIB := $(BUILD)/libpurecrypt.a
OBJS := $(BUILD)/sha512.o $(BUILD)/crypt_sha512.o

.PHONY: all test clean

all: $(LIB)

$(LIB): $(OBJS)
	@mkdir -p $(@D)
	$(AR) rcs $@ $^

$(BUILD)/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Host tests link the same sources with the native compiler.
test: $(BUILD)/test_sha512 $(BUILD)/test_crypt
	./$(BUILD)/test_sha512
	./$(BUILD)/test_crypt

$(BUILD)/test_sha512: test/test_sha512.c src/sha512.c
	@mkdir -p $(@D)
	$(HOST_CC) $(HOST_CFLAGS) $^ -o $@

$(BUILD)/test_crypt: test/test_crypt.c src/sha512.c src/crypt_sha512.c
	@mkdir -p $(@D)
	$(HOST_CC) $(HOST_CFLAGS) $^ -lcrypt -o $@

clean:
	rm -rf $(BUILD)
