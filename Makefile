CROSS ?= x86_64-elf-
CC := $(CROSS)gcc
AR := $(CROSS)ar
LD := $(CROSS)ld

CFLAGS := -std=c11 -Wall -Wextra -Werror -O2 -ffreestanding \
	-fno-stack-protector -fno-pic -m64 -mno-red-zone -Iinclude
MOD_CFLAGS := -std=c11 -Wall -Wextra -Werror -O2 -ffreestanding \
	-fno-stack-protector -fno-pic -m64 -mno-red-zone \
	-mcmodel=kernel -mgeneral-regs-only -Iinclude

HOST_CC ?= gcc
HOST_CFLAGS := -std=c11 -Wall -Wextra -O2 -Iinclude -D_GNU_SOURCE

BUILD := build
BIN_DIR ?= $(CURDIR)/build
MODULE_DIR := $(BIN_DIR)/modules
LIB := $(BUILD)/libpurecrypt.a
OBJS := $(BUILD)/sha512.o $(BUILD)/crypt_sha512.o
MOD_OBJS := $(BUILD)/sha512.k.o $(BUILD)/crypt_sha512.k.o
MOD_ELF := $(MODULE_DIR)/crypt.elf
MOD_KO := $(MODULE_DIR)/crypt.ko

.PHONY: all module test clean

all: $(LIB)

module: $(MOD_ELF) $(MOD_KO)

$(LIB): $(OBJS)
	@mkdir -p $(@D)
	$(AR) rcs $@ $^

$(BUILD)/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.k.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(MOD_CFLAGS) -MMD -MP -c $< -o $@

$(MOD_ELF): $(MOD_OBJS)
	@mkdir -p $(@D)
	$(LD) -r -o $@ $^
	@echo "crypt module -> $@"

$(MOD_KO): $(MOD_ELF)
	@cp $< $@
	@echo "crypt module -> $@"

-include $(MOD_OBJS:.o=.d)

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
