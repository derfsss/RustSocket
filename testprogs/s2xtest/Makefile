# Makefile - link s2xtest: the Rust staticlib and a small C entry point.
# No CRT, no clib4. Run inside Docker: walkero/amigagccondocker:os4-gcc15-3.6.1
# (tools/build-package.sh testprogs/s2xtest does both steps).

TARGET    = s2xtest
CC        = ppc-amigaos-gcc
SDK_INC   = /opt/ppc-amigaos/ppc-amigaos/SDK/include/include_h
CRATE     = ../../amigaos4

GLUE_OBJ  = build/glue.o
SYS_OBJ   = build/sys_glue.o
MEM_OBJ   = build/freestanding_mem.o
RUST_LIB  = target/powerpc-unknown-amigaos/release/libs2xtest.a

GIT_HASH ?= unknown

CFLAGS    = -O2 -Wall -D__AMIGAOS4__ -U__USE_INLINE__ -I$(SDK_INC) -DGIT_HASH=\"$(GIT_HASH)\" \
            -fno-tree-loop-distribute-patterns -ffunction-sections -fdata-sections
LDFLAGS   = -nostartfiles -nodefaultlibs -Wl,-z,noexecstack -Wl,--gc-sections
LIBS      = -lgcc

.PHONY: all clean

all: build $(TARGET)

build:
	mkdir -p build

$(GLUE_OBJ): src/glue.c
	$(CC) $(CFLAGS) -c $< -o $@

$(MEM_OBJ): $(CRATE)/glue/freestanding_mem.c
	$(CC) $(CFLAGS) -ffreestanding -fno-builtin -c $< -o $@

$(SYS_OBJ): $(CRATE)/glue/amiga_glue.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(GLUE_OBJ) $(SYS_OBJ) $(MEM_OBJ) $(RUST_LIB)
	$(CC) $(LDFLAGS) -o $@ $(GLUE_OBJ) $(SYS_OBJ) $(MEM_OBJ) $(RUST_LIB) $(LIBS)
	ppc-amigaos-strip $@

clean:
	rm -rf build $(TARGET)
