# Makefile — Link Rust staticlib + C glue into an AmigaOS 4 shared library
# No CRT, no clib4. Library mode: -nostartfiles -nodefaultlibs -lgcc
# Run inside Docker: walkero/amigagccondocker:os4-gcc15-3.6.1

# make DROPIN=1: the same library named bsdsocket.library (dropin/), to
# replace Roadshow's in LIBS:.
ifeq ($(DROPIN),1)
TARGET    = dropin/bsdsocket.library
NAMEDEF   = -DDROPIN
else
TARGET    = rustsocket.library
NAMEDEF   =
endif
CC        = ppc-amigaos-gcc

# SDK include paths
SDK_INC   = /opt/ppc-amigaos/ppc-amigaos/SDK/include/include_h

# C glue sources
LIB_GLUE_SRC    = src/library_glue.c
VEC_SRC         = src/vectors.c
VEC_OBJ         = build/vectors.o
VEC68K_SRC      = src/vectors68k.c
VEC68K_OBJ      = build/vectors68k.o
SYS_GLUE_SRC    = ../amigaos4/glue/amiga_glue.c
MEM_GLUE_SRC    = ../amigaos4/glue/freestanding_mem.c

# C glue objects
LIB_GLUE_OBJ    = build/library_glue.o
SYS_GLUE_OBJ    = build/sys_glue.o
MEM_GLUE_OBJ    = build/freestanding_mem.o

# Rust output (staticlib built on host)
RUST_LIB  = target/powerpc-unknown-amigaos/release/librustsocket.a

# Compiler flags
CFLAGS    = -O2 -Wall $(NAMEDEF) -D__AMIGAOS4__ -U__USE_INLINE__ -I$(SDK_INC) \
            -fno-tree-loop-distribute-patterns -ffunction-sections -fdata-sections

# Linker flags — library mode
# --undefined=RomTag forces the Resident struct to be retained as a GC root
# (otherwise --gc-sections drops it — nothing statically references the RomTag,
# AmigaOS finds it by scanning memory for RTC_MATCHWORD).
LDFLAGS   = -nostartfiles -nodefaultlibs -Wl,-z,noexecstack -Wl,--gc-sections -Wl,--undefined=RomTag
LIBS      = -lgcc

.PHONY: all clean

all: build $(TARGET)

build:
	mkdir -p build dropin

$(LIB_GLUE_OBJ): $(LIB_GLUE_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(MEM_GLUE_OBJ): $(MEM_GLUE_SRC)
	$(CC) $(CFLAGS) -ffreestanding -fno-builtin -c $< -o $@

$(SYS_GLUE_OBJ): $(SYS_GLUE_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# va_getlinearva passes &va_list to a builtin whose declared type gcc 15
# rejects by default; the SDK's own pattern, so only a warning here.
$(VEC_OBJ): $(VEC_SRC)
	$(CC) $(CFLAGS) -Wno-error=incompatible-pointer-types -Wno-incompatible-pointer-types -c $< -o $@

$(VEC68K_OBJ): $(VEC68K_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(VEC_OBJ) $(VEC68K_OBJ) $(LIB_GLUE_OBJ) $(SYS_GLUE_OBJ) $(MEM_GLUE_OBJ) $(RUST_LIB)
	$(CC) $(LDFLAGS) -o $@ $(VEC_OBJ) $(VEC68K_OBJ) $(LIB_GLUE_OBJ) $(SYS_GLUE_OBJ) $(MEM_GLUE_OBJ) $(RUST_LIB) $(LIBS)
	cp $@ $@.debug
	ppc-amigaos-strip $@

clean:
	rm -rf build $(TARGET)
