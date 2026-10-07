# Oracle runtime: hook DLL for rct.exe (32-bit Windows, built with mingw-w64).
# The DLL is named dinput.dll: it stands in for DirectInput, which rct.exe imports.
CC = i686-w64-mingw32-gcc
CFLAGS = -O2 -Wall -Wextra -Wno-cast-function-type -std=gnu11
OUT ?= ../out/oracle-bin

all: $(OUT)/dinput.dll

SRC = rcthook.c spike.c apitrace.c callasm.S apitrace_asm.S
DEPS = $(SRC) spike.h trace.h mask.h dinput.def apisig.txt Makefile
# build identity: the first 64 bits of the SHA-256 of every oracle source (TR_BUILD, hook.log)
BUILD_ID := $(shell cat $(DEPS) | sha256sum | cut -c1-16)
$(OUT)/dinput.dll: $(DEPS) | $(OUT)
	$(CC) $(CFLAGS) -DORACLE_BUILD_ID=0x$(BUILD_ID)ULL -shared -o $@ $(SRC) dinput.def -lwinmm -lgdi32 -static-libgcc -Wl,--enable-stdcall-fixup -Wl,--no-insert-timestamp

$(OUT):
	mkdir -p $@

clean:
	rm -rf $(OUT)
.PHONY: all clean
