# Oracle runtime: hook DLL for rct.exe (32-bit Windows, built with mingw-w64).
# The DLL is named dinput.dll: it stands in for DirectInput, which rct.exe imports.
CC = i686-w64-mingw32-gcc
CFLAGS = -O2 -Wall -Wextra -Wno-cast-function-type -std=gnu11
OUT ?= ../out/oracle-bin

all: $(OUT)/dinput.dll

$(OUT)/dinput.dll: rcthook.c spike.c spike.h callasm.S trace.h dinput.def | $(OUT)
	$(CC) $(CFLAGS) -shared -o $@ rcthook.c spike.c callasm.S dinput.def -lwinmm -lgdi32 -static-libgcc -Wl,--enable-stdcall-fixup -Wl,--no-insert-timestamp

$(OUT):
	mkdir -p $@

clean:
	rm -rf $(OUT)
.PHONY: all clean
