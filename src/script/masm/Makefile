# RawrXD-Script MASM Build Makefile
# For use with nmake or GNU make

# Tools
ML64 = ml64
LINK = link
LIB = lib

# Directories
BUILD_DIR = ../../../build/script
SRC_DIR = .

# Flags
ASMFLAGS = /c /nologo /Zi /Fo
LDFLAGS = /nologo
LIBFLAGS = /nologo

# Object files
OBJS = $(BUILD_DIR)/interpreter.obj $(BUILD_DIR)/runtime.obj

# Targets
all: dirs $(BUILD_DIR)/rawrxd-script.lib

dirs:
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)

$(BUILD_DIR)/interpreter.obj: $(SRC_DIR)/interpreter.asm
	$(ML64) $(ASMFLAGS)$@ $**

$(BUILD_DIR)/runtime.obj: $(SRC_DIR)/runtime.asm
	$(ML64) $(ASMFLAGS)$@ $**

$(BUILD_DIR)/rawrxd-script.lib: $(OBJS)
	$(LIB) $(LIBFLAGS) /out:$@ $(OBJS)

dll: $(OBJS)
	$(LINK) $(LDFLAGS) /dll /out:$(BUILD_DIR)/rawrxd-script.dll $(OBJS) kernel32.lib

clean:
	@if exist $(BUILD_DIR) rmdir /s /q $(BUILD_DIR)

.PHONY: all dirs clean dll
