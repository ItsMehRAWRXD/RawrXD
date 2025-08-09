# Makefile for MinGW Assembly Project using NASM
# Supports both 32-bit and 64-bit Windows targets

# Compilers and assembler
CC32 = i686-w64-mingw32-gcc
CC64 = x86_64-w64-mingw32-gcc
NASM = nasm

# Flags
CFLAGS = -O2 -Wall
NASM32FLAGS = -f win32
NASM64FLAGS = -f win64 -DWIN64
LDFLAGS = -static

# Source files
ASM_SOURCES = quantum_nasm.asm
C_SOURCES = test_main.c

# Object files
OBJ32 = $(ASM_SOURCES:.asm=.32.obj) $(C_SOURCES:.c=.32.o)
OBJ64 = $(ASM_SOURCES:.asm=.64.obj) $(C_SOURCES:.c=.64.o)

# Targets
TARGET32 = quantum_nasm32.exe
TARGET64 = quantum_nasm64.exe

# Default target
all: $(TARGET32) $(TARGET64)

# 32-bit target
$(TARGET32): $(OBJ32)
	$(CC32) $(LDFLAGS) -o $@ $^
	@echo "Built 32-bit NASM executable: $@"

# 64-bit target
$(TARGET64): $(OBJ64)
	$(CC64) $(LDFLAGS) -o $@ $^
	@echo "Built 64-bit NASM executable: $@"

# 32-bit NASM assembly
%.32.obj: %.asm
	$(NASM) $(NASM32FLAGS) -o $@ $<

# 64-bit NASM assembly
%.64.obj: %.asm
	$(NASM) $(NASM64FLAGS) -o $@ $<

# 32-bit C
%.32.o: %.c
	$(CC32) $(CFLAGS) -c -o $@ $<

# 64-bit C
%.64.o: %.c
	$(CC64) $(CFLAGS) -c -o $@ $<

# Clean
clean:
	rm -f *.o *.obj *.32.o *.64.o *.32.obj *.64.obj $(TARGET32) $(TARGET64)

# Test
test: all
	@echo "Testing 32-bit NASM executable..."
	-wine $(TARGET32)
	@echo "\nTesting 64-bit NASM executable..."
	-wine64 $(TARGET64)

.PHONY: all clean test