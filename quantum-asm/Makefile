# Makefile for MinGW Assembly Project
# Supports both 32-bit and 64-bit Windows targets

# Compilers
CC32 = i686-w64-mingw32-gcc
CC64 = x86_64-w64-mingw32-gcc
AS32 = i686-w64-mingw32-as
AS64 = x86_64-w64-mingw32-as

# Flags
CFLAGS = -O2 -Wall
ASFLAGS = 
LDFLAGS = -static

# Source files
ASM_SOURCES = quantum_mingw.s
C_SOURCES = test_main.c

# Object files
OBJ32 = $(ASM_SOURCES:.s=.32.o) $(C_SOURCES:.c=.32.o)
OBJ64 = $(ASM_SOURCES:.s=.64.o) $(C_SOURCES:.c=.64.o)

# Targets
TARGET32 = quantum_test32.exe
TARGET64 = quantum_test64.exe

# Default target
all: $(TARGET32) $(TARGET64)

# 32-bit target
$(TARGET32): $(OBJ32)
	$(CC32) $(LDFLAGS) -o $@ $^
	@echo "Built 32-bit executable: $@"

# 64-bit target
$(TARGET64): $(OBJ64)
	$(CC64) $(LDFLAGS) -o $@ $^
	@echo "Built 64-bit executable: $@"

# 32-bit assembly
%.32.o: %.s
	$(AS32) --defsym X86_32=1 $(ASFLAGS) -o $@ $<

# 64-bit assembly
%.64.o: %.s
	$(AS64) $(ASFLAGS) -o $@ $<

# 32-bit C
%.32.o: %.c
	$(CC32) $(CFLAGS) -c -o $@ $<

# 64-bit C
%.64.o: %.c
	$(CC64) $(CFLAGS) -c -o $@ $<

# Clean
clean:
	rm -f *.o *.32.o *.64.o $(TARGET32) $(TARGET64)

# Test (requires Wine)
test: all
	@echo "Testing 32-bit executable..."
	-wine $(TARGET32)
	@echo "\nTesting 64-bit executable..."
	-wine64 $(TARGET64)

.PHONY: all clean test