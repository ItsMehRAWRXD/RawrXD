# Makefile for Secure IDE Assembly Implementation
# Compiles with NASM for x86-64 Linux

# Compiler and flags
NASM = nasm
LD = ld
CFLAGS = -f elf64
LDFLAGS = -m elf_x86_64

# Target executable
TARGET = secure-ide

# Source files
SOURCES = main.asm ai_engine.asm security.asm
OBJECTS = $(SOURCES:.asm=.o)

# Default target
all: $(TARGET)

# Build the main executable
$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJECTS)

# Compile assembly files to object files
%.o: %.asm
	$(NASM) $(CFLAGS) -o $@ $<

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET)

# Install dependencies (NASM)
install-deps:
	@echo "Installing NASM..."
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update && sudo apt-get install -y nasm; \
	elif command -v yum >/dev/null 2>&1; then \
		sudo yum install -y nasm; \
	elif command -v brew >/dev/null 2>&1; then \
		brew install nasm; \
	else \
		echo "Please install NASM manually for your system"; \
	fi

# Run the secure IDE
run: $(TARGET)
	./$(TARGET)

# Debug build
debug: CFLAGS += -g
debug: $(TARGET)

# Optimized build
optimize: CFLAGS += -O2
optimize: $(TARGET)

# Static build
static: LDFLAGS += -static
static: $(TARGET)

# Check syntax
check:
	@echo "Checking assembly syntax..."
	@for file in $(SOURCES); do \
		echo "Checking $$file..."; \
		$(NASM) -f elf64 -o /dev/null $$file; \
	done

# Format code (basic formatting)
format:
	@echo "Formatting assembly code..."
	@for file in $(SOURCES); do \
		echo "Formatting $$file..."; \
		# Basic formatting - remove extra whitespace
		sed -i 's/[[:space:]]*$$//' $$file; \
	done

# Create distribution package
dist: clean $(TARGET)
	@echo "Creating distribution package..."
	mkdir -p dist/secure-ide-asm
	cp $(TARGET) dist/secure-ide-asm/
	cp README.md dist/secure-ide-asm/
	cp Makefile dist/secure-ide-asm/
	cp *.asm dist/secure-ide-asm/
	tar -czf secure-ide-asm.tar.gz -C dist secure-ide-asm
	rm -rf dist

# Help target
help:
	@echo "Secure IDE Assembly Makefile"
	@echo "Available targets:"
	@echo "  all          - Build the secure IDE (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  install-deps - Install NASM dependency"
	@echo "  run          - Build and run the secure IDE"
	@echo "  debug        - Build with debug symbols"
	@echo "  optimize     - Build with optimizations"
	@echo "  static       - Build static executable"
	@echo "  check        - Check assembly syntax"
	@echo "  format       - Format assembly code"
	@echo "  dist         - Create distribution package"
	@echo "  help         - Show this help message"

# Phony targets
.PHONY: all clean install-deps run debug optimize static check format dist help

# Dependencies
main.o: main.asm
ai_engine.o: ai_engine.asm
security.o: security.asm
