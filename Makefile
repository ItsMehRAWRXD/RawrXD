# Quantum MASM System 2035 - MinGW Makefile
# Compatible with MinGW-w64 and MSYS2

# Compiler settings
CXX = g++
CXXFLAGS = -O3 -std=c++11 -Wall -Wextra -static-libgcc -static-libstdc++

# Targets
TARGETS = shellcode_generator.exe data_converter.exe

# Default target
all: $(TARGETS)
	@echo "================================================================"
	@echo "QUANTUM MASM SYSTEM 2035 - MinGW BUILD COMPLETE"
	@echo "================================================================"
	@echo "Built targets: $(TARGETS)"
	@echo "Compatible with MinGW-w64, MSYS2, and TDM-GCC"
	@echo "================================================================"

# Individual targets
shellcode_generator.exe: shellcode_generator.cpp
	@echo "Building shellcode generator..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✓ Shellcode generator built successfully"

data_converter.exe: data_converter.cpp
	@echo "Building data converter..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✓ Data converter built successfully"

# Test target
test: $(TARGETS)
	@echo "Running tests..."
	@echo "Generating test shellcode..."
	./shellcode_generator.exe
	@if [ -f test_shellcode.bin ]; then \
		echo "✓ Test shellcode generated successfully"; \
		ls -la test_shellcode.bin; \
	else \
		echo "✗ Test shellcode generation failed"; \
	fi
	@echo "Testing data converter..."
	./data_converter.exe

# Clean target
clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(TARGETS) *.o *.obj test_shellcode.bin
	@echo "✓ Clean complete"

# Install target (copies to system directory)
install: $(TARGETS)
	@echo "Installing to /usr/local/bin..."
	@cp $(TARGETS) /usr/local/bin/
	@echo "✓ Installation complete"

# Debug target (builds with debug symbols)
debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGETS)
	@echo "Debug build complete"

# Help target
help:
	@echo "Quantum MASM System 2035 - MinGW Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all        - Build all C++ components (default)"
	@echo "  test       - Build and run tests"
	@echo "  clean      - Remove build artifacts"
	@echo "  debug      - Build with debug symbols"
	@echo "  install    - Install to system directory"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - MinGW-w64 or MSYS2 with g++"
	@echo "  - C++11 compatible compiler"
	@echo ""
	@echo "Usage examples:"
	@echo "  make               # Build all"
	@echo "  make test          # Build and test"
	@echo "  make clean all     # Clean and rebuild"

.PHONY: all test clean install debug help