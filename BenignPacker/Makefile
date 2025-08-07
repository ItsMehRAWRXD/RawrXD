# BenignPacker Makefile
# Advanced PE Packer with Encryption Features

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra
LDFLAGS = -static-libgcc -static-libstdc++

# Windows-specific flags (for cross-compilation if needed)
WINFLAGS = -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0601
WINLIBS = -lole32 -lcrypt32 -lwininet -lwintrust -limagehlp -lcomctl32 -lshell32 -ladvapi32 -lgdi32 -luser32 -lkernel32

# Detect if we're on Windows or cross-compiling
ifeq ($(OS),Windows_NT)
    WINFLAGS += -mwindows
    TARGET = BenignPacker.exe
else
    # On Linux, we'll create a Linux version for testing
    TARGET = BenignPacker
    WINLIBS =  # No Windows libraries on Linux
endif

# Source files
MAIN_SOURCE = VS2022_GUI_Benign_Packer.cpp
HEADERS = tiny_loader.h cross_platform_encryption.h enhanced_loader_utils.h enhanced_encryption_system.h ultimate_encryption_integration.h

# Output binary (set by OS detection above)

# Default target
all: $(TARGET)

# Main compilation
$(TARGET): $(MAIN_SOURCE) $(HEADERS)
	@echo "🔨 Compiling BenignPacker with advanced encryption features..."
	$(CXX) $(CXXFLAGS) $(WINFLAGS) -o $(TARGET) $(MAIN_SOURCE) $(WINLIBS) $(LDFLAGS)
	@echo "✅ Compilation successful! Binary: $(TARGET)"

# Test compilation
test: test_encryption_integration linux_test test_unique_stub
	@echo "🧪 Running encryption tests..."
	./test_encryption_integration
	./test_unique_stub

test_encryption_integration: test_encryption_integration.cpp ultimate_encryption_integration.h
	@echo "🔨 Compiling encryption test..."
	$(CXX) $(CXXFLAGS) -o test_encryption_integration test_encryption_integration.cpp

linux_test: BenignPacker_Linux_Test.cpp ultimate_encryption_integration.h
	@echo "🔨 Compiling Linux test version..."
	$(CXX) $(CXXFLAGS) -o BenignPacker_Linux_Test BenignPacker_Linux_Test.cpp

test_pe_generation: test_pe_generation.cpp tiny_loader.h
	@echo "🔨 Compiling PE generation test..."
	$(CXX) $(CXXFLAGS) -o test_pe_generation test_pe_generation.cpp

test_unique_stub: test_unique_stub.cpp uniquestub.h
	@echo "🔨 Compiling unique stub test..."
	$(CXX) $(CXXFLAGS) -o test_unique_stub test_unique_stub.cpp

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -f $(TARGET) test_encryption_integration test_pe_generation test_unique_stub *.exe *.o core
	@echo "✅ Clean complete!"

# Install dependencies (for Linux)
install-deps:
	@echo "📦 Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y build-essential g++ make
	@echo "✅ Dependencies installed!"

# Cross-compile for Windows (if mingw is available)
windows: $(MAIN_SOURCE) $(HEADERS)
	@echo "🔨 Cross-compiling for Windows..."
	x86_64-w64-mingw32-g++ $(CXXFLAGS) $(WINFLAGS) -o $(TARGET) $(MAIN_SOURCE) $(WINLIBS) $(LDFLAGS)
	@echo "✅ Windows binary created: $(TARGET)"

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

# Release build
release: CXXFLAGS += -DNDEBUG
release: $(TARGET)

# Show help
help:
	@echo "🎯 BenignPacker Build Options:"
	@echo "  all          - Build the main application (default)"
	@echo "  test         - Run encryption tests"
	@echo "  clean        - Remove build artifacts"
	@echo "  install-deps - Install required dependencies"
	@echo "  windows      - Cross-compile for Windows"
	@echo "  debug        - Build with debug symbols"
	@echo "  release      - Build optimized release version"
	@echo "  help         - Show this help message"

.PHONY: all test clean install-deps windows debug release help