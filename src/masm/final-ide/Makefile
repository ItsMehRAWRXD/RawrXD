# Makefile for Rawr1024 Dual Engine Custom Assembly

# Default target
all: rawr1024_engine.exe

# Windows MASM build
rawr1024_engine.exe: rawr1024_dual_engine_custom.asm
	@echo "Building Rawr1024 Dual Engine..."
	ml64 /c /Fo rawr1024_dual_engine_custom.obj rawr1024_dual_engine_custom.asm
	link /SUBSYSTEM:CONSOLE /ENTRY:main rawr1024_dual_engine_custom.obj /OUT:rawr1024_engine.exe
	@echo "Build complete: rawr1024_engine.exe"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	-del /Q *.obj 2>nul
	-del /Q *.exe 2>nul
	-del /Q *.pdb 2>nul
	@echo "Clean complete"

# Run the built executable
run: rawr1024_engine.exe
	@echo "Running Rawr1024 Engine..."
	rawr1024_engine.exe

# Debug build with symbols
debug: rawr1024_dual_engine_custom.asm
	@echo "Building debug version..."
	ml64 /c /Zi /Fo rawr1024_dual_engine_custom.obj rawr1024_dual_engine_custom.asm
	link /DEBUG /SUBSYSTEM:CONSOLE /ENTRY:main rawr1024_dual_engine_custom.obj /OUT:rawr1024_engine_debug.exe
	@echo "Debug build complete: rawr1024_engine_debug.exe"

# Help target
help:
	@echo "Available targets:"
	@echo "  all     - Build the main executable (default)"
	@echo "  clean   - Remove build artifacts"
	@echo "  run     - Build and run the executable"
	@echo "  debug   - Build debug version with symbols"
	@echo "  help    - Show this help message"

.PHONY: all clean run debug help