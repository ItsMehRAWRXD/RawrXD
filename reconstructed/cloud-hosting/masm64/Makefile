# MASM x64 Build Makefile
# Builds all MASM components for Vulkan and dependencies

# Tools
ML64 = ml64.exe
LINK = link.exe
LIB = lib.exe

# Flags
MLFLAGS = /c /Cp /Cx /Zi /W3 /nologo
LINKFLAGS = /SUBSYSTEM:CONSOLE /MACHINE:X64 /DEBUG /nologo
LIBFLAGS = /MACHINE:X64 /nologo

# Include directories
INCLUDES = /I"include"

# Output directories
OBJDIR = obj
LIBDIR = lib
BINDIR = bin

# Source files - Vulkan Core
VULKAN_CORE_SRC = \
	vulkan\core\vk_instance.asm \
	vulkan\core\vk_command.asm

# Source files - Vulkan Memory
VULKAN_MEM_SRC = \
	vulkan\memory\vk_memory.asm

# Source files - Vulkan Sync
VULKAN_SYNC_SRC = \
	vulkan\sync\vk_sync.asm

# Source files - Vulkan Compute
VULKAN_COMPUTE_SRC = \
	vulkan\compute\tensor_ops.asm \
	vulkan\compute\matrix_ops.asm \
	vulkan\compute\activation_funcs.asm

# Source files - Compression
COMPRESSION_SRC = \
	compression\zlib.asm \
	compression\zstd.asm

# Source files - Crypto
CRYPTO_SRC = \
	crypto\openssl.asm

# Source files - GPU APIs
GPU_SRC = \
	cuda\cuda_runtime.asm \
	rocm\hip_runtime.asm

# All source files
ALL_SRC = $(VULKAN_CORE_SRC) $(VULKAN_MEM_SRC) $(VULKAN_SYNC_SRC) \
          $(VULKAN_COMPUTE_SRC) $(COMPRESSION_SRC) $(CRYPTO_SRC) $(GPU_SRC)

# Object files
VULKAN_CORE_OBJ = $(VULKAN_CORE_SRC:.asm=.obj)
VULKAN_MEM_OBJ = $(VULKAN_MEM_SRC:.asm=.obj)
VULKAN_SYNC_OBJ = $(VULKAN_SYNC_SRC:.asm=.obj)
VULKAN_COMPUTE_OBJ = $(VULKAN_COMPUTE_SRC:.asm=.obj)
COMPRESSION_OBJ = $(COMPRESSION_SRC:.asm=.obj)
CRYPTO_OBJ = $(CRYPTO_SRC:.asm=.obj)
GPU_OBJ = $(GPU_SRC:.asm=.obj)

ALL_OBJ = $(ALL_SRC:.asm=.obj)

# Libraries
VULKAN_LIB = $(LIBDIR)\vulkan_masm.lib
COMPRESSION_LIB = $(LIBDIR)\compression_masm.lib
CRYPTO_LIB = $(LIBDIR)\crypto_masm.lib
GPU_LIB = $(LIBDIR)\gpu_masm.lib

# Default target
all: setup $(VULKAN_LIB) $(COMPRESSION_LIB) $(CRYPTO_LIB) $(GPU_LIB)
	@echo Build complete!

# Setup directories
setup:
	@if not exist $(OBJDIR) mkdir $(OBJDIR)
	@if not exist $(LIBDIR) mkdir $(LIBDIR)
	@if not exist $(BINDIR) mkdir $(BINDIR)

# Compile assembly files
.asm.obj:
	$(ML64) $(MLFLAGS) $(INCLUDES) /Fo$@ $<

# Vulkan library
$(VULKAN_LIB): $(VULKAN_CORE_OBJ) $(VULKAN_MEM_OBJ) $(VULKAN_SYNC_OBJ) $(VULKAN_COMPUTE_OBJ)
	$(LIB) $(LIBFLAGS) /OUT:$@ $**

# Compression library
$(COMPRESSION_LIB): $(COMPRESSION_OBJ)
	$(LIB) $(LIBFLAGS) /OUT:$@ $**

# Crypto library
$(CRYPTO_LIB): $(CRYPTO_OBJ)
	$(LIB) $(LIBFLAGS) /OUT:$@ $**

# GPU library
$(GPU_LIB): $(GPU_OBJ)
	$(LIB) $(LIBFLAGS) /OUT:$@ $**

# Clean
clean:
	@if exist $(OBJDIR)\*.obj del /Q $(OBJDIR)\*.obj
	@if exist $(LIBDIR)\*.lib del /Q $(LIBDIR)\*.lib
	@if exist $(BINDIR)\*.exe del /Q $(BINDIR)\*.exe
	@if exist *.obj del /Q *.obj
	@if exist *.pdb del /Q *.pdb
	@echo Cleaned build artifacts

# Rebuild
rebuild: clean all

.PHONY: all setup clean rebuild
