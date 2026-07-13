# Phase I.4/5: Compiler Optimizations
# CMake configuration for maximum performance on RX 7800 XT

# ============================================================================
# Compiler Flags
# ============================================================================

# MSVC (Windows)
if(MSVC)
    # Optimization flags
    add_compile_options(/O2)           # Maximum optimization
    add_compile_options(/Ob2)          # Inline function expansion
    add_compile_options(/Oi)           # Enable intrinsic functions
    add_compile_options(/Ot)           # Favor fast code
    add_compile_options(/Oy)           # Omit frame pointer
    add_compile_options(/GT)           # Fiber-safe optimizations
    add_compile_options(/GL)           # Whole program optimization
    
    # Architecture-specific
    add_compile_options(/arch:AVX2)    # Enable AVX2 instructions
    add_compile_options(/favor:AMD64)  # Optimize for AMD64
    
    # Link-time optimization
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /LTCG")
    
    # Security (balanced with performance)
    add_compile_options(/GS-)          # Disable buffer security check (performance critical)
    add_compile_options(/sdl-)       # Disable SDL checks
    
# GCC/Clang (Linux)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Optimization flags
    add_compile_options(-O3)           # Maximum optimization
    add_compile_options(-march=native)   # Optimize for host CPU
    add_compile_options(-mtune=native) # Tune for host CPU
    
    # Vectorization
    add_compile_options(-fopenmp)      # OpenMP support
    add_compile_options(-fopenmp-simd) # OpenMP SIMD
    add_compile_options(-ftree-vectorize)
    add_compile_options(-fopt-info-vec)
    
    # Link-time optimization
    add_compile_options(-flto)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
    
    # Function attributes
    add_compile_options(-ffunction-sections)
    add_compile_options(-fdata-sections)
    
    # Linker optimizations
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-O1")
endif()

# ============================================================================
# AMD GPU Specific (HIP/ROCm)
# ============================================================================

if(RAWRXD_ENABLE_HIP)
    # HIP compiler flags
    set(HIP_HIPCC_FLAGS "${HIP_HIPCC_FLAGS} -O3")
    set(HIP_HIPCC_FLAGS "${HIP_HIPCC_FLAGS} -fgpu-rdc")  # Relocatable device code
    set(HIP_HIPCC_FLAGS "${HIP_HIPCC_FLAGS} --offload-arch=gfx1100")  # RX 7800 XT
    
    # Kernel optimization
    set(HIP_HIPCC_FLAGS "${HIP_HIPCC_FLAGS} -fkernel-arg-opt")
    
    # Math optimizations
    set(HIP_HIPCC_FLAGS "${HIP_HIPCC_FLAGS} -ffast-math")
endif()

# ============================================================================
# Vulkan SPIR-V Optimizations
# ============================================================================

if(RAWRXD_ENABLE_VULKAN)
    # SPIR-V optimizer flags
    set(SPIRV_OPT_FLAGS "-O")
    set(SPIRV_OPT_FLAGS "${SPIRV_OPT_FLAGS} --inline-entry-points-exhaustive")
    set(SPIRV_OPT_FLAGS "${SPIRV_OPT_FLAGS} --merge-return")
    set(SPIRV_OPT_FLAGS "${SPIRV_OPT_FLAGS} --eliminate-dead-functions")
    set(SPIRV_OPT_FLAGS "${SPIRV_OPT_FLAGS} --eliminate-dead-code-aggressive")
    set(SPIRV_OPT_FLAGS "${SPIRV_OPT_FLAGS} --private-to-local")
    set(SPIRV_OPT_FLAGS "${SPIRV_OPT_FLAGS} --strip-debug")
endif()

# ============================================================================
# Profile-Guided Optimization (PGO)
# ============================================================================

option(RAWRXD_ENABLE_PGO "Enable Profile-Guided Optimization" OFF)

if(RAWRXD_ENABLE_PGO)
    if(MSVC)
        # Instrumentation phase
        add_compile_options(/GL)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /GENPROFILE")
        
        # Optimization phase (after profiling)
        # add_compile_options(/USEPROFILE)
    else()
        # Instrumentation phase
        add_compile_options(-fprofile-generate)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-generate")
        
        # Optimization phase (after profiling)
        # add_compile_options(-fprofile-use)
    endif()
endif()

# ============================================================================
# Link-Time Optimization (LTO)
# ============================================================================

option(RAWRXD_ENABLE_LTO "Enable Link-Time Optimization" ON)

if(RAWRXD_ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
    
    if(ipo_supported)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
        message(STATUS "Link-Time Optimization (LTO) enabled")
    else()
        message(WARNING "LTO not supported: ${ipo_error}")
    endif()
endif()

# ============================================================================
# Sanitizers (Debug builds only)
# ============================================================================

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    option(RAWRXD_ENABLE_ASAN "Enable AddressSanitizer" OFF)
    option(RAWRXD_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
    
    if(RAWRXD_ENABLE_ASAN)
        add_compile_options(-fsanitize=address)
        add_link_options(-fsanitize=address)
    endif()
    
    if(RAWRXD_ENABLE_TSAN)
        add_compile_options(-fsanitize=thread)
        add_link_options(-fsanitize=thread)
    endif()
endif()
