# =============================================================================
# Toolchain-Windows-MASM.cmake
# Dedicated Windows MASM/MSVC toolchain for deterministic compiler detection
# One-pass initialization with no cache mutation
# =============================================================================

# This file is included BEFORE the project() call, so cache variables
# are initialized cleanly on first run and never force-reset thereafter.

if(NOT CMAKE_SYSTEM_NAME)
    set(CMAKE_SYSTEM_NAME Windows)
endif()

# Detect MSVC/MASM compiler paths only on first run
if(NOT DEFINED CMAKE_C_COMPILER)
    # Try Visual Studio 2022 Enterprise first
    set(_vs_masm_path "C:/VS2022Enterprise/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64/ml64.exe")
    
    if(EXISTS "${_vs_masm_path}")
        set(CMAKE_ASM_MASM_COMPILER "${_vs_masm_path}" CACHE FILEPATH "MASM64 assembler")
    else()
        # Fallback to environment or system search
        find_program(CMAKE_ASM_MASM_COMPILER ml64.exe)
        if(CMAKE_ASM_MASM_COMPILER)
            set(CMAKE_ASM_MASM_COMPILER "${CMAKE_ASM_MASM_COMPILER}" CACHE FILEPATH "MASM64 assembler" FORCE)
        endif()
    endif()
    
    # Detect C/C++ compilers
    if(NOT CMAKE_C_COMPILER)
        # Try MSVC from Visual Studio 2022 first
        if(EXISTS "C:/VS2022Enterprise/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64/cl.exe")
            set(CMAKE_C_COMPILER "C:/VS2022Enterprise/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64/cl.exe")
        endif()
    endif()
    
    if(NOT CMAKE_CXX_COMPILER)
        if(EXISTS "C:/VS2022Enterprise/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64/cl.exe")
            set(CMAKE_CXX_COMPILER "C:/VS2022Enterprise/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64/cl.exe")
        endif()
    endif()
endif()

# Set ASM flags once (enable_language is called by project(), not here)
if(NOT DEFINED CMAKE_ASM_MASM_FLAGS_INIT)
    set(CMAKE_ASM_MASM_FLAGS_INIT "/W3 /nologo /Zd /Zi")
endif()

# Platform defaults
if(NOT DEFINED CMAKE_SIZEOF_VOID_P)
    set(CMAKE_SIZEOF_VOID_P 8)
endif()

# Note: Do NOT call enable_language() here; it's called by project() in CMakeLists.txt
# This file only initializes the toolchain paths.
