cmake_minimum_required(VERSION 3.20)
project(RawrXD-ModelLoader VERSION 1.0.13)

if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_rom_roundtrip.cpp")
    add_executable(deep2_rom_roundtrip tools/deep2_rom_roundtrip.cpp)
    target_include_directories(deep2_rom_roundtrip PRIVATE "${CMAKE_SOURCE_DIR}/src/deep2")
    target_compile_features(deep2_rom_roundtrip PRIVATE cxx_std_20)
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_rom_pack.cpp")
    add_executable(deep2_rom_pack
        tools/deep2_rom_pack.cpp)
    target_include_directories(deep2_rom_pack PRIVATE
        "${CMAKE_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/src"
        "${CMAKE_SOURCE_DIR}/src/deep2")
    target_compile_features(deep2_rom_pack PRIVATE cxx_std_20)
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_shard_probe.cpp")
    add_executable(deep2_shard_probe tools/deep2_shard_probe.cpp)
    target_include_directories(deep2_shard_probe PRIVATE "${CMAKE_SOURCE_DIR}/src/deep2")
    target_compile_features(deep2_shard_probe PRIVATE cxx_std_20)
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/rawrxd_msvc_runner.cpp")
    add_executable(rawrxd_msvc_runner tools/rawrxd_msvc_runner.cpp)
    target_compile_features(rawrxd_msvc_runner PRIVATE cxx_std_20)
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/rawrxd_astro_index.cpp")
    add_executable(rawrxd_astro_index tools/rawrxd_astro_index.cpp)
    target_compile_features(rawrxd_astro_index PRIVATE cxx_std_20)
endif()
add_definitions(-DNOMINMAX -D_WIN32_WINNT=0x0A00)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================
# ENABLE MASM FOR CUSTOM ZLIB IMPLEMENTATION
# ============================================================
enable_language(ASM_MASM)
set(CMAKE_ASM_MASM_FLAGS "/nologo /W3 /Cx /Zi")
message(STATUS "Î“Â£Ã´ MASM assembler enabled for custom ZLIB compression")

# ============================================================
# 64-BIT ARCHITECTURE ENFORCEMENT
# ============================================================
# RawrXD Agentic IDE is x64-ONLY. All dependencies (Qt, GGML, Vulkan)
# are compiled as 64-bit. No 32-bit (x86) support or fallback.
# See: 64BIT_DEPENDENCY_AUDIT.md and DLL_DISTRIBUTION_PACKAGE.md

# Validate 64-bit configuration (generator/platform must be set externally, e.g. -A x64 for VS)
if(MSVC)
    if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "CRITICAL: This project requires 64-bit (x64) configuration. CMAKE_SIZEOF_VOID_P = ${CMAKE_SIZEOF_VOID_P}. Configure with -A x64 for Visual Studio generators.")
    endif()
    message(STATUS "64-bit configuration validated: pointer size = ${CMAKE_SIZEOF_VOID_P}")
endif()

# Pin MSVC runtime for deterministic builds - ALWAYS use /MD (dynamic CRT)
# This ensures all DLLs link against the same MSVC runtime DLL
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    # Force /MD for all targets to prevent CRT mismatch
    add_compile_options(
        $<$<CONFIG:Debug>:/MDd>
        $<$<CONFIG:Release>:/MD>
        $<$<CONFIG:RelWithDebInfo>:/MD>
        $<$<CONFIG:MinSizeRel>:/MD>
    )
endif()

# ============================================================
# SECURITY HARDENING - Compiler & Linker Flags
# ============================================================
# Enable production hardening by default. Can be disabled with -DRAWRXD_ENABLE_HARDENING=OFF
option(RAWRXD_ENABLE_HARDENING "Enable production security hardening (compiler/linker flags)" ON)

if(RAWRXD_ENABLE_HARDENING)
    message(STATUS "Security hardening ENABLED")
    
    if(MSVC)
        # MSVC Security Hardening Flags
        # COMPILE-TIME options below. /DYNAMICBASE, /NXCOMPAT and /HIGHENTROPYVA
        # are LINKER-only: MSVC rejects them as compile arguments with D8021
        # ("invalid numeric argument"), so they live in add_link_options() only.
        # /GS - Buffer Security Check (stack cookie)
        # /guard:cf - Control Flow Guard (CFG)
        # /guard:ehcont - EH Continuation metadata
        # /VOLATILE:ISO - ISO C++ volatile semantics (stronger than MSVC default)
        # /W4 - Warning Level 4 (per-target /WX is opt-in, see rawrxd_security)
        # /Zc:strictStrings - Strict string literal typing (read-only literals)
        # /Zc:throwingNew - Standard-conforming operator new
        # /permissive- - Standards conformance mode
        # NOTE: no /SDL. On this toolchain (VS2022 19.44 + Ninja/Makefiles
        # generators) /SDL is rejected per-file with D9002 "ignoring unknown
        # option", which is noise plus a false sense of hardening. The concrete
        # guarantees we need - /GS, /guard:cf, /guard:ehcont, conformance - are
        # applied explicitly above instead of the SDL bundle.
        add_compile_options(
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/GS>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/guard:cf>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/guard:ehcont>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/VOLATILE:ISO>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/W4>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/Zc:strictStrings>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/Zc:throwingNew>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/permissive->
        )

        add_link_options(
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/DYNAMICBASE>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/NXCOMPAT>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/HIGHENTROPYVA>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/guard:cf>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/guard:ehcont>
        )
        
        # Define security hardening macros
        add_compile_definitions(
            RAWRXD_HARDENING=1
            _FORTIFY_SOURCE=2
            FORTIFY_SOURCE=2
        )
        
    elseif(MINGW OR UNIX)
        # GCC/Clang Security Hardening Flags
        # -fstack-protector-strong - Stack smashing protector (strong)
        # -fstack-clash-protection - Stack clash protection
        # -fcf-protection=full - Control Flow Integrity (CET)
        # -D_FORTIFY_SOURCE=2 - Fortify source (buffer overflow detection)
        # -fPIE - Position Independent Executable
        # -pie - Link as PIE
        # -Wl,-z,relro - Read-only relocations (RELRO)
        # -Wl,-z,now - Immediate binding (BIND_NOW)
        # -Wl,-z,noexecstack - Non-executable stack
        # -fno-plt - Disable PLT for performance/security
        # -Wformat -Wformat-security - Format string warnings
        # -Werror=format-security - Treat format security as error
        # -Wall -Wextra -Wpedantic - Comprehensive warnings
        # -Wconversion -Wsign-conversion - Implicit conversion warnings
        # -Wnull-dereference - Null pointer dereference warnings
        # -Warray-bounds - Array bounds warnings
        # -Wstringop-overflow - String operation overflow warnings
        # -Walloc-zero - Zero-size allocation warnings
        
        add_compile_options(
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-fstack-protector-strong>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-fstack-clash-protection>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-fcf-protection=full>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-D_FORTIFY_SOURCE=2>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-fPIE>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wformat>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wformat-security>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Werror=format-security>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wall>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wextra>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wpedantic>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wconversion>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wsign-conversion>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wnull-dereference>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Warray-bounds>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wstringop-overflow>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Walloc-zero>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wimplicit-fallthrough>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wshadow>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wduplicated-cond>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wduplicated-branches>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wlogical-op>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wrestrict>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wnull-dereference>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wdouble-promotion>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wformat=2>
        )
        
        add_link_options(
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-fPIE>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-pie>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wl,-z,relro>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wl,-z,now>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wl,-z,noexecstack>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-Wl,--no-copy-dt-needed-entries>
            $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-fno-plt>
        )
        
        add_compile_definitions(
            RAWRXD_HARDENING=1
            _FORTIFY_SOURCE=2
            FORTIFY_SOURCE=2
        )
    endif()
    
    # Enable sanitizers in Debug builds (optional, requires -DRAWRXD_ENABLE_SANITIZERS=ON)
    option(RAWRXD_ENABLE_SANITIZERS "Enable Address/Thread/Undefined sanitizers in Debug builds" OFF)
    if(RAWRXD_ENABLE_SANITIZERS AND NOT MSVC)
        if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            add_compile_options(
                $<$<CONFIG:Debug>:-fsanitize=address>
                $<$<CONFIG:Debug>:-fsanitize=undefined>
                $<$<CONFIG:Debug>:-fno-omit-frame-pointer>
            )
            add_link_options(
                $<$<CONFIG:Debug>:-fsanitize=address>
                $<$<CONFIG:Debug>:-fsanitize=undefined>
            )
            message(STATUS "Sanitizers ENABLED for Debug builds (ASan + UBSan)")
        endif()
    elseif(RAWRXD_ENABLE_SANITIZERS AND MSVC)
        # MSVC AddressSanitizer (available in VS 2019 16.9+)
        add_compile_options($<$<CONFIG:Debug>:/fsanitize=address>)
        add_link_options($<$<CONFIG:Debug>:/fsanitize=address>)
        message(STATUS "MSVC AddressSanitizer ENABLED for Debug builds")
    endif()
    
else()
    message(STATUS "Security hardening DISABLED (RAWRXD_ENABLE_HARDENING=OFF)")
    add_compile_definitions(RAWRXD_HARDENING=0)
endif()

# ============================================================
# PRODUCTION RELEASE OPTIMIZATION FLAGS
# ============================================================
# Enable LTO, whole program optimization, and aggressive inlining for Release builds
# These are set globally so all targets benefit without per-target duplication
option(RAWRXD_ENABLE_LTO "Enable Link Time Optimization (LTO) for Release builds" ON)

if(MSVC AND RAWRXD_ENABLE_LTO)
    # MSVC LTO: /GL (whole program optimization) + /LTCG (link-time code generation)
    # /Ob2 - Inline any suitable function
    # /Ot - Favor fast code
    # /Oy - Frame pointer omission (x86 only, implicit for x64)
    # /GF - String pooling
    # /Gy - Function-level linking
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GL /Ob2 /Ot /GF /Gy /EHa")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /GL /Ob2 /Ot /GF /Gy")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /OPT:REF /OPT:ICF")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG /OPT:REF /OPT:ICF")
    set(CMAKE_MODULE_LINKER_FLAGS_RELEASE "${CMAKE_MODULE_LINKER_FLAGS_RELEASE} /LTCG /OPT:REF /OPT:ICF")
    message(STATUS "MSVC LTO enabled: /GL /LTCG /OPT:REF /OPT:ICF")
elseif(MINGW OR UNIX)
    if(RAWRXD_ENABLE_LTO)
        # GCC/Clang LTO: -flto
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -flto -fwhole-program-vtables")
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -flto -fwhole-program-vtables")
        set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -flto -Wl,-O2")
        set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} -flto -Wl,-O2")
        set(CMAKE_MODULE_LINKER_FLAGS_RELEASE "${CMAKE_MODULE_LINKER_FLAGS_RELEASE} -flto -Wl,-O2")
        message(STATUS "GCC/Clang LTO enabled: -flto -Wl,-O2")
    endif()
endif()

# Disable C++ extensions for strict standard conformance
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_EXTENSIONS OFF)

# ============================================================
# STATIC ANALYSIS - Clang-Tidy Integration
# ============================================================
option(RAWRXD_ENABLE_CLANG_TIDY "Enable Clang-Tidy static analysis during build" OFF)

if(RAWRXD_ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE clang-tidy)
    if(CLANG_TIDY_EXE)
        message(STATUS "Clang-Tidy found: ${CLANG_TIDY_EXE}")
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE};-config-file=${CMAKE_SOURCE_DIR}/.clang-tidy")
        set(CMAKE_C_CLANG_TIDY "${CLANG_TIDY_EXE};-config-file=${CMAKE_SOURCE_DIR}/.clang-tidy")
    else()
        message(WARNING "Clang-Tidy not found in PATH - static analysis disabled")
    endif()
endif()

# ============================================================
# CODE COVERAGE - gcov/llvm-cov Integration
# ============================================================
option(RAWRXD_ENABLE_COVERAGE "Enable code coverage instrumentation (GCC/Clang only)" OFF)

if(RAWRXD_ENABLE_COVERAGE AND NOT MSVC)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-instr-generate -fcoverage-mapping")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-instr-generate -fcoverage-mapping")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fprofile-instr-generate -fcoverage-mapping")
    set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -fprofile-instr-generate -fcoverage-mapping")
    message(STATUS "Code coverage instrumentation enabled (Clang/LLVM)")
elseif(RAWRXD_ENABLE_COVERAGE AND MSVC)
    message(WARNING "Code coverage not yet supported for MSVC in this configuration")
endif()

# Detect compiler and set output directory suffix
if(MINGW)
    set(COMPILER_SUFFIX "mingw")
elseif(MSVC)
    set(COMPILER_SUFFIX "msvc")
else()
    set(COMPILER_SUFFIX "other")
endif()

# Build options
option(RAWRXD_BUILD_WIN32IDE "Build the native (Qt-free) Win32 IDE target" ON)
option(RAWRXD_BUILD_WIN32IDE_QT "Build the legacy Qt-dependent Win32IDE target" OFF)
option(RAWRXD_BUILD_BENCHMARKS "Build benchmark executables" OFF)
option(RAWRXD_BUILD_TESTS "Build unit-test harnesses" OFF)
option(ENABLE_COPILOT "Enable Copilot streaming integration for Win32 IDE" OFF)
option(ENABLE_VULKAN "Enable Vulkan GPU acceleration" ON)
option(RAWRXD_BUILD_SECURITY_LIB "Build the rawrxd_security hardening library" ON)

# Force Windows SDK version that ships all required headers
set(CMAKE_SYSTEM_VERSION "10.0.22621.0")

# Qt6 is OPTIONAL. RawrXD's native engine (Deep2, ModelGenie, compiler,
# assembler, linker, CLI tools, native tests) builds dependency-free without
# Qt. Qt-dependent surfaces (IDE, Qt shell, agent, Qt-based tests) are guarded
# on Qt6_FOUND and reported when excluded - never silently skipped.
# CI jobs that certify Qt functionality must pass -DRAWRXD_REQUIRE_QT=ON so a
# missing/incomplete Qt installation fails configure loudly.
option(RAWRXD_REQUIRE_QT "Fail configure when required Qt6 components are unavailable" OFF)

# Qt path: prefer an environment-provided Qt6_DIR
# (e.g. C:/Qt/6.7.3/msvc2022_64/lib/cmake/Qt6), as set by CI Qt installers.
if(DEFINED ENV{Qt6_DIR})
    message(STATUS "Using Qt6 from ENV Qt6_DIR=$ENV{Qt6_DIR}")
    # Qt6_DIR should point to .../lib/cmake/Qt6, so use parent for PREFIX_PATH
    get_filename_component(QT_CMAKE_DIR "$ENV{Qt6_DIR}" DIRECTORY)
    get_filename_component(QT_LIB_DIR "${QT_CMAKE_DIR}" DIRECTORY)
    get_filename_component(QT_ROOT_DIR "${QT_LIB_DIR}" DIRECTORY)
    list(APPEND CMAKE_PREFIX_PATH "${QT_ROOT_DIR}")
    message(STATUS "Set CMAKE_PREFIX_PATH to ${CMAKE_PREFIX_PATH}")
endif()

find_package(Qt6 QUIET COMPONENTS Core Gui Widgets Network Sql Concurrent Test Charts)
if(NOT Qt6_FOUND AND RAWRXD_REQUIRE_QT)
    message(FATAL_ERROR
        "Qt6 is required (RAWRXD_REQUIRE_QT=ON) but was not found with components "
        "Core, Gui, Widgets, Network, Sql, Concurrent, Test, Charts. "
        "Install Qt6 (including Charts) and set Qt6_DIR or CMAKE_PREFIX_PATH.")
endif()

# Qt-dependent targets excluded from a native build, reported at the end.
set(RAWRXD_QT_TARGETS "")

# ============================================================
# TEST INFRASTRUCTURE CONFIGURATION
# ============================================================
if(RAWRXD_BUILD_TESTS)
    enable_testing()
    include(CTest)
    message(STATUS "Î“Â£Ã´ CTest infrastructure enabled - tests will be discoverable")
endif()

# ZLIB Configuration - optional compression library
option(USE_ZLIB_FETCHCONTENT "Auto-download and build zlib if not found" OFF)

# ZLIB is optional - only needed for CheckpointManager compression
# Try to find ZLIB in common installation paths first
find_package(ZLIB QUIET HINTS C:/zlib C:/Program\ Files/zlib "C:/Program Files (x86)/zlib" /usr/local /usr)

if(ZLIB_FOUND)
    message(STATUS "Î“Â£Ã´ ZLIB found at ${ZLIB_INCLUDE_DIR} - Native compression enabled")
    set(HAVE_ZLIB 1)
    set(HAVE_COMPRESSION 1)
elseif(USE_ZLIB_FETCHCONTENT)
    # Auto-fetch zlib if not found on system
    include(FetchContent)
    message(STATUS "Î“Ã¤â•£ ZLIB not found - attempting to auto-download from GitHub...")
    
    FetchContent_Declare(zlib
        URL https://github.com/madler/zlib/archive/refs/tags/v1.3.tar.gz
        URL_HASH SHA256=b5b06d60ce49c8ba700e0ba517fa07de80b5d4628a037f4be8ad16955be7a7c0
    )
    
    FetchContent_MakeAvailable(zlib)
    set(ZLIB_FOUND TRUE)
    set(HAVE_ZLIB 1)
    set(HAVE_COMPRESSION 1)
    message(STATUS "Î“Â£Ã´ ZLIB auto-downloaded and built successfully")
else()
    # Auto-fetch zlib if not found on system (optional - can be enabled with FETCHCONTENT_ZLIB=ON)
    option(FETCHCONTENT_ZLIB "Auto-download and build zlib if not found" OFF)
    
    if(FETCHCONTENT_ZLIB)
        include(FetchContent)
        message(STATUS "Î“Ã¤â•£ ZLIB not found - attempting to auto-download from GitHub...")
        
        FetchContent_Declare(zlib
            URL https://github.com/madler/zlib/archive/refs/tags/v1.3.tar.gz
        )
        
        FetchContent_MakeAvailable(zlib)
        set(ZLIB_FOUND TRUE)
        set(HAVE_ZLIB 1)
        set(HAVE_COMPRESSION 1)
        message(STATUS "Î“Â£Ã´ ZLIB auto-downloaded and built successfully")
    else()
        message(STATUS "Î“Ã¤â•£ ZLIB not installed - Using built-in MASM-based compression (BrutalGzip/Deflate)")
        message(STATUS "  MASM Compression Engines: BrutalGzip (MASM optimized), Deflate (fallback)")
        message(STATUS "  To use native zlib compression:")
        message(STATUS "    Option 1: vcpkg install zlib:x64-windows")
        message(STATUS "    Option 2: Enable auto-download with -DFETCHCONTENT_ZLIB=ON")
        set(HAVE_ZLIB 0)
        set(HAVE_COMPRESSION 1)
    endif()
endif()

find_package(CURL QUIET)
if(CURL_FOUND)
    message(STATUS "CURL found: ${CURL_VERSION_STRING}")
    set(HAVE_CURL 1)
else()
    message(WARNING "CURL not found - HTTP client will use fallback. Set CURL_DIR or install libcurl for full functionality.")
    set(HAVE_CURL 0)
endif()

find_package(ZSTD QUIET)
if(ZSTD_FOUND)
    message(STATUS "ZSTD found: ${ZSTD_VERSION_STRING}")
    set(HAVE_ZSTD 1)
else()
    message(WARNING "ZSTD not found - compression will use passthrough. Set ZSTD_ROOT or install zstd for full functionality.")
    set(HAVE_ZSTD 0)
endif()

if(Qt6_FOUND)
    message(STATUS "Qt6 found: ${Qt6_VERSION}")
    add_definitions(-DHAVE_QT_CORE -DQT_NO_OPENGL)
    include_directories(${Qt6_INCLUDE_DIRS})
    link_libraries(Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network Qt6::Sql Qt6::Concurrent Qt6::Test Qt6::Charts)
    
    # Add compression definitions globally
    add_compile_definitions(HAVE_COMPRESSION=1)
    if(HAVE_ZLIB)
        add_compile_definitions(HAVE_ZLIB=1)
    endif()
    if(HAVE_ZSTD)
        add_compile_definitions(HAVE_ZSTD=1)
    endif()
    
    # ============================================================
    # AUTOMATIC DLL DEPLOYMENT - Deploy ALL dependencies automatically
    # ============================================================
    find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${Qt6_DIR}/../../../bin")
    
    # NOTE: deploy_runtime_dependencies is defined unconditionally below the
    # Qt6_FOUND block: a second find_package(Qt6 ...) later in this file can
    # re-enable Qt6_FOUND after this block was skipped, and the QtShell /
    # AgenticIDE call sites must always be able to call it.
    
    
else()
    message(STATUS "Qt6 not found - native dependency-free build (Qt-dependent targets excluded)")
endif()

# ============================================================
# AUTOMATIC DLL DEPLOYMENT HELPER (defined unconditionally)
# ============================================================
# A second find_package(Qt6 ...) later in this file can re-enable Qt6_FOUND
# after the block above was skipped, so the QtShell / AgenticIDE call sites
# must always be able to call this function.
find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${Qt6_DIR}/../../../bin")
function(deploy_runtime_dependencies target_name)
    if(WIN32 AND WINDEPLOYQT_EXECUTABLE)
        add_custom_command(TARGET ${target_name} POST_BUILD
            COMMAND "${WINDEPLOYQT_EXECUTABLE}"
                --release
                --compiler-runtime
                --no-translations
                --no-system-d3d-compiler
                --no-opengl-sw
                "$<TARGET_FILE:${target_name}>"
            WORKING_DIRECTORY "$<TARGET_FILE_DIR:${target_name}>"
            COMMENT "Deploying Qt dependencies for ${target_name}..."
        )
        add_custom_command(TARGET ${target_name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:Qt6::Sql>"
                "$<TARGET_FILE_DIR:${target_name}>/"
            COMMENT "Ensuring Qt6Sql.dll is deployed for ${target_name}"
        )
        if(EXISTS "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC/14.44.35207/x64/Microsoft.VC144.OpenMP/vcomp140.dll")
            add_custom_command(TARGET ${target_name} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC/14.44.35207/x64/Microsoft.VC144.OpenMP/vcomp140.dll"
                    "$<TARGET_FILE_DIR:${target_name}>/"
                COMMENT "Deploying vcomp140.dll for ${target_name}"
            )
        endif()
        message(STATUS "Automatic DLL deployment enabled for ${target_name}")
    else()
        message(WARNING "windeployqt not found - manual DLL deployment required for ${target_name}")
    endif()
endfunction()

# ============================================================
# GGML Submodule Integration (Quantized Transformer Kernels)
# ============================================================
if(EXISTS "${CMAKE_SOURCE_DIR}/3rdparty/ggml/CMakeLists.txt")
    message(STATUS "Adding ggml submodule for quantized inference")
    
    # ggml build options - disable unnecessary components
    set(GGML_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(GGML_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(GGML_AVX2 ON CACHE BOOL "" FORCE)  # Enable AVX2 for speed
    set(GGML_STATIC ON CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    
    # Enable GPU backends (Vulkan follows ENABLE_VULKAN so dependency-free
    # builds without the Vulkan SDK stay possible; it was previously forced
    # ON, which made ggml-vulkan a hard requirement on every configure)
    if(ENABLE_VULKAN)
        set(GGML_VULKAN ON CACHE BOOL "" FORCE)  # Vulkan for AMD/NVIDIA/Intel
    else()
        set(GGML_VULKAN OFF CACHE BOOL "" FORCE)
    endif()
    set(GGML_CUDA OFF CACHE BOOL "" FORCE)   # CUDA for NVIDIA only
    set(GGML_METAL OFF CACHE BOOL "" FORCE)  # Metal for macOS only
    
    # Add our include directory first to provide missing Windows SDK headers
    include_directories(BEFORE SYSTEM ${CMAKE_SOURCE_DIR}/include)
    
    # Export include path for nested ExternalProject builds (Vulkan shader gen)
    set(CMAKE_INCLUDE_PATH "${CMAKE_SOURCE_DIR}/include" CACHE STRING "" FORCE)
    set(ENV{INCLUDE} "${CMAKE_SOURCE_DIR}/include;$ENV{INCLUDE}")
    
add_subdirectory(3rdparty/ggml EXCLUDE_FROM_ALL)

    # Deep2 SNAP: dependency-free event-driven tool protocol + stop controller.
    # Provides the deep2_snap INTERFACE target and deep2_snap_test executable.
    add_subdirectory(tools/deep2_snap/deep2_snap EXCLUDE_FROM_ALL)

    # SNAP Process Guard: dependency-free process enumeration, verification, job object,
    # and termination. Provides the snap_process_guard library and CLI.
    add_subdirectory(tools/snap_process_guard EXCLUDE_FROM_ALL)

    # SNAP Supervisor: production-grade process supervisor with Job Object lifecycle,
    # ownership receipts, orphan scanning, and JSONL lifecycle events.
    add_subdirectory(tools/snap_supervisor EXCLUDE_FROM_ALL)

    # Deep2 Flight Recorder: self-logging inference debugger for performance diagnosis.
    add_subdirectory(tools/deep2_debugger EXCLUDE_FROM_ALL)

    # RawrXD parity finalization runner: dependency-free C++20 autonomous
    # execution loop (rawr run <model> <task>) with guarded file editing,
    # bounded retries, process timeouts, tool-name integrity (rejects gash/
    # bash etc.) and a JSONL evidence ledger. Its --self-test is registered
    # with CTest so the guarded-edit/JSON/frame/path-guard contracts are
    # enforced on every build, not just on manual invocation.
    if(EXISTS "${CMAKE_SOURCE_DIR}/tools/rawrxd_parity_final/CMakeLists.txt")
        add_subdirectory(tools/rawrxd_parity_final)
    else()
        message(STATUS "rawrxd_parity_final EXCLUDED: tools/rawrxd_parity_final/CMakeLists.txt not present")
    endif()

    # Create ggml interface library for clean linking
    add_library(ggml_interface INTERFACE)
    target_link_libraries(ggml_interface INTERFACE ggml)
    target_include_directories(ggml_interface INTERFACE 
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/src
    )
    
    # Suppress ggml warnings and add our stubs
    if(TARGET ggml)
        target_include_directories(ggml BEFORE PRIVATE ${CMAKE_SOURCE_DIR}/include)
        if(MSVC)
            target_compile_options(ggml PRIVATE /W0)
        else()
            target_compile_options(ggml PRIVATE -w)
        endif()
    endif()
else()
    message(WARNING "ggml submodule not found - quantized inference will use fallback")
endif()

# ============================================================
# GPU Backend Detection (CUDA, ROCm/HIP, Vulkan)
# ============================================================
option(ENABLE_CUDA "Enable NVIDIA CUDA support" ON)
option(ENABLE_HIP "Enable AMD ROCm/HIP support" ON)
option(ENABLE_VULKAN "Enable Vulkan Compute support" ON)

# Try to find CUDA (NVIDIA)
if(ENABLE_CUDA)
    find_package(CUDAToolkit QUIET)
    if(CUDAToolkit_FOUND)
        message(STATUS "CUDA Toolkit found: ${CUDAToolkit_VERSION}")
        add_compile_definitions(HAVE_CUDA=1)
        set(GPU_BACKEND_LIBS ${GPU_BACKEND_LIBS} CUDA::cudart CUDA::cuda_driver)
    else()
        message(STATUS "CUDA Toolkit not found - NVIDIA GPU support disabled")
    endif()
endif()

# Try to find ROCm/HIP (AMD)
if(ENABLE_HIP)
    find_package(hip QUIET)
    if(hip_FOUND)
        message(STATUS "ROCm/HIP found: ${hip_VERSION}")
        add_compile_definitions(HAVE_HIP=1)
        set(GPU_BACKEND_LIBS ${GPU_BACKEND_LIBS} hip::host)
    else()
        # Try alternative: check if hipcc compiler exists
        find_program(HIPCC_EXECUTABLE hipcc)
        if(HIPCC_EXECUTABLE)
            message(STATUS "HIP compiler found at ${HIPCC_EXECUTABLE}")
            add_compile_definitions(HAVE_HIP=1)
            # Manual HIP setup for Windows
            if(DEFINED ENV{HIP_PATH})
                set(HIP_INCLUDE_DIRS "$ENV{HIP_PATH}/include")
                set(HIP_LIBRARIES "$ENV{HIP_PATH}/lib/amdhip64.lib")
                include_directories(${HIP_INCLUDE_DIRS})
                link_libraries(${HIP_LIBRARIES})
                message(STATUS "Using HIP from HIP_PATH: $ENV{HIP_PATH}")
            endif()
        else()
            message(STATUS "ROCm/HIP not found - AMD GPU support disabled")
            message(STATUS "To enable AMD GPU: Install ROCm for Windows and set HIP_PATH")
        endif()
    endif()
endif()

# Try to find Vulkan (Cross-platform)
if(ENABLE_VULKAN)
    find_package(Vulkan QUIET)
    if(Vulkan_FOUND)
        # Verify we have the real Vulkan SDK header, not the local stub.
        # The repo's include/ ships a vulkan/vulkan.h STUB (no vk* entry points),
        # which FindVulkan may incorrectly resolve. We must locate the real SDK header.
        set(_rawrxd_vk_inc "${Vulkan_INCLUDE_DIRS}")
        if(NOT _rawrxd_vk_inc)
            set(_rawrxd_vk_inc "${Vulkan_INCLUDE_DIR}")
        endif()
        set(_rawrxd_vk_hdr "")
        if(_rawrxd_vk_inc)
            file(TO_CMAKE_PATH "${_rawrxd_vk_inc}" _rawrxd_vk_inc)
            set(_rawrxd_vk_hdr "${_rawrxd_vk_inc}/vulkan/vulkan.h")
        endif()
        if(NOT EXISTS "${_rawrxd_vk_hdr}")
            # Also check VULKAN_SDK environment variable as fallback
            if(DEFINED ENV{VULKAN_SDK})
                set(_rawrxd_vk_sdk_inc "$ENV{VULKAN_SDK}/Include")
                if(EXISTS "${_rawrxd_vk_sdk_inc}/vulkan/vulkan.h")
                    set(_rawrxd_vk_hdr "${_rawrxd_vk_sdk_inc}/vulkan/vulkan.h")
                    set(_rawrxd_vk_inc "${_rawrxd_vk_sdk_inc}")
                endif()
            endif()
        endif()
        
        if(EXISTS "${_rawrxd_vk_hdr}")
            message(STATUS "Vulkan found: ${Vulkan_VERSION}")
            message(STATUS "Vulkan header: ${_rawrxd_vk_hdr}")
            add_compile_definitions(HAVE_VULKAN=1)
            add_compile_definitions(RAWRXD_VULKAN_SDK_HEADER="${_rawrxd_vk_hdr}")
            # BEFORE so the real SDK header is selected rather than the local stub.
            # It also puts vk_video/ on the search path, which vulkan_core.h needs.
            include_directories(BEFORE SYSTEM "${_rawrxd_vk_inc}")
            set(GPU_BACKEND_LIBS ${GPU_BACKEND_LIBS} Vulkan::Vulkan)
        else()
            message(WARNING "Vulkan package found but real SDK header (vulkan/vulkan.h) not located.")
            message(WARNING "  Found include path: ${_rawrxd_vk_inc}")
            message(WARNING "  The local stub header in include/vulkan/vulkan.h will NOT be used.")
            message(WARNING "  Vulkan Compute support DISABLED. Install Vulkan SDK and set VULKAN_SDK env var.")
            # Do NOT set HAVE_VULKAN or add Vulkan::Vulkan - treat as not found
        endif()
    else()
        message(STATUS "Vulkan not found - Vulkan Compute support disabled")
    endif()
endif()

if(NOT CUDAToolkit_FOUND AND NOT hip_FOUND AND NOT HIPCC_EXECUTABLE AND NOT Vulkan_FOUND)
    message(WARNING "========================================")
    message(WARNING "NO GPU BACKEND DETECTED")
    message(WARNING "Application will run in CPU-only mode")
    message(WARNING "========================================")
    message(WARNING "Detected GPU: Run 'Get-WmiObject Win32_VideoController | Select Name'")
    message(WARNING "For NVIDIA: Install CUDA Toolkit from developer.nvidia.com")
    message(WARNING "For AMD: Install ROCm for Windows from rocm.docs.amd.com")
    message(WARNING "========================================")
endif()

# ============================================================
# Dependency-free Workflow Modules (Browser Testing & GitHub Cloud Agents)
# ============================================================
# rawrxd_workflow builds the Cursor-like workflow tools (browser
# automation via WebView2, GitHub REST/cloud-agent via WinHTTP) as
# a static library. It depends only on the vendored nlohmann/json
# and the Windows SDK - no Qt - so it is built in native
# dependency-free builds. It is a WINDOWS-ONLY library (WebView2,
# WinHTTP, windows.h), so it is gated on WIN32 to keep non-Windows
# builds working.

# nlohmann/json is vendored header-only at include/nlohmann/json.hpp, but the
# targets at CMakeLists.txt:3095 and :3182 link nlohmann_json::nlohmann_json,
# which was never defined -- so `cmake -G "Visual Studio 17 2022"` aborted with
# "Target ... links to nlohmann_json::nlohmann_json but the target was not
# found". Define the imported/interface target from the vendored header instead
# of adding a network dependency or removing the call sites.
if(NOT TARGET nlohmann_json)
    add_library(nlohmann_json INTERFACE)
    target_include_directories(nlohmann_json SYSTEM INTERFACE
        ${CMAKE_SOURCE_DIR}/include)
    if(NOT TARGET nlohmann_json::nlohmann_json)
        add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
    endif()
    message(STATUS "nlohmann_json: using vendored header at include/nlohmann/json.hpp")
endif()

if(WIN32)
    # Production-hardening runtime (dependency-free: Windows stdlib + CNG).
    # Built unconditionally on Windows because it has no external dependency,
    # so CI and shipped binaries get the same hardened layer.
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/production/CMakeLists.txt")
        add_subdirectory(src/production)
    else()
        message(STATUS "rawrxd_production_hardening EXCLUDED: src/production not present")
    endif()

    add_subdirectory(src/workflow)
    # Deep2 AutoTune — native C++20 tuning core (Windows-only, no Qt)
    if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_autotune/CMakeLists.txt")
        add_subdirectory(tools/deep2_autotune)
    else()
        message(STATUS "deep2_autotune EXCLUDED: tools/deep2_autotune/CMakeLists.txt not present")
    endif()
    # Agent ESP — native C++20 event telemetry (Windows-only, no Qt)
    if(EXISTS "${CMAKE_SOURCE_DIR}/tools/agent_esp/rawrxd_agent_esp/CMakeLists.txt")
        add_subdirectory(tools/agent_esp/rawrxd_agent_esp)
    else()
        message(STATUS "agent_esp EXCLUDED: tools/agent_esp/rawrxd_agent_esp/CMakeLists.txt not present")
    endif()
endif()

# ============================================================
# Advanced Orchestration Modules (Phase 1-6 Implementation)
# ============================================================
message(STATUS "Adding advanced orchestration modules for AI-native IDE")
# The orchestration modules (orchestration/git/terminal/paint) are Qt6-based
# (RawrXDOrchestration, RawrXDGit, RawrXDTerminal link Qt6::*). They are
# excluded from native dependency-free builds and reported, never skipped
# silently. With Qt6 present they build normally (and fail loudly if any of
# their sources or subdirectory build files are missing).
if(Qt6_FOUND)
    add_subdirectory(src/orchestration)
    add_subdirectory(src/git)
    add_subdirectory(src/terminal)
    # Paint shell is not present in this tree; report instead of failing.
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/paint/CMakeLists.txt")
        add_subdirectory(src/paint)
    else()
        list(APPEND RAWRXD_QT_TARGETS RawrXDPaint)
        message(STATUS "RawrXDPaint EXCLUDED: src/paint not present in this tree")
    endif()
else()
    list(APPEND RAWRXD_QT_TARGETS RawrXDOrchestration RawrXDGit RawrXDTerminal RawrXDPaint)
    message(STATUS "Qt-dependent orchestration modules EXCLUDED (Qt6 not installed): RawrXDOrchestration, RawrXDGit, RawrXDTerminal, RawrXDPaint")
endif()

# Qt-based IDE shell (separate executable, no Vulkan)
# NOTE: Qt6 is optional and this project does not depend on it. When Qt6 is
# absent these targets are excluded and reported (see the summary at the end
# of this file). No second find_package(Qt6 ...) here: a partial component
# list could re-enable Qt6_FOUND after the Qt6-guarded helper functions above
# were skipped, producing "Unknown CMake command" errors at the call sites.
if(MSVC)
    if(Qt6_FOUND) # Enabled to build Qt shell
        message(STATUS "Building Qt Shell with Qt version: ${Qt6_VERSION}")
        
        # Enable Qt MOC for QObject classes
        set(CMAKE_AUTOMOC ON)

        # Create a simple Qt console app for now
                    if(EXISTS "${CMAKE_SOURCE_DIR}/MainWindow_AI_Integration.cpp")
            add_executable(RawrXD-QtShell 
                        src/qtapp/main_qt.cpp
                        src/qtapp/MainWindow.cpp
                        src/qtapp/MainWindow.h
                        # MainWindow_AI_Integration.cpp removed - duplicate definitions merged into MainWindow.cpp
                        src/qtapp/ActivityBar.cpp
                        src/qtapp/ActivityBar.h
                        src/qtapp/ActivityBarButton.cpp
                        src/qtapp/ActivityBarButton.h
                        src/qtapp/TerminalWidget.cpp
                        src/qtapp/TerminalWidget.h
                        src/qtapp/TerminalManager.cpp
                        src/qtapp/TerminalManager.h
                        src/gguf_loader.cpp        # Native C++ loader wrapped by gguf_loader_qt
                        src/gguf_vocab_resolver.cpp  # Universal vocab size detection for all GGUF models
                        include/gguf_loader.h      # Ensure header is in sources for proper dependency tracking
                        src/qtapp/gguf_loader.hpp  # Qt wrapper header
                        src/qtapp/gguf_loader.cpp  # Qt wrapper implementation
                        src/qtapp/inference_engine.hpp
                        src/qtapp/inference_engine.cpp
                        src/qtapp/transformer_inference.hpp
                        src/qtapp/transformer_inference.cpp
                        src/qtapp/bpe_tokenizer.hpp
                        src/qtapp/bpe_tokenizer.cpp
                        src/qtapp/sentencepiece_tokenizer.hpp
                        src/qtapp/sentencepiece_tokenizer.cpp
                        src/qtapp/vocabulary_loader.hpp
                        src/qtapp/vocabulary_loader.cpp
                        src/qtapp/gguf_server.hpp
                        src/qtapp/gguf_server.cpp
                        src/qtapp/inflate_deflate_cpp.cpp
                        src/qtapp/deflate_brutal_stub.cpp
                        src/qtapp/ai_switcher.hpp
                        src/qtapp/ai_switcher.cpp
                        src/qtapp/unified_backend.hpp
                        src/qtapp/unified_backend.cpp
                        src/qtapp/widgets/layer_quant_widget.hpp
                        src/qtapp/widgets/layer_quant_widget.cpp
                        src/qtapp/streaming_inference.hpp
                        src/qtapp/streaming_inference.cpp
                        src/qtapp/model_monitor.hpp
                        src/qtapp/model_monitor.cpp
                        src/qtapp/command_palette.hpp
                        src/qtapp/command_palette.cpp
                        src/qtapp/ai_chat_panel.hpp
                        src/qtapp/ai_chat_panel.cpp
                        src/qtapp/model_memory_hotpatch.hpp
                        src/qtapp/model_memory_hotpatch.cpp
                        src/qtapp/byte_level_hotpatcher.hpp
                        src/qtapp/byte_level_hotpatcher.cpp
                        src/qtapp/gguf_server_hotpatch.hpp
                        src/qtapp/gguf_server_hotpatch.cpp
                        src/qtapp/unified_hotpatch_manager.hpp
                        src/qtapp/unified_hotpatch_manager.cpp
                        src/qtapp/proxy_hotpatcher.hpp
                        src/qtapp/proxy_hotpatcher.cpp
                        # Production-ready enterprise components
                        src/qtapp/model_queue.hpp
                        src/qtapp/model_queue.cpp
                        src/qtapp/streaming_inference_api.hpp
                        src/qtapp/streaming_inference_api.cpp
                        src/qtapp/gpu_backend.hpp
                        src/qtapp/gpu_backend.cpp
                        src/qtapp/metrics_collector.hpp
                        src/qtapp/metrics_collector.cpp
                          src/qtapp/backup_manager.hpp
                          src/qtapp/backup_manager.cpp
                          # src/qtapp/compliance_logger.hpp  # TEMPORARILY DISABLED - Windows header enum conflicts
                          # src/qtapp/compliance_logger.cpp  # MOC issue RESOLVED but case expression errors remain
                          src/qtapp/sla_manager.hpp
                          src/qtapp/sla_manager.cpp
                        # ============================================================
                        # Phase 3: Production Enhancement Components (5,280 LOC)
                        # ============================================================
                        # src/qtapp/security_manager.cpp
                        # src/qtapp/security_manager.h
                        # src/qtapp/distributed_trainer.cpp    # Temporarily disabled due to compilation issues
                        # src/qtapp/distributed_trainer.h      # Temporarily disabled due to compilation issues
                        # ENHANCED Interpretability Panel - Production Ready (1,500+ LOC)
                        src/qtapp/interpretability_panel_enhanced.hpp
                        src/qtapp/interpretability_panel_enhanced.cpp
                        include/checkpoint_manager.h
                        src/qtapp/checkpoint_manager.cpp
                        include/tokenizer_selector.h
                        src/qtapp/tokenizer_selector.cpp
                        include/ci_cd_settings.h
                        src/qtapp/ci_cd_settings.cpp
                        # Project detection and metadata management
                        src/qtapp/utils/project_detector.cpp
                        # File and directory operations
                        src/qtapp/utils/qt_file_writer.cpp
                        src/qtapp/utils/qt_directory_manager.cpp
                        src/qtapp/settings_dialog.h
                        src/qtapp/settings_dialog.cpp
                        src/qtapp/settings_manager.h
                        src/qtapp/settings_manager.cpp
                        src/qtapp/advanced_checkpoint_manager.cpp
                        src/qtapp/advanced_checkpoint_manager.h
                        src/qtapp/tokenizer_language_selector.cpp
                        src/qtapp/tokenizer_language_selector.h
                        src/qtapp/ci_pipeline_manager.cpp
                        src/qtapp/ci_pipeline_manager.h
                        src/qtapp/codec.h
                        src/qtapp/codec.cpp
                        # ============================================================
                        # Phase 4: AI Code Assistant (Code Completion with MASM Transport)
                        # ============================================================
                        src/qtapp/ai_code_assistant.h
                        src/qtapp/ai_code_assistant.cpp
                        src/qtapp/ai_code_assistant_panel.h
                        src/qtapp/ai_code_assistant_panel.cpp
                        src/agent/agentic_puppeteer.hpp
                        src/agent/agentic_puppeteer.cpp
                        src/agent/agentic_failure_detector.hpp
                        src/agent/agentic_failure_detector.cpp
                        src/agent/agentic_copilot_bridge.hpp
                        src/agent/agentic_copilot_bridge.cpp
                        # ============================================================
                        # Hot-Patching System: Real-time hallucination detection & correction
                        # ============================================================
                        # src/agent/agent_hot_patcher.cpp
                        # src/agent/gguf_proxy_server.cpp
                        # src/agent/ide_agent_bridge_hot_patching_integration.cpp
                        src/llm_adapter/QuantBackend.cpp
                        src/llm_adapter/QuantBackend.h
                        src/agent/auto_bootstrap.cpp
                        src/qtapp/widgets/masm_editor_widget.cpp
                        src/qtapp/widgets/hotpatch_panel.cpp
                        src/qtapp/widgets/layer_quant_widget.cpp
                        # src/agent/zero_touch.cpp
                        # kernels/quant_ladder_avx2.cpp  # Conflicts with ggml quantization functions
                        # src/agent/planner.cpp
                        # src/agent/self_patch.cpp
                        # src/agent/sign_binary.cpp
                        # src/agent/release_agent.cpp
                        src/agent/meta_learn.cpp
                        src/agent/hot_reload.cpp
                        src/agent/auto_update.cpp
                        src/agent/planner.cpp
                        src/agent/self_patch.cpp
                        src/agent/release_agent.cpp
                        src/agent/zero_touch.cpp
                        src/agent/sentry_integration.hpp
                        src/agent/sentry_integration.cpp
                        src/agent/code_signer.hpp
                        src/agent/code_signer.cpp
                        src/agent/telemetry_collector.hpp
                        src/agent/telemetry_collector.cpp
                        # Agent execution and planning modules
                        src/agent/action_executor.hpp
                        src/agent/action_executor.cpp
                        src/agent/meta_planner.hpp
                        src/agent/meta_planner.cpp
                        # ============================================================
                        # Agentic resilience subsystems (no dependencies, pure C++20)
                        #   - adaptive_retry: circuit breakers + exponential backoff+jitter
                        #   - delegated_agents: agent lifecycle, resource quotas, messaging
                        #   - conflict_resolution: 3-way merge + semantic conflict handling
                        # ============================================================
                        src/agent/adaptive_retry.hpp
                        src/agent/adaptive_retry.cpp
                        src/agent/delegated_agents.hpp
                        src/agent/delegated_agents.cpp
                        src/agentic/conflict_resolution.hpp
                        src/agentic/conflict_resolution.cpp
                        # Project UI components
                        src/qtapp/widgets/project_explorer.cpp
                        src/qtapp/widgets/project_explorer.h
                        # Code quality improvement modules
                        src/utils/ErrorReporter.hpp
                        src/utils/ErrorReporter.cpp
                        src/model_loader/GGUFConstants.hpp
                        src/utils/Diagnostics.hpp
                        src/utils/Diagnostics.cpp
                        # Full Utility Tool Registry with Production Readiness
                        # TODO: Fix Windows RPC macro conflicts with nlohmann::json in tool_registry.cpp
                        # include/tool_registry.hpp
                        # src/tool_registry.cpp
                    )
        else()
            list(APPEND RAWRXD_QT_TARGETS RawrXD-QtShell)
            message(STATUS "RawrXD-QtShell EXCLUDED: sources absent from this tree (MainWindow_AI_Integration.cpp, MainWindow.cpp, src/qtapp/deflate_brutal_stub.cpp, tool_registry.cpp)")
        endif()
        
        add_library(self_test_gate STATIC
            src/agent/self_test.cpp
            src/agent/self_test_gate.cpp
            src/agent/rollback.cpp
        )
        target_link_libraries(self_test_gate PRIVATE Qt6::Core Qt6::Network)
        target_include_directories(self_test_gate PRIVATE ${CMAKE_SOURCE_DIR}/src/agent)

        # Small shared quant utils library (used by QtShell and tests)
        add_library(quant_utils STATIC src/qtapp/quant_utils.cpp)
        target_include_directories(quant_utils PUBLIC ${CMAKE_SOURCE_DIR}/src/qtapp ${CMAKE_SOURCE_DIR}/include)
        target_link_libraries(quant_utils PUBLIC Qt6::Core)
        
        # CPU inference engine library (replaces GPU dependencies)
        add_library(cpu_inference_engine STATIC 
            src/cpu_inference_engine.cpp
        )
        target_include_directories(cpu_inference_engine PUBLIC ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include)
        if(MSVC)
            target_compile_options(cpu_inference_engine PRIVATE /arch:AVX2)
        endif()
        
        # Find OpenSSL for SecurityManager encryption/HMAC (optional, with fallback)
        find_package(OpenSSL QUIET)
        if(OpenSSL_FOUND)
            message(STATUS "OpenSSL found - SecurityManager encryption enabled")
            add_compile_definitions(HAVE_OPENSSL=1)
        else()
            message(STATUS "OpenSSL not found - SecurityManager will use basic hash-only mode")
        endif()
        
        # Find zlib for CheckpointManager compression (optional with fallback)
        find_package(ZLIB QUIET)
        if(ZLIB_FOUND)
            message(STATUS "ZLIB found - CheckpointManager compression enabled")
            add_compile_definitions(HAVE_ZLIB=1)
        else()
            message(STATUS "ZLIB not found - CheckpointManager will use no compression")
        endif()

        # Link Qt modules including WebSockets for swarm collaboration
        if(TARGET RawrXD-QtShell)
        target_link_libraries(RawrXD-QtShell PRIVATE
            Qt6::Core
            Qt6::Gui
            Qt6::Widgets
            Qt6::Network
            Qt6::Sql
            Qt6::Concurrent
            RawrXDOrchestration
            brutal_compression_lib
            self_test_gate
            quant_utils
            masm_compiler_qt_lib
            cpu_inference_engine
        )        # Add include directories for QtShell to access both qtapp and main source headers
        endif()
        if(TARGET RawrXD-QtShell)
        target_include_directories(RawrXD-QtShell PRIVATE 
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/qtapp
            ${CMAKE_SOURCE_DIR}/include
        )
        endif()
        
        # Conditionally link OpenSSL if found
        if(OpenSSL_FOUND)
            if(TARGET RawrXD-QtShell)
            target_link_libraries(RawrXD-QtShell PRIVATE OpenSSL::Crypto OpenSSL::SSL)
            endif()
        endif()
        
        # Conditionally link ZLIB if found
        if(ZLIB_FOUND)
            if(TARGET RawrXD-QtShell)
            target_link_libraries(RawrXD-QtShell PRIVATE ZLIB::ZLIB)
            endif()
        endif()
        
        # Try to find Qt WebSockets (optional for swarm editing)
        find_package(Qt6 COMPONENTS WebSockets QUIET)
        if(Qt6WebSockets_FOUND)
            if(TARGET RawrXD-QtShell)
            target_link_libraries(RawrXD-QtShell PRIVATE Qt6::WebSockets)
            endif()
            if(TARGET RawrXD-QtShell)
            target_compile_definitions(RawrXD-QtShell PRIVATE HAVE_QT_WEBSOCKETS=1)
            endif()
            message(STATUS "Qt WebSockets found - swarm collaboration enabled")
        else()
            message(STATUS "Qt WebSockets not found - swarm collaboration disabled")
        endif()
        
        # Link ggml if available
        if(TARGET ggml)
            if(TARGET RawrXD-QtShell)
            target_link_libraries(RawrXD-QtShell PRIVATE ggml_interface)
            endif()
            if(TARGET RawrXD-QtShell)
            target_compile_definitions(RawrXD-QtShell PRIVATE HAVE_GGML=1)
            endif()
            message(STATUS "RawrXD-QtShell: ggml quantization enabled")
        endif()
        
        if(TARGET RawrXD-QtShell)
        target_include_directories(RawrXD-QtShell PRIVATE 
            include 
            ${CMAKE_SOURCE_DIR}/src 
            ${CMAKE_SOURCE_DIR}/src/qtapp 
            ${CMAKE_SOURCE_DIR}/src/llm_adapter 
            ${CMAKE_SOURCE_DIR}/src/agent
            ${CMAKE_SOURCE_DIR}/src/utils
            ${CMAKE_SOURCE_DIR}/src/model_loader
        )
        endif()
        
        if(TARGET RawrXD-QtShell)
        set_target_properties(RawrXD-QtShell PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
            WIN32_EXECUTABLE TRUE
            AUTOMOC ON
            AUTOMOC_MOC_OPTIONS "-I${CMAKE_SOURCE_DIR}/include;-I${CMAKE_CURRENT_SOURCE_DIR}/src/qtapp"
        )
        endif()

        if(MSVC)
            if(TARGET RawrXD-QtShell)
            target_compile_options(RawrXD-QtShell PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
            endif()
        else()
            if(TARGET RawrXD-QtShell)
            target_compile_options(RawrXD-QtShell PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
            endif()
        endif()
        
        # Automatic DLL deployment for RawrXD-QtShell
        if(TARGET RawrXD-QtShell)
        deploy_runtime_dependencies(RawrXD-QtShell)
        endif()
        
        # ---------- Production Feature Test: Real component testing ----------
        if(RAWRXD_BUILD_TESTS)
        add_executable(production_feature_test
            src/qtapp/production_feature_test.cpp
            src/qtapp/gpu_backend.cpp
            src/qtapp/metrics_collector.cpp
            # src/qtapp/backup_manager.cpp  # Disabled - requires zlib
            src/qtapp/sla_manager.cpp
        )
        
        target_link_libraries(production_feature_test PRIVATE
            Qt6::Core
            Qt6::Gui
            Qt6::Widgets
            Qt6::Network
            ${GPU_BACKEND_LIBS}
        )
        
        # Link Vulkan if enabled
        if(Vulkan_FOUND)
            target_link_libraries(production_feature_test PRIVATE Vulkan::Vulkan)
        endif()
        
        target_include_directories(production_feature_test PRIVATE 
            include 
            ${CMAKE_SOURCE_DIR}/src 
            ${CMAKE_SOURCE_DIR}/src/qtapp
        )
        
        # Explicitly apply GPU backend definitions
        if(CUDAToolkit_FOUND)
            target_compile_definitions(production_feature_test PRIVATE HAVE_CUDA=1)
        endif()
        if(hip_FOUND OR HIPCC_EXECUTABLE)
            target_compile_definitions(production_feature_test PRIVATE HAVE_HIP=1)
        endif()
        if(Vulkan_FOUND)
            target_compile_definitions(production_feature_test PRIVATE HAVE_VULKAN=1)
        endif()
        
        set_target_properties(production_feature_test PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        endif() # RAWRXD_BUILD_TESTS

        # (instruction_loader_test removed - keep test file for future integration)
        
        # ---------- Simple GPU Test: Quick Vulkan verification ----------
        add_executable(simple_gpu_test
            src/qtapp/simple_gpu_test.cpp
            src/qtapp/gpu_backend.cpp
            src/qtapp/metrics_collector.cpp
        )
        
        target_link_libraries(simple_gpu_test PRIVATE
            Qt6::Core
            ${GPU_BACKEND_LIBS}
        )
        
        # Link ggml for Vulkan compute support
        if(TARGET ggml)
            target_link_libraries(simple_gpu_test PRIVATE ggml)
        endif()
        
        if(Vulkan_FOUND)
            target_link_libraries(simple_gpu_test PRIVATE Vulkan::Vulkan)
        endif()
        
        target_include_directories(simple_gpu_test PRIVATE 
            include 
            ${CMAKE_SOURCE_DIR}/src 
            ${CMAKE_SOURCE_DIR}/src/qtapp
            ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        )
        
        # Explicitly apply GPU backend definitions
        if(CUDAToolkit_FOUND)
            target_compile_definitions(simple_gpu_test PRIVATE HAVE_CUDA=1)
        endif()
        if(hip_FOUND OR HIPCC_EXECUTABLE)
            target_compile_definitions(simple_gpu_test PRIVATE HAVE_HIP=1)
        endif()
        if(Vulkan_FOUND)
            target_compile_definitions(simple_gpu_test PRIVATE HAVE_VULKAN=1)
        endif()
        
        set_target_properties(simple_gpu_test PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        
        # ---------- GPU Inference Benchmark: Real GGUF model performance test ----------
        add_executable(gpu_inference_benchmark
            src/qtapp/gpu_inference_benchmark.cpp
            src/qtapp/inference_engine.cpp
            src/qtapp/gguf_loader.cpp
            src/gguf_loader.cpp
            src/gguf_vocab_resolver.cpp  # Universal vocab size detection
            src/qtapp/transformer_inference.cpp
            src/qtapp/bpe_tokenizer.cpp
            src/qtapp/sentencepiece_tokenizer.cpp
            src/qtapp/vocabulary_loader.cpp
            src/qtapp/gpu_backend.cpp
            src/qtapp/metrics_collector.cpp
            src/qtapp/quant_utils.cpp
        )
        
        target_link_libraries(gpu_inference_benchmark PRIVATE
            Qt6::Core
            brutal_compression_lib
            ${GPU_BACKEND_LIBS}
        )
        
        if(TARGET ggml)
            target_link_libraries(gpu_inference_benchmark PRIVATE ggml)
        endif()
        
        if(Vulkan_FOUND)
            target_link_libraries(gpu_inference_benchmark PRIVATE Vulkan::Vulkan)
            target_compile_definitions(gpu_inference_benchmark PRIVATE HAVE_VULKAN=1)
        endif()
        
        target_include_directories(gpu_inference_benchmark PRIVATE 
            include 
            ${CMAKE_SOURCE_DIR}/src 
            ${CMAKE_SOURCE_DIR}/src/qtapp
            ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        )
        
        set_target_properties(gpu_inference_benchmark PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        
        # ---------- Minimal Qt Test ----------
        add_executable(minimal_qt_test
            src/minimal_qt_test.cpp
        )
        
        target_link_libraries(minimal_qt_test PRIVATE 
            Qt6::Core
            Qt6::Gui
            Qt6::Widgets
        )
        
        target_include_directories(minimal_qt_test PRIVATE 
            include 
            ${CMAKE_SOURCE_DIR}/src 
            ${CMAKE_SOURCE_DIR}/src/qtapp
            ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        )
        
        set_target_properties(minimal_qt_test PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        
        # ---------- GGUF Hotpatch Tester: Command-line tool for real hotpatch testing ----------
        add_executable(gguf_hotpatch_tester
            src/qtapp/gguf_hotpatch_tester.cpp
            src/qtapp/inference_engine.cpp
            src/qtapp/gguf_loader.cpp
            src/gguf_loader.cpp
            src/gguf_vocab_resolver.cpp  # Universal vocab size detection
            src/qtapp/transformer_inference.cpp
            src/qtapp/bpe_tokenizer.cpp
            src/qtapp/sentencepiece_tokenizer.cpp
            src/qtapp/vocabulary_loader.cpp
            src/qtapp/gpu_backend.cpp
            src/qtapp/metrics_collector.cpp
            src/qtapp/quant_utils.cpp
        )
        
        target_link_libraries(gguf_hotpatch_tester PRIVATE
            Qt6::Core
            brutal_compression_lib
            ${GPU_BACKEND_LIBS}
        )
        
        if(TARGET ggml)
            target_link_libraries(gguf_hotpatch_tester PRIVATE ggml)
        endif()
        
        if(Vulkan_FOUND)
            target_link_libraries(gguf_hotpatch_tester PRIVATE Vulkan::Vulkan)
            target_compile_definitions(gguf_hotpatch_tester PRIVATE HAVE_VULKAN=1)
        endif()
        
        target_include_directories(gguf_hotpatch_tester PRIVATE 
            include 
            ${CMAKE_SOURCE_DIR}/src 
            ${CMAKE_SOURCE_DIR}/src/qtapp
            ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        )
        
        set_target_properties(gguf_hotpatch_tester PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        
        # ---------- Test Chat Streaming: Console streaming chat test ----------
        add_executable(test_chat_streaming
            src/qtapp/test_chat_streaming.cpp
            src/qtapp/inference_engine.cpp
            src/qtapp/gguf_loader.cpp
            src/gguf_loader.cpp
            src/gguf_vocab_resolver.cpp  # Universal vocab size detection
            src/qtapp/transformer_inference.cpp
            src/qtapp/bpe_tokenizer.cpp
            src/qtapp/sentencepiece_tokenizer.cpp
            src/qtapp/vocabulary_loader.cpp
            src/qtapp/gpu_backend.cpp
            src/qtapp/metrics_collector.cpp
            src/qtapp/quant_utils.cpp
        )
        
        target_link_libraries(test_chat_streaming PRIVATE
            Qt6::Core
            Qt6::Gui
            Qt6::Widgets
            brutal_compression_lib
            ${GPU_BACKEND_LIBS}
        )
        
        if(TARGET ggml)
            target_link_libraries(test_chat_streaming PRIVATE ggml)
        endif()
        
        if(Vulkan_FOUND)
            target_link_libraries(test_chat_streaming PRIVATE Vulkan::Vulkan)
            target_compile_definitions(test_chat_streaming PRIVATE HAVE_VULKAN=1)
        endif()
        
        target_include_directories(test_chat_streaming PRIVATE 
            include 
            ${CMAKE_SOURCE_DIR}/src 
            ${CMAKE_SOURCE_DIR}/src/qtapp
            ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        )
        
        set_target_properties(test_chat_streaming PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        
        # ---------- RawrXD-Agent: Autonomous coding agent executable ----------
        add_executable(RawrXD-Agent
            src/agent/agent_main.cpp
            src/agent/planner.cpp
            src/agent/self_patch.cpp
            src/agent/sign_binary.cpp
            src/agent/release_agent.cpp
            src/agent/meta_learn.cpp
            src/agent/hot_reload.cpp
        )
        
        target_link_libraries(RawrXD-Agent PRIVATE 
            Qt6::Core 
            Qt6::Network
            Qt6::Concurrent
            Qt6::Sql
            self_test_gate
        )
        
        target_include_directories(RawrXD-Agent PRIVATE 
            include 
            ${CMAKE_SOURCE_DIR}/src 
            ${CMAKE_SOURCE_DIR}/src/agent
            ${CMAKE_SOURCE_DIR}/src/orchestration
            ${CMAKE_SOURCE_DIR}/src/git
            ${CMAKE_SOURCE_DIR}/src/terminal
        )
        
        set_target_properties(RawrXD-Agent PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
            WIN32_EXECUTABLE FALSE
        )
        
        if(MSVC)
            target_compile_options(RawrXD-Agent PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
        else()
            target_compile_options(RawrXD-Agent PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
        endif()
        
        message(STATUS "RawrXD-Agent: Autonomous coding agent enabled")

        # ============================================================
        # RawrXD-Compiler: Full CLI Compiler Tool
        # Compiles Eon/ASM source code to native executables
        # Supports: x86-64, x86-32, ARM64, WASM targets
        # Output: exe, dll, lib, obj, asm, ir formats
        # ============================================================
        if(EXISTS "${CMAKE_SOURCE_DIR}/src/cli/rawrxd_cli_compiler.cpp")
            add_executable(RawrXD-Compiler
                src/cli/rawrxd_cli_compiler.cpp
            )
            target_link_libraries(RawrXD-Compiler PRIVATE
                Qt6::Core
                Qt6::Widgets
                Qt6::Network
                Qt6::Concurrent
            )
            target_include_directories(RawrXD-Compiler PRIVATE
                include
                ${CMAKE_SOURCE_DIR}/src
                ${CMAKE_SOURCE_DIR}/src/compiler
            )
            set_target_properties(RawrXD-Compiler PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
                WIN32_EXECUTABLE FALSE
                OUTPUT_NAME "rawrxd"
            )
            if(MSVC)
                target_compile_options(RawrXD-Compiler PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
            else()
                target_compile_options(RawrXD-Compiler PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
            endif()
            message(STATUS "RawrXD-Compiler: CLI compiler tool enabled (output: rawrxd.exe)")
        else()
            list(APPEND RAWRXD_QT_TARGETS RawrXD-Compiler)
            message(STATUS "RawrXD-Compiler EXCLUDED: src/cli/rawrxd_cli_compiler.cpp absent from this tree")
        endif()

        # ============================================================
        # RawrXD Compiler Library: Qt-integrated compiler for IDE use
        # ============================================================
        if(EXISTS "${CMAKE_SOURCE_DIR}/src/compiler/rawrxd_compiler_qt.cpp")
            add_library(rawrxd_compiler_qt STATIC
                src/compiler/rawrxd_compiler_qt.cpp
            )
            target_link_libraries(rawrxd_compiler_qt PUBLIC
                Qt6::Core
                Qt6::Widgets
                Qt6::Concurrent
            )
            target_include_directories(rawrxd_compiler_qt PUBLIC
                ${CMAKE_SOURCE_DIR}/src/compiler
                ${CMAKE_SOURCE_DIR}/include
            )
            if(MSVC)
                target_compile_options(rawrxd_compiler_qt PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
            else()
                target_compile_options(rawrxd_compiler_qt PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
            endif()
            set_target_properties(rawrxd_compiler_qt PROPERTIES AUTOMOC ON)
            message(STATUS "rawrxd_compiler_qt: Qt compiler library enabled")

            # Add the MASM writers (present in some trees only)
            if(EXISTS "${CMAKE_SOURCE_DIR}/src/masm/CMakeLists.txt")
                add_subdirectory(src/masm)
                if(TARGET rawrxd_compiler_qt)
                    target_link_libraries(rawrxd_compiler_qt PRIVATE masm_writers)
                endif()
                if(TARGET RawrXD-Compiler)
                    target_link_libraries(RawrXD-Compiler PRIVATE masm_writers)
                endif()
            else()
                list(APPEND RAWRXD_QT_TARGETS masm_writers)
                message(STATUS "masm_writers EXCLUDED: src/masm/CMakeLists.txt not present in this tree")
            endif()
        else()
            list(APPEND RAWRXD_QT_TARGETS rawrxd_compiler_qt)
            message(STATUS "rawrxd_compiler_qt EXCLUDED: src/compiler/rawrxd_compiler_qt.cpp absent from this tree")
        endif()
    else()
        message(STATUS "Qt6 not found, skipping RawrXD-QtShell")
    endif()
else()
    message(STATUS "MSVC not detected; skipping Qt6 targets to avoid MinGW/MSVC mismatch")
endif()

# Win32-based IDE (MSVC only to match Qt)
if(MSVC AND RAWRXD_BUILD_WIN32IDE_QT AND Qt6_FOUND)
            if(EXISTS "${CMAKE_SOURCE_DIR}/src/win32app/Win32IDE_CopilotIntegration.cpp")
        add_executable(RawrXD-Win32IDE 
                src/win32app/main_win32.cpp
                src/win32app/Win32IDE.cpp
                src/win32app/Win32IDE.h
                src/win32app/Win32IDE_Sidebar.cpp
                src/win32app/Win32IDE_VSCodeUI.cpp
                src/win32app/Win32IDE_PowerShellPanel.cpp
                src/win32app/Win32IDE_PowerShell.cpp
                src/win32app/Win32IDE_Logger.cpp
                src/win32app/TransparentRenderer.cpp
                src/win32app/TransparentRenderer.h
                src/win32app/Win32TerminalManager.cpp
                src/win32app/Win32TerminalManager.h
                src/win32app/Win32IDE_FileOps.cpp
                src/win32app/Win32IDE_Commands.cpp
                src/win32app/Win32IDE_Debugger.cpp
                src/win32app/Win32IDE_AgenticBridge.h
                src/win32app/Win32IDE_AgenticBridge.cpp
                src/win32app/Win32IDE_AgentCommands.cpp
                src/win32app/Win32IDE_Autonomy.h
                src/win32app/Win32IDE_Autonomy.cpp
                src/gguf_loader.cpp
                src/gguf_vocab_resolver.cpp
                src/streaming_gguf_loader.cpp
                src/utils/ErrorReporter.cpp
                src/utils/Diagnostics.cpp
                # Benchmark menu integration (headers required for Q_OBJECT moc)
                include/benchmark_menu_widget.hpp
                include/benchmark_runner.hpp
                src/benchmark_menu_widget.cpp
                src/benchmark_runner.cpp
                $<$<BOOL:${ENABLE_VULKAN}>:src/win32app/VulkanRenderer.cpp>
                $<$<BOOL:${ENABLE_COPILOT}>:src/win32app/Win32IDE_CopilotIntegration.cpp>
                $<$<BOOL:${ENABLE_COPILOT}>:src/win32app/CopilotStreaming.cpp>
                # Agentic navigation integration
                src/agentic/AgenticNavigator.cpp
                src/agentic/AgenticCopilotIntegration.cpp
                # Qt-based IDE Main Window
                src/ide_main_window.h
                src/ide_main_window.cpp
                src/autonomous_widgets.h
                src/autonomous_widgets.cpp
                # Model Router Components
                # Universal Model Router Integration (Cloud AI + Local GGUF)
                src/universal_model_router.cpp
                src/cloud_api_client.cpp
                src/model_interface.cpp
                # Model Router Qt Adapter for IDE Integration
                src/model_router_adapter.h
                src/model_router_adapter.cpp
                # Model Router GUI Widget
                src/model_router_widget.h
                src/model_router_widget.cpp
                # Cloud Settings Dialog
                src/cloud_settings_dialog.h
                src/cloud_settings_dialog.cpp
                # Metrics Dashboard
                src/metrics_dashboard.h
                src/metrics_dashboard.cpp
                # Model Router Console
                src/model_router_console.h
                src/model_router_console.cpp
                # Autonomous IDE Components (missing implementations for linker)
                src/autonomous_model_manager.cpp
                src/autonomous_feature_engine.cpp
                src/intelligent_codebase_engine.cpp
                src/hybrid_cloud_manager.cpp
                src/error_recovery_system.cpp
                src/performance_monitor.cpp
                # Real-time completion and inference
                src/real_time_completion_engine.cpp
                src/qtapp/inference_engine.cpp
                # Additional tokenizer/inference support
                src/qtapp/bpe_tokenizer.cpp
                src/qtapp/sentencepiece_tokenizer.cpp
                src/qtapp/vocabulary_loader.cpp
                src/qtapp/transformer_inference.cpp
                src/qtapp/gguf_loader.cpp
            )
    else()
        list(APPEND RAWRXD_QT_TARGETS RawrXD-Win32IDE)
        message(STATUS "RawrXD-Win32IDE EXCLUDED: sources absent from this tree (src/win32app/Win32IDE_CopilotIntegration.cpp, src/win32app/CopilotStreaming.cpp)")
    endif()

    if(TARGET RawrXD-Win32IDE)
        target_link_libraries(RawrXD-Win32IDE PRIVATE
            d3d11
            dxgi
            dcomp
            dwmapi
            d2d1
            dwrite
            d3dcompiler
            winhttp
            shlwapi
            shell32
            RawrXDOrchestration
            RawrXDGit
            RawrXDTerminal
            brutal_compression_lib
            quant_utils
            Qt6::Core
            Qt6::Network
            Qt6::Widgets
            Qt6::Charts
        )
    
    # Add include dir first to pick up our d3d10effect.h and ggml.h stubs before system SDK
    target_include_directories(RawrXD-Win32IDE BEFORE PRIVATE 
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/utils
        ${CMAKE_SOURCE_DIR}/src/model_loader
        ${CMAKE_SOURCE_DIR}/src/qtapp
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/src
    )
    
    # Link ggml if available
    if(TARGET ggml)
        target_link_libraries(RawrXD-Win32IDE PRIVATE ggml)
        target_compile_definitions(RawrXD-Win32IDE PRIVATE HAVE_GGML=1)
    endif()

    # Production-hardening runtime. Qt6::link finds the dependency, so this is
    # linked unconditionally for both IDE flavours, matching the native target.
    if(TARGET rawrxd_production_hardening)
        target_link_libraries(RawrXD-Win32IDE PRIVATE
            rawrxd_production_hardening
        )
        target_include_directories(RawrXD-Win32IDE PRIVATE
            ${CMAKE_SOURCE_DIR}/src/production
        )
    endif()
    
    # Compiler options - MSVC only now
    target_compile_options(RawrXD-Win32IDE PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
    
    # Force MBCS/ANSI build to avoid Unicode string conversion issues
    target_compile_definitions(RawrXD-Win32IDE PRIVATE _MBCS)
    
    set_target_properties(RawrXD-Win32IDE PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        WIN32_EXECUTABLE TRUE
    )
    if(ENABLE_VULKAN)
        target_compile_definitions(RawrXD-Win32IDE PRIVATE ENABLE_VULKAN=1)
    endif()
    if(ENABLE_COPILOT)
        target_compile_definitions(RawrXD-Win32IDE PRIVATE ENABLE_COPILOT=1)
        message(STATUS "Copilot integration enabled for Win32 IDE")
    endif()
    endif()
else()
    list(APPEND RAWRXD_QT_TARGETS RawrXD-Win32IDE)
    message(STATUS "RawrXD-Win32IDE excluded (Qt6 unavailable or RAWRXD_BUILD_WIN32IDE_QT=OFF)")
endif() # End RAWRXD_BUILD_WIN32IDE_QT block

# ============================================================================
# Universal GGUF probe (model-agnostic Deep2 integration)
# ============================================================================
# Discovers every model installed in the local ollama store, parses each blob
# architecturally (any arch, any ggml quant, any tensor layout) and runs a real
# ggml op on the model's own weights - so Deep2 works regardless of model.
find_package(Vulkan QUIET)
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/gguf_universal_probe.cpp")
    add_executable(gguf_universal_probe tools/gguf_universal_probe.cpp)
    target_include_directories(gguf_universal_probe PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        $ENV{VULKAN_SDK}/Include
    )
    if(TARGET ggml_interface)
        target_link_libraries(gguf_universal_probe PRIVATE ggml_interface)
    endif()
    if(MSVC)
        target_compile_options(gguf_universal_probe PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(gguf_universal_probe PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(gguf_universal_probe PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "gguf_universal_probe enabled (any-model GGUF integration)")
endif()

# ============================================================================
# Deep2 per-token performance profiler (native, dependency-free)
# ============================================================================
# First move of the 5x throughput program (128.78 -> 643.90 TPS on Nemotron
# 30B MoE): profile the real per-token decode path before optimizing. Reports
# per-phase ms/token, weight bandwidth, dominant phase. No Qt, no external deps.
# gguf_loader.h pulls in vulkan_compute.h, so the Vulkan SDK include path is
# required (it is discovered here, not hardcoded).
find_package(Vulkan QUIET)
# The repo's include/ ships a vulkan/vulkan.h STUB (no vk* entry points), which
# FindVulkan is happy to resolve. Point the target at the real SDK instead:
# VULKAN_SDK (set by the SDK installer) wins over the discovered stub path.
set(_rawrxd_vk_sdk_inc "$ENV{VULKAN_SDK}/Include")
if(NOT EXISTS "${_rawrxd_vk_sdk_inc}/vulkan/vulkan.h")
    set(_rawrxd_vk_sdk_inc "${Vulkan_INCLUDE_DIRS}")
endif()
if(NOT EXISTS "${_rawrxd_vk_sdk_inc}/vulkan/vulkan.h")
    set(_rawrxd_vk_sdk_inc "")
endif()
message(STATUS "profiler gate: Vulkan_FOUND=${Vulkan_FOUND} vulkan_include='${_rawrxd_vk_sdk_inc}'")
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_token_profiler.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_token_profiler
        tools/deep2_token_profiler.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
        src/utils/Diagnostics.cpp
        src/utils/input_sanitizer.cpp
    )
    target_include_directories(deep2_token_profiler PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${_rawrxd_vk_sdk_inc}
    )
    # The GGUF loader chain includes vulkan_compute.h -> vulkan/vulkan.h, which
    # comes from the real Vulkan SDK (see _rawrxd_vk_sdk_inc above) - ggml itself
    # is linked through ggml_interface and needs no extra include path.
    if(TARGET ggml_interface)
        target_link_libraries(deep2_token_profiler PRIVATE ggml_interface)
    endif()
    if(MSVC)
        target_compile_options(deep2_token_profiler PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_token_profiler PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(deep2_token_profiler PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_token_profiler enabled (ggml + Vulkan SDK)")
else()
    message(STATUS "deep2_token_profiler EXCLUDED: profiler source or Vulkan SDK not available")
endif()

# Gate 4 — native forward dispatch audit.
#
# Registered inside the SAME Vulkan guard as deep2_token_profiler, with the same
# conventions, because this auditor had no CMake target at all: its source exists
# (tools/deep2_parity_trace.cpp, implements --gate4 <cpu|gpu>) but nothing
# registered it, so `cmake --build --target help` did not list it and the only
# way anyone had run it was a hand-rolled cl command. A gate that cannot be
# reproduced through the build system is not CI-enforceable and cannot be
# certified, regardless of what a direct compile previously produced.
#
# The guard is deliberately the same one that gates the sibling: --gate4 gpu
# requires the Vulkan SDK include path, and on a machine without it the target
# must be EXCLUDED with a message rather than silently building a GPU-less
# auditor and letting a missing Vulkan path look like a certification pass.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_parity_trace.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_parity_trace
        tools/deep2_parity_trace.cpp
        src/deep2/runtime_graph_executor.cpp
        src/deep2/generic_vulkan_matmul.cpp
        src/deep2/vulkan_compute.cpp
        src/deep2/QuantKernelRegistry.cpp
        src/deep2/asm_stubs.cpp
        src/deep2/op_linear.cpp
        src/deep2/op_gdn.cpp
        src/deep2/modelgenie/universal_gguf.cpp
        # RAWRXD_GATE4_LINK_001: the QuantDot implementation layer and the
        # Vulkan engine it drives. The dispatch layer's five entry points
        # (DotBlocked, DotF16, BeginBatch, EndBatch, LastReceipt) are DEFINED
        # in src/deep2/quant_dot_dispatch.cpp - it is not a generated stub -
        # and it calls the ::VulkanCompute GPU execution path DEFINED in
        # src/vulkan_compute.cpp. Without both translation units the target
        # links with LNK2019 on exactly those five QuantDot symbols, because
        # runtime_graph_executor.cpp and op_linear.cpp are their only callers
        # in this target. These are the identical translation units the
        # hand-rolled tools/build_deep2_parity_trace.bat compiles, so the
        # CMake target and the bat now share ONE definition of the build.
        src/deep2/quant_dot_dispatch.cpp
        src/vulkan_compute.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
        src/utils/Diagnostics.cpp
        src/utils/input_sanitizer.cpp
    )
    target_include_directories(deep2_parity_trace PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tools
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET ggml_interface)
        target_link_libraries(deep2_parity_trace PRIVATE ggml_interface)
    endif()
    # The Vulkan loader library (vulkan-1.lib): src/vulkan_compute.cpp invokes
    # the vk* entry points directly, and the GPU-native audit is required to
    # reach a real device rather than a CPU substitute.
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_parity_trace PRIVATE Vulkan::Vulkan)
    endif()
    if(TARGET ggml-vulkan)
        target_link_libraries(deep2_parity_trace PRIVATE ggml-vulkan)
    endif()
    if(MSVC)
        target_compile_options(deep2_parity_trace PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_parity_trace PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(deep2_parity_trace PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_parity_trace enabled (Gate 4 dispatch audit; ggml + Vulkan SDK)")
else()
    message(STATUS "deep2_parity_trace EXCLUDED: auditor source or Vulkan SDK unavailable - "
                   "Gate 4 GPU audit will be SKIPPED_UNSUPPORTED, never PASS")
endif()

# Full-model certification runner.  This is intentionally a separate target
# from the metadata probes: it binds the complete runtime graph, executes the
# supplied token sequence, and compares the full vocabulary logits on the GPU
# and CPU-pinned paths.  A build or metadata pass must never be reported as a
# full-model certification result.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_gpu_certify.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_gpu_certify
        tools/deep2_gpu_certify.cpp
        src/deep2/op_gdn.cpp
        src/deep2/runtime_graph_executor.cpp
        src/deep2/generic_vulkan_matmul.cpp
        src/deep2/op_linear.cpp
        src/deep2/modelgenie/universal_gguf.cpp
        src/deep2/quant_dot_dispatch.cpp
        # The executor's stateful GDN path uses the Deep2 VulkanCompute
        # implementation (separate from the legacy quant-dot wrapper below).
        # Keep both translation units: quant_dot_dispatch.cpp intentionally
        # binds the canonical root VulkanCompute, while GDN state ownership
        # and ResetGdnState live in src/deep2/vulkan_compute.cpp.
        src/deep2/vulkan_compute.cpp
        src/deep2/QuantKernelRegistry.cpp
        src/deep2/asm_stubs.cpp
        src/vulkan_compute.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
        src/utils/Diagnostics.cpp
        src/utils/input_sanitizer.cpp
    )
    target_include_directories(deep2_gpu_certify PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tools
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET ggml_interface)
        target_link_libraries(deep2_gpu_certify PRIVATE ggml_interface)
    endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_gpu_certify PRIVATE Vulkan::Vulkan)
    endif()
    if(TARGET ggml-vulkan)
        target_link_libraries(deep2_gpu_certify PRIVATE ggml-vulkan)
    endif()
    if(MSVC)
        target_compile_options(deep2_gpu_certify PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_gpu_certify PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(deep2_gpu_certify PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS
        DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
    )
    set_target_properties(deep2_gpu_certify PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_gpu_certify enabled (full-model GPU/CPU logits certification)")
else()
    message(STATUS "deep2_gpu_certify EXCLUDED: source or Vulkan SDK unavailable")
endif()

# Native Qwen4Exp reverse-engineering contract extractor.  This target is
# intentionally dependency-free and read-only: it audits real shard manifests
# before any operator is lowered into the executable Vulkan graph.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_reverse_engineer.cpp")
    add_executable(deep2_reverse_engineer tools/deep2_reverse_engineer.cpp)
    target_compile_features(deep2_reverse_engineer PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_reverse_engineer PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_reverse_engineer PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(deep2_reverse_engineer PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    message(STATUS "deep2_reverse_engineer enabled (native Qwen4Exp contract audit)")
endif()

# GDN lowering contract and independent state-continuity harness.  This target
# intentionally stops at reference arithmetic; it must not be treated as GPU
# execution or Qwen4Exp certification until a production descriptor path owns
# the shader dispatch and an independent model trace passes.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_gdn_parity_harness.cpp")
    add_executable(deep2_gdn_parity_harness
        tools/deep2_gdn_parity_harness.cpp
        src/deep2/op_gdn.cpp)
    target_include_directories(deep2_gdn_parity_harness PRIVATE
        ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR})
    target_compile_features(deep2_gdn_parity_harness PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_gdn_parity_harness PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_gdn_parity_harness PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(deep2_gdn_parity_harness PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    add_test(NAME deep2_gdn_reference_contract
        COMMAND deep2_gdn_parity_harness)
    message(STATUS "deep2_gdn_parity_harness enabled (reference-only GDN contract)")
endif()

find_program(GLSLC_EXECUTABLE NAMES glslc
    HINTS "$ENV{VULKAN_SDK}/Bin" "$ENV{VULKAN_SDK}/bin")
if(EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/shaders/deep2_qwen4exp_gdn.comp" AND GLSLC_EXECUTABLE)
    add_custom_command(
        OUTPUT "${CMAKE_SOURCE_DIR}/src/deep2/shaders/deep2_qwen4exp_gdn.spv"
        COMMAND ${GLSLC_EXECUTABLE}
            "${CMAKE_SOURCE_DIR}/src/deep2/shaders/deep2_qwen4exp_gdn.comp"
            -o "${CMAKE_SOURCE_DIR}/src/deep2/shaders/deep2_qwen4exp_gdn.spv"
        DEPENDS "${CMAKE_SOURCE_DIR}/src/deep2/shaders/deep2_qwen4exp_gdn.comp"
        COMMENT "Compiling Qwen4Exp GDN shader")
    add_custom_target(deep2_qwen4exp_gdn_shader ALL
        DEPENDS "${CMAKE_SOURCE_DIR}/src/deep2/shaders/deep2_qwen4exp_gdn.spv")
endif()

if(GLSLC_EXECUTABLE)
    # Quant GEMV is intentionally specialized by format.  Keeping one
    # runtime type-switch shader forces the register allocator and control
    # flow to pay for the worst Q6 path on every invocation.  This target
    # compiles every supported packed format and fails the build immediately
    # if glslc cannot produce an artifact (never mask stderr/exit status).
    set(_rawrxd_quant_specialized_outputs)
    foreach(_tile row4 row8)
        foreach(_quant_kind q4k=0 q6k=1 q2k=5 q3k=6 q5k=8)
            string(REPLACE "=" ";" _kind_pair "${_quant_kind}")
            list(GET _kind_pair 0 _kind_name)
            list(GET _kind_pair 1 _kind_id)
            set(_quant_src "${CMAKE_SOURCE_DIR}/tools/shaders/quant_dot_${_tile}.comp")
            set(_quant_out "${CMAKE_SOURCE_DIR}/tools/shaders/quant_dot_${_tile}_${_kind_name}_specialized.spv")
            add_custom_command(
                OUTPUT "${_quant_out}"
                COMMAND ${GLSLC_EXECUTABLE} -O --target-env=vulkan1.2
                    "-DDEEP2_SPECIALIZED_KIND=${_kind_id}"
                    "${_quant_src}" -o "${_quant_out}"
                DEPENDS "${_quant_src}"
                VERBATIM
                COMMENT "Compiling specialized ${_tile} ${_kind_name} quant GEMV")
            list(APPEND _rawrxd_quant_specialized_outputs "${_quant_out}")
        endforeach()
    endforeach()
    add_custom_target(deep2_quant_specialized_shaders ALL
        DEPENDS ${_rawrxd_quant_specialized_outputs})

    set(_rawrxd_qwen4exp_operator_shader_sources
        deep2_qwen4exp_ple
        deep2_qwen4exp_hc_combine
        deep2_qwen4exp_qsa_score
        deep2_qwen4exp_moe_router)
    set(_rawrxd_qwen4exp_operator_shader_outputs)
    foreach(_shader ${_rawrxd_qwen4exp_operator_shader_sources})
        add_custom_command(
            OUTPUT "${CMAKE_SOURCE_DIR}/src/deep2/shaders/${_shader}.spv"
            COMMAND ${GLSLC_EXECUTABLE}
                "${CMAKE_SOURCE_DIR}/src/deep2/shaders/${_shader}.comp"
                -o "${CMAKE_SOURCE_DIR}/src/deep2/shaders/${_shader}.spv"
            DEPENDS "${CMAKE_SOURCE_DIR}/src/deep2/shaders/${_shader}.comp"
            COMMENT "Compiling Qwen4Exp ${_shader} shader")
        list(APPEND _rawrxd_qwen4exp_operator_shader_outputs
            "${CMAKE_SOURCE_DIR}/src/deep2/shaders/${_shader}.spv")
    endforeach()
    add_custom_target(deep2_qwen4exp_operator_shaders ALL
        DEPENDS ${_rawrxd_qwen4exp_operator_shader_outputs})
endif()

# CPU operator contract harness. It exercises the exact Qwen4Exp geometry for
# PLE, hyperconnections, QSA scoring/selection, and sparse-MoE routing. Expert
# execution remains fail-closed until IQ2_S/MXFP4 dequantization is certified.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_qwen4exp_operator_harness.cpp")
    add_executable(deep2_qwen4exp_operator_harness
        tools/deep2_qwen4exp_operator_harness.cpp
        src/deep2/op_ple.cpp
        src/deep2/op_hyperconnection.cpp
        src/deep2/op_qsa.cpp
        src/deep2/op_sparse_moe.cpp)
    target_include_directories(deep2_qwen4exp_operator_harness PRIVATE
        ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR})
    target_compile_features(deep2_qwen4exp_operator_harness PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_qwen4exp_operator_harness PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_qwen4exp_operator_harness PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(deep2_qwen4exp_operator_harness PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    add_test(NAME deep2_qwen4exp_operator_contract
        COMMAND deep2_qwen4exp_operator_harness)
    message(STATUS "deep2_qwen4exp_operator_harness enabled (PLE/HC/QSA/MoE contracts)")
endif()

# Physical Vulkan topology telemetry. This target reports real device heaps and
# queues only; it is deliberately separate from the certifier and never claims
# an operator allocation or execution.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_dynamic_interceptor.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_dynamic_interceptor tools/deep2_dynamic_interceptor.cpp)
    target_include_directories(deep2_dynamic_interceptor PRIVATE ${_rawrxd_vk_sdk_inc})
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_dynamic_interceptor PRIVATE Vulkan::Vulkan)
    endif()
    target_compile_features(deep2_dynamic_interceptor PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_dynamic_interceptor PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_dynamic_interceptor PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(deep2_dynamic_interceptor PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    message(STATUS "deep2_dynamic_interceptor enabled (real Vulkan topology telemetry)")
endif()

# Qwen4Exp shader-to-Vulkan wiring probe. It creates real PLE and
# Hyperconnection pipeline objects but submits no inference work.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_qwen4exp_pipeline_probe.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_qwen4exp_pipeline_probe tools/deep2_qwen4exp_pipeline_probe.cpp)
    target_include_directories(deep2_qwen4exp_pipeline_probe PRIVATE ${_rawrxd_vk_sdk_inc})
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_qwen4exp_pipeline_probe PRIVATE Vulkan::Vulkan)
    endif()
    target_compile_features(deep2_qwen4exp_pipeline_probe PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_qwen4exp_pipeline_probe PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_qwen4exp_pipeline_probe PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(deep2_qwen4exp_pipeline_probe PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    message(STATUS "deep2_qwen4exp_pipeline_probe enabled (physical shader wiring)" )
endif()

# Real isolated GDN execution probe. This allocates synthetic Qwen4Exp-shaped
# buffers, submits one Vulkan dispatch, and compares output plus recurrent state
# against the independent CPU reference. It is an operator certificate only;
# it never advances the Qwen4Exp full-model gate.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_qwen4exp_gdn_probe.cpp" AND
   EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/op_gdn.cpp" AND
   Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_qwen4exp_gdn_probe
        tools/deep2_qwen4exp_gdn_probe.cpp
        src/deep2/op_gdn.cpp)
    target_include_directories(deep2_qwen4exp_gdn_probe PRIVATE
        ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR} ${_rawrxd_vk_sdk_inc})
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_qwen4exp_gdn_probe PRIVATE Vulkan::Vulkan)
    endif()
    target_compile_features(deep2_qwen4exp_gdn_probe PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_qwen4exp_gdn_probe PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_qwen4exp_gdn_probe PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    if(TARGET deep2_qwen4exp_gdn_shader)
        add_dependencies(deep2_qwen4exp_gdn_probe deep2_qwen4exp_gdn_shader)
    endif()
    set_target_properties(deep2_qwen4exp_gdn_probe PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    message(STATUS "deep2_qwen4exp_gdn_probe enabled (real isolated GDN dispatch)")
endif()

# Real isolated GPU probes for the remaining Qwen4Exp scalar operators. These
# use bounded synthetic buffers and independent CPU contracts; they do not
# admit the full model or alter the production executor's fail-closed boundary.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_qwen4exp_operator_probe.cpp" AND
   EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/op_ple.cpp" AND
   Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_qwen4exp_operator_probe
        tools/deep2_qwen4exp_operator_probe.cpp
        src/deep2/op_ple.cpp
        src/deep2/op_hyperconnection.cpp
        src/deep2/op_qsa.cpp
        src/deep2/op_sparse_moe.cpp)
    target_include_directories(deep2_qwen4exp_operator_probe PRIVATE
        ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR} ${_rawrxd_vk_sdk_inc})
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_qwen4exp_operator_probe PRIVATE Vulkan::Vulkan)
    endif()
    target_compile_features(deep2_qwen4exp_operator_probe PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_qwen4exp_operator_probe PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_qwen4exp_operator_probe PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    if(TARGET deep2_qwen4exp_operator_shaders)
        add_dependencies(deep2_qwen4exp_operator_probe deep2_qwen4exp_operator_shaders)
    endif()
    set_target_properties(deep2_qwen4exp_operator_probe PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    add_test(NAME deep2_qwen4exp_operator_gpu_probe
        COMMAND deep2_qwen4exp_operator_probe
            "${CMAKE_SOURCE_DIR}/src/deep2/shaders/")
    message(STATUS "deep2_qwen4exp_operator_probe enabled (PLE/HC/QSA/router GPU dispatch)")
endif()

# Canonical GGML Vulkan quantization probe.  Deep2's hand-written quant-dot
# shader intentionally remains limited to its certified Q2/Q4/Q6 layouts;
# this target proves that the bundled GGML Vulkan backend can execute the
# Qwen4Exp expert formats (IQ2_S and MXFP4) without a CPU expansion.  It is a
# prerequisite for production MoE lowering, not a full-model certificate.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_generic_vulkan_quant_probe.cpp" AND
   EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND
   Vulkan_FOUND AND _rawrxd_vk_sdk_inc AND TARGET ggml-vulkan)
    add_executable(deep2_generic_vulkan_quant_probe
        tools/deep2_generic_vulkan_quant_probe.cpp
        src/deep2/generic_vulkan_matmul.cpp)
    target_include_directories(deep2_generic_vulkan_quant_probe PRIVATE
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        ${_rawrxd_vk_sdk_inc})
    target_link_libraries(deep2_generic_vulkan_quant_probe PRIVATE
        ggml-vulkan ggml)
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_generic_vulkan_quant_probe PRIVATE Vulkan::Vulkan)
    endif()
    target_compile_features(deep2_generic_vulkan_quant_probe PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_generic_vulkan_quant_probe PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_generic_vulkan_quant_probe PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(deep2_generic_vulkan_quant_probe PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    add_test(NAME deep2_generic_vulkan_quant_probe
        COMMAND deep2_generic_vulkan_quant_probe)
    message(STATUS "deep2_generic_vulkan_quant_probe enabled (canonical IQ2_S/MXFP4 GPU path)")
endif()

# Enterprise source-to-parity closure manifest.  This read-only target hashes
# the reverse-engineered contract, executor boundary, shader source/SPIR-V,
# pipeline probe, and independent parity references.  It deliberately records
# command submission and full-model execution as NOT_RUN until ExecuteToken
# owns descriptor updates and real dispatches for every Qwen4Exp operator.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_enterprise_manifest.cpp")
    add_executable(deep2_enterprise_manifest tools/deep2_enterprise_manifest.cpp)
    target_compile_features(deep2_enterprise_manifest PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_enterprise_manifest PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
        target_link_libraries(deep2_enterprise_manifest PRIVATE Bcrypt)
    else()
        target_compile_options(deep2_enterprise_manifest PRIVATE -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(deep2_enterprise_manifest PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    message(STATUS "deep2_enterprise_manifest enabled (source-to-parity closure receipt)")
endif()

# Gate 7 D1 — batched multi-token prefill full-logit parity.
# RAWRXD_DEEP2_D1_PREFILL_PARITY verifies Executor::PrefillBatch against the
# serial ExecuteToken path: full-logit BIT_EXACT over a prefix sweep + causal
# KV via continued decode. Same source set as deep2_parity_trace so the
# batched path is exercised against the identical kernels the cert path uses.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_d1_prefill_parity.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_d1_prefill_parity
        tools/deep2_d1_prefill_parity.cpp
        src/deep2/runtime_graph_executor.cpp
        src/deep2/generic_vulkan_matmul.cpp
        src/deep2/op_linear.cpp
        src/deep2/modelgenie/universal_gguf.cpp
        src/deep2/quant_dot_dispatch.cpp
        src/vulkan_compute.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
        src/utils/Diagnostics.cpp
    )
    target_include_directories(deep2_d1_prefill_parity PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tools
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET ggml_interface)
        target_link_libraries(deep2_d1_prefill_parity PRIVATE ggml_interface)
    endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_d1_prefill_parity PRIVATE Vulkan::Vulkan)
    endif()
    if(TARGET ggml-vulkan)
        target_link_libraries(deep2_d1_prefill_parity PRIVATE ggml-vulkan)
    endif()
    if(MSVC)
        target_compile_options(deep2_d1_prefill_parity PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_d1_prefill_parity PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(deep2_d1_prefill_parity PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS
        DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
    )
    set_target_properties(deep2_d1_prefill_parity PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_d1_prefill_parity enabled (D1 batched-prefill parity; ggml + Vulkan SDK)")
else()
    message(STATUS "deep2_d1_prefill_parity EXCLUDED: tool source or Vulkan SDK unavailable")
endif()

# Gate 8 — Speculative Verification Benchmark (RAWRXD_DEEP2_SPEC_VERIFY_001).
#
# Measures Deep2 native batched speculative verification against the serial
# greedy decode path on a REAL GGUF, with per-workload (code/prose) acceptance
# rates. The fused LM-head path (DispatchGemvQ4KBatch) is exercised when the
# model has a Q4_K LM head and perPosLogits is requested.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_spec_bench.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_spec_bench
        tools/deep2_spec_bench.cpp
        src/deep2/runtime_graph_executor.cpp
        src/deep2/generic_vulkan_matmul.cpp
        src/deep2/op_linear.cpp
        src/deep2/modelgenie/universal_gguf.cpp
        src/deep2/quant_dot_dispatch.cpp
        src/deep2/deep2_speculative.cpp
        src/vulkan_compute.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
        src/utils/input_sanitizer.cpp
        src/utils/Diagnostics.cpp
    )
    target_include_directories(deep2_spec_bench PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tools
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET ggml_interface)
        target_link_libraries(deep2_spec_bench PRIVATE ggml_interface)
    endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_spec_bench PRIVATE Vulkan::Vulkan)
    endif()
    if(TARGET ggml-vulkan)
        target_link_libraries(deep2_spec_bench PRIVATE ggml-vulkan)
    endif()
    if(MSVC)
        target_compile_options(deep2_spec_bench PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_spec_bench PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(deep2_spec_bench PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS
        DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
    )
    set_target_properties(deep2_spec_bench PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_spec_bench enabled (Speculative verification benchmark; ggml + Vulkan SDK)")
else()
    message(STATUS "deep2_spec_bench EXCLUDED: tool source or Vulkan SDK unavailable")
endif()

# HEXMAG_PARALLEL_WORKTREE_001 — HexMag parallel swarm execution certification.
# Requires MASM (RAWR_HAS_MASM) and HexMag runtime sources.
# Note: hexmag_finalize_policy is header-only (inline); hexmag_client is not yet implemented.
if(FALSE AND EXISTS "${CMAKE_SOURCE_DIR}/~dev/rawrxd/tests/hexmag_repeat_tuner_cert.cpp" AND
   EXISTS "${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/asm/RawrXD_HexMag_RepeatTuner.asm" AND
   EXISTS "${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/asm/RawrXD_HexMag_Swarm.asm" AND
   EXISTS "${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/core/hexmag_runtime_controller.cpp" AND
   EXISTS "${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/core/hexmag_control_plane.cpp" AND
   EXISTS "${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/core/hexmag_oracle_binder.cpp")
    # Repeat tuner MASM object library
    add_library(rawrxd_hexmag_repeat OBJECT
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/asm/RawrXD_HexMag_RepeatTuner.asm
    )
    set_source_files_properties(${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/asm/RawrXD_HexMag_RepeatTuner.asm
        PROPERTIES LANGUAGE ASM_MASM)
    # Without LINKER_LANGUAGE CMake resolves the object library's language from
    # the target's first CXX source (none here) and then applies the C++ compile
    # rules to the assembler, emitting A4018 warnings for every /Zc /GS /MD flag
    # and leaving the expected .obj unproduced. Pin it to MASM.
    set_target_properties(rawrxd_hexmag_repeat PROPERTIES
        LINKER_LANGUAGE ASM_MASM
    )
    if(MSVC)
        # MASM-specific options only (no C++ options), scoped by language so they
        # can never be mirrored onto a CXX translation unit.
        target_compile_options(rawrxd_hexmag_repeat PRIVATE
            $<$<COMPILE_LANGUAGE:ASM_MASM>:/Zi /Cx /W3 /errorReport:prompt>
        )
    endif()

    # HexMag repeat tuner cert
    add_executable(hexmag_repeat_tuner_cert
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/tests/hexmag_repeat_tuner_cert.cpp
        $<TARGET_OBJECTS:rawrxd_hexmag_repeat>
    )
    target_include_directories(hexmag_repeat_tuner_cert PRIVATE
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/agentic
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src
    )
    target_compile_definitions(hexmag_repeat_tuner_cert PRIVATE RAWR_HAS_MASM=1)
    if(MSVC)
        target_compile_options(hexmag_repeat_tuner_cert PRIVATE /EHsc /W4 /std:c++20)
    endif()
    set_target_properties(hexmag_repeat_tuner_cert PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "[Agentic] HexMag repeat tuner cert: hexmag_repeat_tuner_cert")

    # HexMag IDE E2E cert (uses runtime controller, control plane, oracle binder, swarm MASM)
    add_executable(hexmag_ide_e2e_cert
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/tests/hexmag_ide_e2e_cert.cpp
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/core/hexmag_runtime_controller.cpp
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/core/hexmag_control_plane.cpp
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/core/hexmag_oracle_binder.cpp
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/asm/RawrXD_HexMag_Swarm.asm
        $<TARGET_OBJECTS:rawrxd_hexmag_repeat>
    )
    set_source_files_properties(${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/asm/RawrXD_HexMag_Swarm.asm
        PROPERTIES LANGUAGE ASM_MASM)
    target_include_directories(hexmag_ide_e2e_cert PRIVATE
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/agentic
        ${CMAKE_SOURCE_DIR}/include
    )
    target_compile_definitions(hexmag_ide_e2e_cert PRIVATE RAWR_HAS_MASM=1)
    if(MSVC)
        # C++ options for C++ sources, MASM options for MASM sources
        target_compile_options(hexmag_ide_e2e_cert PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:/EHsc /W4 /std:c++20>
            $<$<COMPILE_LANGUAGE:ASM_MASM>:/Zi /Cx /W3 /errorReport:prompt>
        )
    endif()
    set_target_properties(hexmag_ide_e2e_cert PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "[Agentic] HexMag IDE E2E cert: hexmag_ide_e2e_cert")

    # HexMag runtime controller cert (uses runtime controller, control plane, oracle binder, swarm MASM)
    add_executable(hexmag_runtime_controller_cert
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/tests/hexmag_runtime_controller_cert.cpp
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/core/hexmag_runtime_controller.cpp
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/core/hexmag_control_plane.cpp
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/core/hexmag_oracle_binder.cpp
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/asm/RawrXD_HexMag_Swarm.asm
        $<TARGET_OBJECTS:rawrxd_hexmag_repeat>
    )
    set_source_files_properties(${CMAKE_SOURCE_DIR}/~dev/rawrxd/src/asm/RawrXD_HexMag_Swarm.asm
        PROPERTIES LANGUAGE ASM_MASM)
    target_include_directories(hexmag_runtime_controller_cert PRIVATE
        ${CMAKE_SOURCE_DIR}/~dev/rawrxd/src
        ${CMAKE_SOURCE_DIR}/include
    )
    target_compile_definitions(hexmag_runtime_controller_cert PRIVATE RAWR_HAS_MASM=1)
    if(MSVC)
        target_compile_options(hexmag_runtime_controller_cert PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:/EHsc /W4 /std:c++20>
            $<$<COMPILE_LANGUAGE:ASM_MASM>:/Zi /Cx /W3 /errorReport:prompt>
        )
    endif()
    set_target_properties(hexmag_runtime_controller_cert PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "[Agentic] HexMag runtime controller cert: hexmag_runtime_controller_cert")
else()
    message(STATUS "HexMag cert targets EXCLUDED: required sources not found")
endif()

# Gate 11 — Long-Context KV Correctness (DEEP2_CONTEXT_SCALING_001).
# Progress through 4K, 32K, 128K, 512K, and 1M where supported.
# Verify KV contents, memory residency, position handling, and measured decode scaling.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_context_scaling.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_context_scaling
        tools/deep2_context_scaling.cpp
        src/deep2/runtime_graph_executor.cpp
        src/deep2/generic_vulkan_matmul.cpp
        src/deep2/op_linear.cpp
        src/deep2/modelgenie/universal_gguf.cpp
        src/deep2/quant_dot_dispatch.cpp
        src/vulkan_compute.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
        src/utils/Diagnostics.cpp
    )
    target_include_directories(deep2_context_scaling PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tools
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET ggml_interface)
        target_link_libraries(deep2_context_scaling PRIVATE ggml_interface)
    endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_context_scaling PRIVATE Vulkan::Vulkan)
    endif()
    if(TARGET ggml-vulkan)
        target_link_libraries(deep2_context_scaling PRIVATE ggml-vulkan)
    endif()
    if(MSVC)
        target_compile_options(deep2_context_scaling PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_context_scaling PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(deep2_context_scaling PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS
        DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
    )
    set_target_properties(deep2_context_scaling PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_context_scaling enabled (Long-context KV certification; ggml + Vulkan SDK)")
else()
    message(STATUS "deep2_context_scaling EXCLUDED: tool source or Vulkan SDK unavailable")
endif()

# Gate 9 — GGUF Lifecycle Certification (DEEP2_GGUF_LIFECYCLE_001).
# Tests load, generate, cancel, unload, reload, and corrupted GGUF handling
# with memory accounting and fail-closed architecture dispatch.
# Uses the same minimal source set as deep2_spec_bench.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_gguf_lifecycle.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_gguf_lifecycle
        tools/deep2_gguf_lifecycle.cpp
        src/deep2/runtime_graph_executor.cpp
        src/deep2/generic_vulkan_matmul.cpp
        src/deep2/op_linear.cpp
        src/deep2/modelgenie/universal_gguf.cpp
        src/deep2/quant_dot_dispatch.cpp
        src/vulkan_compute.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
        src/utils/Diagnostics.cpp
    )
    target_include_directories(deep2_gguf_lifecycle PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tools
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET ggml_interface)
        target_link_libraries(deep2_gguf_lifecycle PRIVATE ggml_interface)
    endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_gguf_lifecycle PRIVATE Vulkan::Vulkan)
    endif()
    if(TARGET ggml-vulkan)
        target_link_libraries(deep2_gguf_lifecycle PRIVATE ggml-vulkan)
    endif()
    if(MSVC)
        target_compile_options(deep2_gguf_lifecycle PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_gguf_lifecycle PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(deep2_gguf_lifecycle PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS
        DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
    )
    set_target_properties(deep2_gguf_lifecycle PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_gguf_lifecycle enabled (GGUF lifecycle certification; ggml + Vulkan SDK)")
else()
    message(STATUS "deep2_gguf_lifecycle EXCLUDED: tool source or Vulkan SDK unavailable")
endif()

# Gate 4 kernel evidence (RAWRXD_DEEP2_GPU_QUANT_DOT_001): the native Vulkan
# quantised-dot verifier. It builds synthetic Q4_K/Q6_K rows plus Q8_K
# activations, runs vc.ExecuteQuantDot on the REAL device and compares it
# against an independent CPU decode of the same GGML block layouts
# (cosine >= 0.999999 and relative <= 1e-4 per shape). It previously existed
# only as a hand-compiled tool, so its PASS could not be re-proved from a
# clean tree; it is now registered under the same Vulkan guard as the
# dispatch auditor, and EXCLUDED (never silently passed) without a device.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/gpu_quant_dot_verify.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(gpu_quant_dot_verify
        tools/gpu_quant_dot_verify.cpp
        src/vulkan_compute.cpp
    )
    target_include_directories(gpu_quant_dot_verify PRIVATE
        # include/ FIRST: the tool's bare "vulkan_compute.h" must resolve to
        # the global ::VulkanCompute this binary builds, not the Deep2 one.
        # The repo root is what makes src/vulkan_compute.cpp's prefixed
        # "include/vulkan_compute.h" resolve to the same header.
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(gpu_quant_dot_verify PRIVATE Vulkan::Vulkan)
    endif()
    if(MSVC)
        target_compile_options(gpu_quant_dot_verify PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(gpu_quant_dot_verify PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(gpu_quant_dot_verify PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "gpu_quant_dot_verify enabled (native Vulkan quant-dot kernel evidence)")
else()
    message(STATUS "gpu_quant_dot_verify EXCLUDED: Vulkan SDK unavailable - kernel parity evidence cannot be produced")
endif()

# Gate 4 kernel evidence on REAL GGUF weights (RAWRXD_DEEP2_GPU_QUANT_DOT_002):
# runs VulkanCompute::ExecuteQuantDot on bytes read from a real GGUF tensor
# with a real activation, and compares the GPU result against BOTH ggml's own
# float dequantise+dot and an independent CPU integer-lane decode. Synthetic
# shapes cannot expose data-dependent accumulation behaviour; real weight
# distributions can. Same Vulkan guard as its siblings.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/gpu_quant_dot_realweights.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(gpu_quant_dot_realweights
        tools/gpu_quant_dot_realweights.cpp
        src/vulkan_compute.cpp
    )
    target_include_directories(gpu_quant_dot_realweights PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET ggml_interface)
        target_link_libraries(gpu_quant_dot_realweights PRIVATE ggml_interface)
    endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(gpu_quant_dot_realweights PRIVATE Vulkan::Vulkan)
    endif()
    if(MSVC)
        target_compile_options(gpu_quant_dot_realweights PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(gpu_quant_dot_realweights PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(gpu_quant_dot_realweights PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "gpu_quant_dot_realweights enabled (native Vulkan quant-dot on real GGUF weights)")
else()
    message(STATUS "gpu_quant_dot_realweights EXCLUDED: source or Vulkan SDK unavailable")
endif()

# Gate 9 — Fused Speculative LM-Head Runtime (DEEP2_SPEC_FUSED_RUNTIME_001).
# Verifies that DispatchGemvQ4KBatch is reached by the real speculative
# verification path, with correct per-position logits and measured launch
# reduction. Uses the same Vulkan guard as deep2_spec_bench.
if(EXISTS "${CMAKE_SOURCE_DIR}/tests/deep2_fused_lmhead_verify.cpp" AND Vulkan_FOUND AND 
_rawrxd_vk_sdk_inc)
    add_executable(deep2_fused_lmhead_verify
        tests/deep2_fused_lmhead_verify.cpp
        # Logf_() is defined exactly once, in Deep2Log.cpp.
        src/deep2/Deep2Log.cpp
        src/deep2/QuantKernelRegistry.cpp
        src/deep2/KVCache.cpp
        src/deep2/vulkan_compute.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
        src/utils/Diagnostics.cpp
        src/utils/input_sanitizer.cpp
        src/streaming_gguf_loader.cpp
    )
    target_link_libraries(deep2_fused_lmhead_verify PRIVATE deep2_engine_lib)
    target_include_directories(deep2_fused_lmhead_verify PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tests
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET ggml_interface)
        target_link_libraries(deep2_fused_lmhead_verify PRIVATE ggml_interface)
    endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_fused_lmhead_verify PRIVATE Vulkan::Vulkan)
    endif()
    if(MSVC)
        target_compile_options(deep2_fused_lmhead_verify PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_fused_lmhead_verify PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(deep2_fused_lmhead_verify PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS
        DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
    )
    set_target_properties(deep2_fused_lmhead_verify PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_fused_lmhead_verify enabled (Fused speculative LM-head certification; ggml + Vulkan SDK)")
else()
    message(STATUS "deep2_fused_lmhead_verify EXCLUDED: test source or Vulkan SDK unavailable")
endif()

# Gate 10 — Q6_K Row-Level Differential Test
# Verifies Q6_K GEMV kernel produces identical results for direct call vs row-sliced call
if(EXISTS "${CMAKE_SOURCE_DIR}/tests/q6k_row_differential_test.cpp")
    add_executable(q6k_row_differential_test
        tests/q6k_row_differential_test.cpp
    )
    target_link_libraries(q6k_row_differential_test PRIVATE deep2_engine_lib)
    target_include_directories(q6k_row_differential_test PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tests
        ${CMAKE_SOURCE_DIR}/src/deep2
    )
    if(MSVC)
        target_compile_options(q6k_row_differential_test PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(q6k_row_differential_test PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(q6k_row_differential_test PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS
    )
    set_target_properties(q6k_row_differential_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "q6k_row_differential_test enabled (Q6_K row-level differential test)")
else()
    message(STATUS "q6k_row_differential_test EXCLUDED: test source unavailable")
endif()

# Gate 7 hybrid evidence (RAWRXD_GATE7_HYBRID_001): independent Mamba2 block-0
# reference probe. It decodes the SSM weights through ggml's own dequantiser
# (a different decode path from the executor) and recomputes the block-0 mixer
# with independent float arithmetic, so the first divergent tensor of the
# hybrid can be localised instead of inferred from end-to-end logits.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/mamba2_ref_probe.cpp")
    add_executable(mamba2_ref_probe tools/mamba2_ref_probe.cpp)
    target_include_directories(mamba2_ref_probe PRIVATE
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
    )
    if(TARGET ggml_interface)
        target_link_libraries(mamba2_ref_probe PRIVATE ggml_interface)
    endif()
    if(MSVC)
        target_compile_options(mamba2_ref_probe PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(mamba2_ref_probe PRIVATE -std=c++20 $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(mamba2_ref_probe PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "mamba2_ref_probe enabled (independent Mamba2 block-0 reference)")
endif()

# Gate 9 agentic E2E harness (RAWRXD_AUTONOMOUS_AGENT_E2E_001): drives a real
# inference -> tool-call -> real execution -> observation -> resumed inference
# loop over the native Deep2 executor, and prints a tool receipt (every
# invocation, its observation size, and the final verdict) as its conclusion.
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_agentic_loop.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp")
    add_executable(deep2_agentic_loop
        tools/deep2_agentic_loop.cpp
        # Logf_() is defined exactly once, in Deep2Log.cpp, for this target too.
        src/deep2/Deep2Log.cpp
        src/deep2/runtime_graph_executor.cpp
        src/deep2/generic_vulkan_matmul.cpp
        src/deep2/vulkan_compute.cpp
        src/deep2/QuantKernelRegistry.cpp
        src/deep2/asm_stubs.cpp
        src/deep2/op_linear.cpp
        src/deep2/op_gdn.cpp
        src/deep2/modelgenie/universal_gguf.cpp
        src/deep2/quant_dot_dispatch.cpp
        src/vulkan_compute.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
        src/utils/Diagnostics.cpp
        src/utils/input_sanitizer.cpp
        src/utils/secure_buffer.cpp
        src/utils/crash_handler.cpp
        # Cloud API client (Qt-free, WinHTTP native)
        src/cloud_api_client.cpp
        src/universal_model_router.cpp
    )
    target_include_directories(deep2_agentic_loop PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tools
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${CMAKE_SOURCE_DIR}/tools/deep2_snap/deep2_snap
        ${CMAKE_SOURCE_DIR}/tools/agent_esp/rawrxd_agent_esp
        ${CMAKE_SOURCE_DIR}/tools/snap_process_guard
        ${CMAKE_SOURCE_DIR}/tools/snap_supervisor
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET deep2_snap)
        target_link_libraries(deep2_agentic_loop PRIVATE deep2_snap)
    endif()
    if(TARGET ggml_interface)
        target_link_libraries(deep2_agentic_loop PRIVATE ggml_interface)
    endif()
    if(TARGET rawrxd_agent_esp)
        target_link_libraries(deep2_agentic_loop PRIVATE rawrxd_agent_esp)
    endif()
    if(TARGET snap_process_guard)
        target_link_libraries(deep2_agentic_loop PRIVATE snap_process_guard)
    endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_agentic_loop PRIVATE Vulkan::Vulkan)
    endif()
    if(TARGET ggml-vulkan)
        target_link_libraries(deep2_agentic_loop PRIVATE ggml-vulkan)
    endif()
    # Link the real Deep2Engine so the agent uses batched prefill and GPU kernels
    if(TARGET deep2_engine_lib)
        target_link_libraries(deep2_agentic_loop PRIVATE deep2_engine_lib)
        target_compile_definitions(deep2_agentic_loop PRIVATE HAVE_DEEP2_ENGINE=1)
    endif()
    # Link WinHTTP for cloud API client
    if(MSVC)
        target_link_libraries(deep2_agentic_loop PRIVATE winhttp.lib)
    endif()
    if(MSVC)
        target_compile_options(deep2_agentic_loop PRIVATE /EHsc /std:c++20 /bigobj $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_agentic_loop PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    set_target_properties(deep2_agentic_loop PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_agentic_loop enabled (Gate 9 agentic E2E harness)")
endif()

# AgenticLoopBridge recovery gate: exercises the real Win32 process-launch
# lifecycle without a model or cloud service.  The executable is emitted to a
# separate directory so no helper sibling is discoverable; this makes the
# missing-helper and bridge-reuse outcomes deterministic and non-synthetic.
if(WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/tools/agentic_loop_bridge_recovery_smoke.cpp" AND
   EXISTS "${CMAKE_SOURCE_DIR}/src/win32app/Win32IDE_AgenticLoopBridge.cpp")
    add_executable(agentic_loop_timeout_helper
        tools/agentic_loop_timeout_helper.cpp
    )
    set_target_properties(agentic_loop_timeout_helper PROPERTIES
        OUTPUT_NAME "deep2_agentic_loop"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bridge_smoke_timeout"
    )
    add_executable(agentic_loop_bridge_recovery_smoke
        tools/agentic_loop_bridge_recovery_smoke.cpp
        tools/agentic_loop_bridge_smoke_logger.cpp
        src/win32app/Win32IDE_AgenticLoopBridge.cpp
    )
    target_include_directories(agentic_loop_bridge_recovery_smoke PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/win32app
        ${CMAKE_SOURCE_DIR}/src/snap
        ${CMAKE_SOURCE_DIR}/src/deep2/watchdog
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tools
        ${CMAKE_SOURCE_DIR}/tools/snap_process_guard
        ${CMAKE_SOURCE_DIR}/tools/snap_supervisor
        ${CMAKE_SOURCE_DIR}/tools/agent_esp/rawrxd_agent_esp
    )
    target_link_libraries(agentic_loop_bridge_recovery_smoke PRIVATE
        user32
        advapi32
        psapi
    )
    target_compile_options(agentic_loop_bridge_recovery_smoke PRIVATE /EHsc /std:c++20)
    add_dependencies(agentic_loop_bridge_recovery_smoke agentic_loop_timeout_helper)
    set_target_properties(agentic_loop_bridge_recovery_smoke PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bridge_smoke"
    )
    message(STATUS "agentic_loop_bridge_recovery_smoke enabled")
endif()

# ============================================================================
# H01/H02: Host-driven autonomous repair loop (RAWR_AUTONOMOUS_REPAIR_E2E_001)
# Host controls: read -> present to model -> get patch -> apply -> build -> test -> retry
# Model only outputs fixed source code. No TOOL protocol, no free-form commands.
# ============================================================================
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_agentic_repair.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_agentic_repair
        tools/deep2_agentic_repair.cpp
        src/deep2/runtime_graph_executor.cpp
        src/deep2/generic_vulkan_matmul.cpp
        src/deep2/op_linear.cpp
        src/deep2/modelgenie/universal_gguf.cpp
        src/deep2/quant_dot_dispatch.cpp
        src/vulkan_compute.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
        src/utils/Diagnostics.cpp
    )
    target_include_directories(deep2_agentic_repair PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tools
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET ggml_interface)
        target_link_libraries(deep2_agentic_repair PRIVATE ggml_interface)
    endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_agentic_repair PRIVATE Vulkan::Vulkan)
    endif()
    if(TARGET ggml-vulkan)
        target_link_libraries(deep2_agentic_repair PRIVATE ggml-vulkan)
    endif()
    if(MSVC)
        target_compile_options(deep2_agentic_repair PRIVATE /EHsc /std:c++20 /bigobj $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_agentic_repair PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(deep2_agentic_repair PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS
        DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
    )
    set_target_properties(deep2_agentic_repair PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_agentic_repair enabled (H01/H02 host-driven autonomous repair)")
endif()

# ============================================================================
# RAWRXD_EXEC_TRUTH: authoritative inference execution trace.
# Answers "one pass per layer" vs "one pass per token per layer", and proves
# which backend actually executes each tensor op (with fallback reasons).
# ============================================================================
if(FALSE AND EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_exec_trace.cpp" AND EXISTS 
   "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_exec_trace
        tools/deep2_exec_trace.cpp
        src/deep2/runtime_graph_executor.cpp
        src/deep2/op_gdn.cpp
        src/deep2/generic_vulkan_matmul.cpp
        src/deep2/vulkan_compute.cpp
        src/deep2/QuantKernelRegistry.cpp
        src/deep2/asm_stubs.cpp
        src/deep2/op_linear.cpp
        src/deep2/modelgenie/universal_gguf.cpp
        src/deep2/quant_dot_dispatch.cpp
        src/vulkan_compute.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
        src/utils/Diagnostics.cpp
        src/utils/input_sanitizer.cpp
    )
    target_include_directories(deep2_exec_trace PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tools
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET ggml_interface)
        target_link_libraries(deep2_exec_trace PRIVATE ggml_interface)
    endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_exec_trace PRIVATE Vulkan::Vulkan)
    endif()
    if(TARGET ggml-vulkan)
        target_link_libraries(deep2_exec_trace PRIVATE ggml-vulkan)
    endif()
    if(MSVC)
        target_compile_options(deep2_exec_trace PRIVATE /EHsc /std:c++20 /bigobj $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_exec_trace PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(deep2_exec_trace PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS
        DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
    )
    set_target_properties(deep2_exec_trace PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_exec_trace enabled (RAWRXD_EXEC_TRUTH authoritative trace)")
endif()

# ============================================================================
# H11-P1..P4: batched-prefill numerical parity vs the serial reference.
# Gate 5 (command fusion) may only be optimised after this passes.
# ============================================================================
if(EXISTS "${CMAKE_SOURCE_DIR}/tools/deep2_prefill_parity.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_prefill_parity
        tools/deep2_prefill_parity.cpp
        src/deep2/runtime_graph_executor.cpp
        src/deep2/generic_vulkan_matmul.cpp
        src/deep2/op_linear.cpp
        src/deep2/modelgenie/universal_gguf.cpp
        src/deep2/quant_dot_dispatch.cpp
        src/vulkan_compute.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
        src/utils/Diagnostics.cpp
    )
    target_include_directories(deep2_prefill_parity PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/tools
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        ${_rawrxd_vk_sdk_inc}
    )
    if(TARGET ggml_interface)
        target_link_libraries(deep2_prefill_parity PRIVATE ggml_interface)
    endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(deep2_prefill_parity PRIVATE Vulkan::Vulkan)
    endif()
    if(TARGET ggml-vulkan)
        target_link_libraries(deep2_prefill_parity PRIVATE ggml-vulkan)
    endif()
    if(MSVC)
        target_compile_options(deep2_prefill_parity PRIVATE /EHsc /std:c++20 /bigobj $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_prefill_parity PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(deep2_prefill_parity PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS
        DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
    )
    set_target_properties(deep2_prefill_parity PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_prefill_parity enabled (H11-P1..P4 parity + H11-P6 dispatch profile)")
endif()

# ============================================================================
# Custom GPU compute environment (Deep2::VulkanCompute + KernelRegistry-backed
# quantised dispatch)
#
# This is the subsystem that sits above the raw Vulkan device layer: the
# kernel/registry/dispatch surface that Deep2Engine talks to. It used to live
# only in the ~dev scratch tree, so anything that included
# "vulkan_compute.h" from a Deep2 translation unit resolved the *device-level*
# include/vulkan_compute.h instead (a different class, without DispatchGEMVQuant,
# DispatchGEMV, GemvSuccessCount, SetPinResidentBudget or the CPUInference
# alias). That is why Deep2Engine could never be built from this tree.
#
# The headers now ship beside the engine in src/deep2/, so a quoted include
# from src/deep2/ finds them before the include/ path.
# ============================================================================
if(EXISTS ${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute.cpp AND EXISTS ${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute.h)
    add_library(rawrxd_gpu_compute STATIC
        src/deep2/vulkan_compute.cpp
        src/streaming_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
    )
    target_include_directories(rawrxd_gpu_compute PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        # Must precede include/ so "vulkan_compute.h" resolves to the
        # Deep2::VulkanCompute definition this library implements.
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/include
    )
    if(TARGET ggml_interface)
            target_link_libraries(rawrxd_gpu_compute PUBLIC ggml_interface)
        endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(rawrxd_gpu_compute PUBLIC Vulkan::Vulkan)
    endif()
    if(MSVC)
        target_compile_options(rawrxd_gpu_compute PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(rawrxd_gpu_compute PRIVATE -std:c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(rawrxd_gpu_compute PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
    )
    message(STATUS "rawrxd_gpu_compute enabled: Deep2::VulkanCompute buildable from the main tree")

    # ------------------------------------------------------------------------
    # Deep2Engine: the engine that drives the GPU compute environment.
    #
    # Built here deliberately even though it cannot link yet. The link errors
    # ARE the deliverable: they are the exact, complete inventory of
    # CPUInference::VulkanCompute members the production engine actually calls,
    # which is the only honest way to size the remaining work. Classifying
    # that list into "adapter over Deep2::VulkanCompute", "inline", "residency
    # management", "genuinely missing kernel" and "never called" is what
    # prevents implementing ~150 methods blind.
    # ------------------------------------------------------------------------
    if(EXISTS ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine.cpp)
        # ------------------------------------------------------------------------
        # ENGINE_RECOVERY: the subsystems above were only ever compiled as a link
        # inventory, so their out-of-class implementations were never wired in.
        # The .cpp files below already exist in src/deep2/ and define the missing
        # symbols; they are added here so the engine links as a real executable
        # instead of enumerating what is absent. Each one is guarded on EXISTS so
        # a partially-recovered tree still configures.
        #
        # NOTE: src/deep2/execution_policy/ and src/deep2/mars/, plus
        # AttnCertProbe / SsmCertProbe / MlaCertProbe / Deep2DeviceManager /
        # Deep2MultiGpuLayerPlan / ElasticDynamicBudget / K2LivePolicy /
        # FusedLiveController / Deep2LivePath, are separate translation units
        # rather than header-only declarations.
        # ------------------------------------------------------------------------
        set(_DEEP2_ENGINE_SUBSYSTEM_SOURCES
            ${CMAKE_SOURCE_DIR}/src/deep2/KVCache.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/CompressedKVCache.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/NVMeStream.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/ResidencyManager.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/VwaResolveBlocks.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/CycloneScheduler.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/SlidingWindowEngine.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/WarmupScheduler.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/MARS.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/QuantKernelRegistry.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/MoEWeightsLoader.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/MoERouter.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/MoEWeightProxy.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/NUFusedPacker.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/RouterPrefetchTelemetry.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/HotPatcher.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/ReverseHotpatchEngine.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/BP16Streamer.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/SovereignOutOfCoreRuntime.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/OutOfCoreRuntime.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/Chamber.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/PlasmaGovernor.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2GlobalTensorIndex.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2GpuStreamCopy.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/VulkanWeightStreamerVulkanBackend.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2MLA_GpuGemv.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2ShardIo.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2MLAAttention.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2TokenEmbedding.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2NativeStreamGate.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2NativeMoEFfn.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2NativeMoEFfn_Place.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2NativeMoEFfn_Expert.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2NativeMoEFfn_ExpertGpu.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2NativeMoEFfn_ExpertGpuDevice.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2LogitsClimb.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2LogitsSplit.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2WeightResolve.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2LivePathTensorCache.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2LivePathTensorCache_Prefetch.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2LivePathTensorCache_Emit.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2MLA_PathB.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2MLA_PathB_Attn.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2QbHostShrinkD2h.cpp
            ${CMAKE_SOURCE_DIR}/src/runtime/QbHostReadbackWindow.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/HostExchangeDiscover.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2MoEWeights.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2MLA_QPathDevice_Emit.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickBundle_Table.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickBundle_Note.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickBundle_Evict.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickBundle_Quota.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickBundle_Attr.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickBundle_Pins.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickBundle_Touch.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickExpertBundle.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickImbalance.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickImbalance_Steal.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickImbalance_Cost.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickImbalance_CostCov.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickImbalance_Ewma.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickImbalance_Observe.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickImbalance_Xfer.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/HostFutureConsumerPrefetch.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/HostFutureConsumerPrefetch_KnO3.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/HostFutureConsumerPrefetch_Move.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/HostFutureConsumerPrefetch_Nvme.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/HostFutureConsumerPrefetch_Seal.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/HostFutureConsumerPrefetch_Worker.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickStreamWindow_Vc.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/EndDeviceStep3Diag.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/MoEExpertResidencyPlace.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/MoEExpertResidencyPlace_Place.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/MoEPlaceLiveCounters.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2MLA_KvExpand_Fused.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2MLAWeights.cpp
            # Certification probes (deep2/AttnCertProbe.cpp etc.)
            ${CMAKE_SOURCE_DIR}/src/deep2/AttnCertProbe.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/SsmCertProbe.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/MlaCertProbe.cpp
            # Device manager + multi-GPU layer planning
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2DeviceManager.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2MultiGpuLayerPlan.cpp
            # Elastic residency budgeting (probe/derive/emit) and residency manager
            ${CMAKE_SOURCE_DIR}/src/deep2/ElasticDynamicBudget.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/ElasticResidencyManager.cpp
            # Live path + fused controller + K2 execution policy
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/FusedLiveController.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2LivePolicy.cpp
            # Cert probes / device manager (declared, definitions live in .cpp)
            ${CMAKE_SOURCE_DIR}/src/deep2/DualGPUHook.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/GhostCache.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/TrailBrake.cpp
            # MLA gating / Qa critical path / q-path device / logits lineage are
            # owned by K2MLA_FusedQ4KT.cpp / K2MLA_QaCritical.cpp /
            # K2MLA_QPathDevice.cpp / K2LogitsLineage.cpp (batch-05);
            # K2MLA_telemetry.cpp is intentionally NOT listed because it defines
            # the same symbols and would collide (LNK2005).
            # lavapath: free-token micro-zones + future consumer page ownership
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/FreeTokenMicroZone.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/FutureConsumerSpace.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/execution_policy/ExecutionPolicy.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/execution_policy/ExecutionPolicyApply.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/execution_policy/ExecutionPolicyStore.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/execution_policy/PlacementPlan.cpp
            # Ollama blob ingestion and native blob detector implementation
            # used by RawrModelAlias and `rawr run`.  The implementation unit
            # also owns OllamaBlobParser; do not compile the legacy duplicate
            # parser unit alongside it.
            # the `rawr run <ollama-name>` front door.  Keep this in the shared
            # engine library so CLI consumers do not get unresolved symbols.
            ${CMAKE_SOURCE_DIR}/src/deep2/ollama_blob_parser_impl.cpp
            # Deep2Engine's own out-of-class members
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine_missing_members.cpp
            # Sampling helpers used by the engine
            ${CMAKE_SOURCE_DIR}/src/sampling/advanced_sampler.cpp
            # ENGINE_RECOVERY batch-05: out-of-class definitions referenced by
            # the deep2 modules. mars/MARSController.cpp, mars/TensorHotpatch.cpp
            # and mars/DualGPUBackend.cpp are deliberately OMITTED (they redefine
            # MARSController members MARS.cpp already owns -> LNK2005).
            ${CMAKE_SOURCE_DIR}/src/deep2/KimiK2Config.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/ReverseTensorRecovery.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/mars/VRAMManager.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2MLA_FusedQ4KT.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2MLA_QaCritical.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2MLA_QPathDevice.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath_Gate.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2BraidExecutionPolicy.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/asm_stubs.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2LogitsLineage.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/GpuTransfer_Emit.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/MoEEliminate.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/engine_link_supplement.cpp
            # Pure-implementation out-of-class definitions (no main()). The
            # *_cert.cpp / *_parity.cpp harnesses are deliberately NOT listed
            # (each defines its own main()).
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickStreamWindow.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickStreamWindow_Acquire.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/DualStickStreamWindow_Emit.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath_Mech.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath_Pinball.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath_Thermal.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2LivePath_MechEnd.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2LivePolicy_Apply.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2MultiGpu_CostCut.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2GpuStreamCopy_Overlap.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/K2C1C9.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/StreamerParity_Post.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/StreamEngine.cpp            # Remaining CPUInference::VulkanCompute members: fused-layer
            # lifecycle, forward arena, GEMV staging, Q4_K/Q6_K dispatch and the
            # weight window. Forwards real Deep2::VulkanCompute capability and
            # fails closed where the implementation has none, so a false return
            # is a genuine "no device work happened" hand-off.
            ${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute_adapter_fused.cpp
            # Patch safety: SHA-256, stack canary, crash recovery, pre-flight
            # and the RAII guards the hot-patcher constructs.
            ${CMAKE_SOURCE_DIR}/src/deep2/HotPatcherSafety.cpp
            # Completion for the two lavapath contracts that were left with a few
            # unimplemented members. Owns FindHotByKey/PickZone/EmitWitness and
            # ConsumerCount/NotePhysicalOverwrite only.
            ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/FreeTokenFutureCompletion.cpp
            # Stream engine lifecycle (ctor/dtor/Initialize/unreverseHot/
            # ReviveLayer/GetState). StreamEngine.cpp was simply not in the list.
            ${CMAKE_SOURCE_DIR}/src/deep2/StreamEngine.cpp
        )
        foreach(_s ${_DEEP2_ENGINE_SUBSYSTEM_SOURCES})
            if(NOT EXISTS "${_s}")
                message(STATUS "rawrxd_deep2_engine: subsystem source absent, skipped: ${_s}")
            endif()
        endforeach()
        foreach(_s ${_DEEP2_ENGINE_SUBSYSTEM_SOURCES})
            if(NOT EXISTS "${_s}")
                list(REMOVE_ITEM _DEEP2_ENGINE_SUBSYSTEM_SOURCES "${_s}")
            endif()
endforeach()

        # Assemble the real x64 MASM modules explicitly with ml64. Keeping
        # them out of the CXX target's implicit .asm rule avoids CMake applying
        # cl.exe flags and makes object paths deterministic for the archive.
        set(_DEEP2_MASM_DIR ${CMAKE_CURRENT_BINARY_DIR}/reap_masm)
        set(_DEEP2_MASM_OBJECTS)
        foreach(_masm_name VwaRangeLineageX64 KN_O3KKEN RuntimeEvidence512_Core
                              RuntimeEvidence512_Emit RuntimeEvidence512_Collect
                              RuntimeEvidence512_IDEEmit RuntimeEvidence512_IDECollect)
            if(_masm_name STREQUAL VwaRangeLineageX64 OR _masm_name STREQUAL KN_O3KKEN)
                set(_masm_src ${CMAKE_SOURCE_DIR}/src/deep2/vwa/${_masm_name}.asm)
                if(_masm_name STREQUAL KN_O3KKEN)
                    set(_masm_src ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/${_masm_name}.asm)
                endif()
            else()
                set(_masm_src ${CMAKE_SOURCE_DIR}/src/asm/${_masm_name}.asm)
            endif()
            set(_masm_obj ${_DEEP2_MASM_DIR}/${_masm_name}.obj)
            set(_masm_deps ${_masm_src})
            if(_masm_name STREQUAL RuntimeEvidence512_Collect)
                list(APPEND _masm_deps ${CMAKE_SOURCE_DIR}/src/asm/RuntimeEvidence512_Collect.inc)
            endif()
            if(_masm_name STREQUAL RuntimeEvidence512_IDEEmit)
                list(APPEND _masm_deps ${CMAKE_SOURCE_DIR}/src/asm/RuntimeEvidence512_IDEClaims.inc)
            endif()
            if(_masm_name STREQUAL KN_O3KKEN)
                list(APPEND _masm_deps ${CMAKE_SOURCE_DIR}/src/deep2/lavapath/KN_O3KKEN.inc)
            endif()
            add_custom_command(
                OUTPUT ${_masm_obj}
                COMMAND ${CMAKE_COMMAND} -E make_directory ${_DEEP2_MASM_DIR}
                COMMAND ${CMAKE_ASM_MASM_COMPILER} /nologo /c /Fo${_masm_obj} ${_masm_src}
                DEPENDS ${_masm_deps}
                VERBATIM
                COMMENT "Assembling ${_masm_name}.asm with ml64"
            )
            list(APPEND _DEEP2_MASM_OBJECTS ${_masm_obj})
        endforeach()

        # Create a static library from the engine subsystem sources so other targets
        # (deep2_gpu_decode_roofline, deep2_runtime_dispatch) can link against the
        # same implementation instead of re-listing sources and risking ODR violations.
        add_library(deep2_engine_lib STATIC
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2CLIBridge.cpp
            ${CMAKE_SOURCE_DIR}/src/agentic/AgentOrchestrator.cpp
            ${CMAKE_SOURCE_DIR}/src/agentic/tool_call_parser.cpp
            # Deep2Log.cpp defines Logf_() EXACTLY ONCE and is shared by
            # Deep2Engine.cpp and tools/deep2_agentic_loop.cpp. Every target
            # that compiles either of those needs this in the link, or Logf_
            # is unresolved.
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Log.cpp
            # DEEP2_MODEL_FIT_AUTHORITY_001 / DEEP2_EXECUTION_AUTHORITY_001 /
            # DEEP2_BATCHED_PREFILL_001: admission-to-execution contract.
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine_ModelFit.cpp
            ${CMAKE_SOURCE_DIR}/src/ChatTemplate.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute_engine_adapter.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/generic_vulkan_matmul.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2MlaLifecycleAdapter.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/MlaCertAuthority.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/engine_subsystems.cpp
            ${_DEEP2_MASM_OBJECTS}
            ${_DEEP2_ENGINE_SUBSYSTEM_SOURCES}
        )
        target_include_directories(deep2_engine_lib PUBLIC
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/deep2
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/tools/deep2_debugger
            ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
            ${CMAKE_SOURCE_DIR}/3rdparty/ggml/src
        )
        target_link_libraries(deep2_engine_lib PUBLIC
            rawrxd_gpu_compute
            ggml
            Vulkan::Vulkan
        )
        target_compile_options(deep2_engine_lib PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
        target_compile_definitions(deep2_engine_lib PRIVATE
            NOMINMAX _CRT_SECURE_NO_WARNINGS
            DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
        )
        set_target_properties(deep2_engine_lib PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
        )

        # Main engine executable: contains the entry point and core engine logic,
        # links against the subsystem library.
        add_executable(rawrxd_deep2_engine
            ${CMAKE_SOURCE_DIR}/src/deep2/engine_main.cpp
        )
        target_link_libraries(rawrxd_deep2_engine PRIVATE deep2_engine_lib)
        set_target_properties(rawrxd_deep2_engine PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )

message(STATUS "deep2_engine_lib enabled (static library; rawrxd_deep2_engine executable enabled)")
    endif()
endif()

# ---------------------------------------------------------------------------
# Quantization correctness + CPU-state gates (DEEP2_Q5_0_SIGNED_OFFSET_001,
# DEEP2_OS_XSAVE_STATE_001). Both build without Vulkan and must pass BEFORE any
# kernel optimisation is trusted: a "faster" kernel that dequantizes wrongly is
# worse than a slow one.
# ---------------------------------------------------------------------------
if(FALSE AND EXISTS "${CMAKE_SOURCE_DIR}/tests/deep2_q5_0_parity.cpp")
    add_executable(deep2_q5_0_parity
        tests/deep2_q5_0_parity.cpp
        ${CMAKE_SOURCE_DIR}/src/deep2/QuantKernelRegistry.cpp
        ${CMAKE_SOURCE_DIR}/src/deep2/asm_stubs.cpp
    )
    target_include_directories(deep2_q5_0_parity PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
    )
    target_compile_features(deep2_q5_0_parity PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_q5_0_parity PRIVATE /EHsc /std:c++20)
    else()
        target_compile_options(deep2_q5_0_parity PRIVATE -std=c++20)
    endif()
    enable_testing()
    add_test(NAME deep2_q5_0_parity COMMAND deep2_q5_0_parity)
endif()

if(FALSE AND EXISTS "${CMAKE_SOURCE_DIR}/tests/deep2_cpu_state_probe.cpp")
    add_executable(deep2_cpu_state_probe
        tests/deep2_cpu_state_probe.cpp
        ${CMAKE_SOURCE_DIR}/src/deep2/QuantKernelRegistry.cpp
        ${CMAKE_SOURCE_DIR}/src/deep2/asm_stubs.cpp
    )
    target_include_directories(deep2_cpu_state_probe PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
    )
    target_compile_features(deep2_cpu_state_probe PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_cpu_state_probe PRIVATE /EHsc /std:c++20)
    else()
        target_compile_options(deep2_cpu_state_probe PRIVATE -std=c++20)
    endif()
    enable_testing()
    add_test(NAME deep2_cpu_state_probe COMMAND deep2_cpu_state_probe)
endif()

# ---------------------------------------------------------------------------
# H11 prefill parity gate (H11-P1..P4).  Runs the real engine on a real GGUF
# and compares the chunked-causal prefill against the faithful serial path for
# chunk sizes 1, 2, 16 and 128 — KV bytes and logits.
#
# This gate exists to make GPU command fusion (H11-P5) safe: submission-count
# optimisation must not land while any parity gate fails, because a fused path
# that changes numerics is a silent model-corruption bug, not a speedup.
#
# Requires a model; skipped (not failed) when no GGUF is supplied via
# DEEP2_H11_MODEL.
# ---------------------------------------------------------------------------
if(EXISTS "${CMAKE_SOURCE_DIR}/tests/deep2_h11_prefill_parity.cpp" AND TARGET deep2_engine_lib)
    add_executable(deep2_h11_prefill_parity
        tests/deep2_h11_prefill_parity.cpp
    )
    target_include_directories(deep2_h11_prefill_parity PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/tools/deep2_debugger
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        ${_rawrxd_vk_sdk_inc}
    )
    target_link_libraries(deep2_h11_prefill_parity PRIVATE
        deep2_engine_lib
        ggml
        Vulkan::Vulkan
    )
    target_compile_features(deep2_h11_prefill_parity PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_h11_prefill_parity PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_h11_prefill_parity PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    enable_testing()
    add_test(NAME deep2_h11_prefill_parity
             COMMAND deep2_h11_prefill_parity $ENV{DEEP2_H11_MODEL})
endif()

# Gate 8 — GPU Decode Roofline Profiling (DEEP2_GPU_DECODE_ROOFLINE_001).
# Measures kernel execution, launch overhead, memory bandwidth, synchronization,
# KV reads, and LM-head costs per token. Optimizes the largest measured bottleneck.
# Now placed AFTER deep2_engine_lib definition so target_link_libraries can resolve it.
if(TARGET deep2_engine_lib AND EXISTS "${CMAKE_SOURCE_DIR}/tools/gpu_profiler/deep2_gpu_roofline.cpp" AND Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(deep2_gpu_decode_roofline
        tools/gpu_profiler/deep2_gpu_roofline.cpp
    )
    target_include_directories(deep2_gpu_decode_roofline PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${_rawrxd_vk_sdk_inc}
    )
    target_link_libraries(deep2_gpu_decode_roofline PRIVATE
        deep2_engine_lib
        ggml_interface
        Vulkan::Vulkan
    )
    if(MSVC)
        target_compile_options(deep2_gpu_decode_roofline PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_gpu_decode_roofline PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(deep2_gpu_decode_roofline PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS
        DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
    )
    set_target_properties(deep2_gpu_decode_roofline PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_gpu_decode_roofline enabled (GPU decode bottleneck profiling; ggml + Vulkan SDK)")
else()
    message(STATUS "deep2_gpu_decode_roofline EXCLUDED: deep2_engine_lib not available or test source/Vulkan SDK unavailable")
endif()

# Gate 10 diagnostic — uneven tensor-parallel GEMV microbenchmark. This proves
# only shard math and Vulkan timing on the local AMD devices; it is not a real
# Deep2 tensor-parallel inference certification.
if(TARGET rawrxd_gpu_compute AND TARGET deep2_engine_lib AND Vulkan_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/tools/gpu_profiler/deep2_uneven_tp_gemv.cpp")
    add_executable(deep2_uneven_tp_gemv
        tools/gpu_profiler/deep2_uneven_tp_gemv.cpp
    )
    target_link_libraries(deep2_uneven_tp_gemv PRIVATE
        rawrxd_gpu_compute
        deep2_engine_lib
        Vulkan::Vulkan
    )
    target_compile_features(deep2_uneven_tp_gemv PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_uneven_tp_gemv PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(deep2_uneven_tp_gemv PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(deep2_uneven_tp_gemv PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)
    set_target_properties(deep2_uneven_tp_gemv PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "deep2_uneven_tp_gemv enabled: Vulkan uneven shard diagnostics")
endif()

# ============================================================================
# Native (dependency-free, Qt-free) Win32 IDE
# ============================================================================
# The genuine RawrXD Win32 IDE: CreateWindow/Win32 API, D3D11/Vulkan
# transparent rendering, embedded PowerShell terminal, GGUF model loading and
# the native agentic bridge. None of these sources include Qt; the Qt-coupled
# RawrXD-Win32IDE target above mixes them with Qt widgets and is excluded from
# the dependency-free build. Enabled with -DRAWRXD_BUILD_WIN32IDE=ON.
# ============================================================================
if(MSVC AND RAWRXD_BUILD_WIN32IDE)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    set(_chat_route_generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
    set(_chat_route_generated_header "${_chat_route_generated_dir}/GeneratedChatRouteMenu.h")
    add_custom_command(
        OUTPUT "${_chat_route_generated_header}"
        COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/scripts/generate_chat_route_menu.py"
                --manifest "${CMAKE_SOURCE_DIR}/config/chat_model_routes.json"
                --output "${_chat_route_generated_header}"
        DEPENDS
            "${CMAKE_SOURCE_DIR}/scripts/generate_chat_route_menu.py"
            "${CMAKE_SOURCE_DIR}/config/chat_model_routes.json"
        COMMENT "Generating local/cloud chat route menu from manifest"
        VERBATIM
    )
    add_custom_target(rawrxd_chat_route_menu DEPENDS "${_chat_route_generated_header}")

    set(RAWRXD_NATIVE_IDE_SOURCES
        src/win32app/main_win32.cpp
        src/win32app/Win32IDE.cpp
        src/win32app/Win32IDE_Sidebar.cpp
        src/win32app/Win32IDE_VSCodeUI.cpp
        src/win32app/Win32IDE_PowerShellPanel.cpp
        src/win32app/Win32IDE_PowerShell.cpp
        src/win32app/Win32IDE_Logger.cpp
        src/win32app/Win32TerminalManager.cpp
        src/win32app/Win32IDE_FileOps.cpp
        src/win32app/Win32IDE_Commands.cpp
        src/win32app/Win32IDE_Debugger.cpp
        src/win32app/Win32IDE_AgenticBridge.cpp
        src/win32app/Win32IDE_AgentCommands.cpp
        src/win32app/Win32IDE_Autonomy.cpp
        src/win32app/Win32IDE_Deep2Bridge.cpp
        src/win32app/Win32IDE_AgenticLoopBridge.cpp
        src/win32app/Win32IDE_GhostText.cpp
        src/win32app/Win32IDE_GhostTextIntegration.cpp
        src/cloud_api_client.cpp
        # Lifecycle methods declared in Win32IDE.h but defined in their own
        # translation unit (createWindow/showWindow/runMessageLoop/onSize/
        # editor surface/Ollama bridge + the WindowProc dispatch chain).
        src/win32app/Win32IDE_lifecycle.cpp
        src/win32app/TransparentRenderer.cpp
        src/gguf_loader.cpp
        # Concrete IGGUFLoader implementation + the CPU inference engine
        # executor: both are referenced from Win32IDE.h's members but their
        # definitions live in separate translation units.
        src/GGUFLoader.cpp
        src/gguf_vocab_resolver.cpp
        src/streaming_gguf_loader.cpp
        src/cpu_inference_engine_impl.cpp
        src/utils/ErrorReporter.cpp
        src/utils/Diagnostics.cpp
    )
    set(RAWRXD_NATIVE_IDE_COMPLETE TRUE)
    foreach(_src ${RAWRXD_NATIVE_IDE_SOURCES})
        if(NOT EXISTS "${CMAKE_SOURCE_DIR}/${_src}")
            set(RAWRXD_NATIVE_IDE_COMPLETE FALSE)
            message(STATUS "RawrXD-Win32IDE-Native: missing source ${_src}")
        endif()
    endforeach()

    if(RAWRXD_NATIVE_IDE_COMPLETE)
        add_executable(RawrXD-Win32IDE-Native ${RAWRXD_NATIVE_IDE_SOURCES}
            "${_chat_route_generated_header}"
            $<$<BOOL:${ENABLE_VULKAN}>:src/win32app/VulkanRenderer.cpp>
        )
        target_include_directories(RawrXD-Win32IDE-Native PRIVATE
            "${_chat_route_generated_dir}"
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/win32app
            ${CMAKE_SOURCE_DIR}/src/utils
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/src/snap
            ${CMAKE_SOURCE_DIR}/src/deep2/perf_fix
            ${CMAKE_SOURCE_DIR}/src/deep2/watchdog
            # ggml.h / ggml_type_traits for the CPU executor's quant geometry.
            ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
            # Agent ESP telemetry
            ${CMAKE_SOURCE_DIR}/tools/agent_esp/rawrxd_agent_esp
            # deep2_snap (deep2_snap.hpp, snap_process_guard.hpp) used by Win32IDE_Deep2Bridge.cpp
            ${CMAKE_SOURCE_DIR}/tools/deep2_snap/deep2_snap
            ${CMAKE_SOURCE_DIR}/tools/snap_process_guard
            # gguf_loader.h includes vulkan_compute.h -> vulkan/vulkan.h, so the
            # Vulkan SDK include path is required even when GPU compute is off.
            ${Vulkan_INCLUDE_DIRS}
        )
        target_compile_definitions(RawrXD-Win32IDE-Native PRIVATE
            NOMINMAX
            _WIN32_WINNT=0x0A00
            _CRT_SECURE_NO_WARNINGS
            _MBCS
            $<$<BOOL:${ENABLE_VULKAN}>:ENABLE_VULKAN=1>
        )
        target_compile_options(RawrXD-Win32IDE-Native PRIVATE
            /EHsc $<$<CONFIG:Release>:/O2>
        )
        # RichEdit 2.0 ("RichEdit20A" / RICHEDIT_CLASSA) is used by the editor,
        # terminal and PowerShell-panel controls. The IDE reaches it only as a
        # registered window class (the PowerShell panel does
        # LoadLibrary("Riched20.dll")) plus window messages such as EM_SETTEXTEX,
        # EM_SETCHARFORMAT and EM_EXGETSEL, so no import library is strictly
        # required. Hardcoding riched32/richedit here made the link fail outright
        # on SDKs that do not ship those import libs (the 10.0.26100.0 SDK used
        # for this build has neither riched20.lib nor riched32.lib). Link them
        # when the SDK provides them, and skip silently otherwise.
        set(RAWRXD_RICHEDIT_LIBS)
        foreach(_relib riched20 riched32 richedit msftedit)
            find_library(RAWRXD_LIB_${_relib} ${_relib})
            if(RAWRXD_LIB_${_relib})
                list(APPEND RAWRXD_RICHEDIT_LIBS ${RAWRXD_LIB_${_relib}})
            endif()
        endforeach()
        if(RAWRXD_RICHEDIT_LIBS)
            message(STATUS "RawrXD-Win32IDE-Native: RichEdit import libs: ${RAWRXD_RICHEDIT_LIBS}")
        else()
            message(STATUS "RawrXD-Win32IDE-Native: RichEdit used as a runtime window class only; no import lib found in this SDK")
        endif()
        target_link_libraries(RawrXD-Win32IDE-Native PRIVATE
            comctl32 comdlg32 winhttp
            ${RAWRXD_RICHEDIT_LIBS}
            shell32 user32 gdi32
            ole32 oleaut32 uuid advapi32 d3d11 dxgi d3dcompiler
            # TransparentRenderer (src/win32app/TransparentRenderer.cpp) uses
            # Direct2D, DirectWrite and DirectComposition for the glass /
            # composited editor surface, and DWM for the blur-behind window.
            # These were missing, so D2D1CreateFactory, DWriteCreateFactory,
            # DCompositionCreateDevice and DwmEnableBlurBehindWindow were all
            # unresolved at link time.
            d2d1 dwrite dxguid dwmapi dcomp
            # PSAPI for process enumeration in SNAP detectors
            psapi
        )
        add_dependencies(RawrXD-Win32IDE-Native rawrxd_chat_route_menu)
        # Production-hardening runtime: configuration, structured logging,
        # metrics, security (AES-GCM + hash-chained audit) and readiness gates.
        # main_win32.cpp calls ProductionRuntime::init()/shutdown() and
        # exposes --health-check, so this is a hard dependency of the IDE
        # rather than an optional extra.
        if(TARGET rawrxd_production_hardening)
            target_link_libraries(RawrXD-Win32IDE-Native PRIVATE
                rawrxd_production_hardening
            )
            target_include_directories(RawrXD-Win32IDE-Native PRIVATE
                ${CMAKE_SOURCE_DIR}/src/production
            )
            message(STATUS "RawrXD-Win32IDE-Native: linked against rawrxd_production_hardening")
        endif()
        if(RAWRXD_BUILD_SECURITY_LIB)
            target_link_libraries(RawrXD-Win32IDE-Native PRIVATE
                rawrxd_security
            )
            message(STATUS "RawrXD-Win32IDE-Native: linked against rawrxd_security")
        endif()
            message(WARNING "RawrXD-Win32IDE-Native: rawrxd_production_hardening is not a target; the IDE will start without hardening")
        set_target_properties(RawrXD-Win32IDE-Native PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
            WIN32_EXECUTABLE TRUE
        )
        # The CPU executor's row_geom()/row_dot()/dequant_all() read block size,
        # type size and the to_float converter from ggml's authoritative type
        # table, so ggml_get_type_traits must link.
        if(TARGET ggml)
            target_link_libraries(RawrXD-Win32IDE-Native PRIVATE ggml)
            target_compile_definitions(RawrXD-Win32IDE-Native PRIVATE HAVE_GGML=1)
        endif()
        if(TARGET rawrxd_agent_esp)
            target_link_libraries(RawrXD-Win32IDE-Native PRIVATE rawrxd_agent_esp)
        endif()
        # Link the real Deep2Engine so Win32IDE_Deep2Bridge uses GPU inference
        if(TARGET deep2_engine_lib)
            target_link_libraries(RawrXD-Win32IDE-Native PRIVATE deep2_engine_lib)
            target_compile_definitions(RawrXD-Win32IDE-Native PRIVATE HAVE_DEEP2_ENGINE=1)
        endif()
        message(STATUS "RawrXD-Win32IDE-Native: native dependency-free Win32 IDE enabled")
    else()
        list(APPEND RAWRXD_QT_TARGETS RawrXD-Win32IDE-Native)
        message(STATUS "RawrXD-Win32IDE-Native EXCLUDED: Win32 IDE sources absent from this tree")
    endif()
endif()

# Terminal test executable (MSVC only, placed in bin-msvc)
if(FALSE AND MSVC AND EXISTS "${CMAKE_SOURCE_DIR}/src/win32app/test_terminal.cpp") # Disabled until headers exist
    add_executable(test_terminal
        src/win32app/test_terminal.cpp
        src/win32app/Win32TerminalManager.cpp
        src/win32app/Win32TerminalManager.h
    )
    set_target_properties(test_terminal PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-msvc"
    )
endif()

# Chat application (MSVC only, taskbar integration)
if(FALSE AND MSVC AND ENABLE_COPILOT AND EXISTS "${CMAKE_SOURCE_DIR}/src/win32app/main_chat.cpp") # Disabled until headers exist
    add_executable(RawrXD-Chat
        src/win32app/main_chat.cpp
        src/win32app/Win32ChatApp.cpp
        src/win32app/Win32ChatApp.h
        src/win32app/ContextManager.h
    )

    target_link_libraries(RawrXD-Chat PRIVATE
        comctl32
        shell32
        winhttp
    )

    target_include_directories(RawrXD-Chat PRIVATE
        ${CMAKE_SOURCE_DIR}/include
    )

    target_compile_options(RawrXD-Chat PRIVATE /EHsc)

    set_target_properties(RawrXD-Chat PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-msvc"
        WIN32_EXECUTABLE TRUE
    )
endif()

# Vulkan SDK (optional now; can be disabled if not installed)
option(BUILD_TESTS "Build unit tests (disables Vulkan requirement)" OFF)
# ENABLE_VULKAN defined earlier at line 105 - removed duplicate definition
if(ENABLE_VULKAN)
    if(NOT BUILD_TESTS)
        find_package(Vulkan REQUIRED)
    else()
        find_package(Vulkan QUIET)
    endif()
else()
    message(STATUS "Vulkan disabled via ENABLE_VULKAN=OFF; skipping find_package")
endif()


# Compiler selection: do not force MinGW globally. Let the generator/toolchain decide.
# If you need MinGW, configure the build folder with `-G "MinGW Makefiles"`.

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

if(FALSE) # Disabled until headers exist
# Add main executable
add_executable(RawrXD-ModelLoader
    src/main.cpp
    src/gguf_loader.cpp
    src/vulkan_compute.cpp
    src/hf_downloader.cpp
    src/gui.cpp
    src/api_server.cpp
    src/settings.cpp
    src/telemetry.cpp
    src/telemetry/ai_metrics.cpp
    src/overclock_vendor.cpp
    src/overclock_governor.cpp
    src/baseline_profile.cpp
)

# Console-based IDE (non-Qt) interactive shell
add_executable(RawrXD-CLI
    src/rawrxd_cli.cpp
    src/gguf_loader.cpp
    src/vulkan_compute.cpp
    src/hf_downloader.cpp
    src/api_server.cpp
    src/settings.cpp
    src/telemetry.cpp
    src/overclock_vendor.cpp
    src/overclock_governor.cpp
    src/baseline_profile.cpp
)

target_link_libraries(RawrXD-CLI PRIVATE wbemuuid pdh)
if(Vulkan_FOUND)
    target_link_libraries(RawrXD-CLI PRIVATE Vulkan::Vulkan)
endif()
set_target_properties(RawrXD-CLI PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-${COMPILER_SUFFIX}")

if(Qt6Widgets_FOUND)
    message(STATUS "Qt6Widgets already configured above")
endif()
# Link libraries
target_link_libraries(RawrXD-ModelLoader PRIVATE
    ws2_32
    winmm
    imm32
    ole32
    oleaut32
    winspool
    advapi32
    shell32
    user32
    gdi32
    wbemuuid
    pdh
    cpu_inference_engine
)

if(Vulkan_FOUND)
    target_link_libraries(RawrXD-ModelLoader PRIVATE Vulkan::Vulkan)
endif()

# Compiler flags
if(MSVC)
    target_compile_options(RawrXD-ModelLoader PRIVATE $<$<CONFIG:Release>:/O2> /EHsc)
else()
    target_compile_options(RawrXD-ModelLoader PRIVATE -O2 -fexceptions)
endif()
target_compile_definitions(RawrXD-ModelLoader PRIVATE _CRT_SECURE_NO_WARNINGS _WINDOWS)

# Output directory
set_target_properties(RawrXD-ModelLoader PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-${COMPILER_SUFFIX}"
)
endif()

if(FALSE) # Disabled until headers exist
# Benchmark target
add_executable(model_loader_bench
    src/bench_main.cpp
    src/gguf_loader.cpp
    src/vulkan_compute.cpp
    src/settings.cpp
    src/telemetry.cpp
)

target_link_libraries(model_loader_bench PRIVATE wbemuuid pdh)
if(Vulkan_FOUND)
    target_link_libraries(model_loader_bench PRIVATE Vulkan::Vulkan)
endif()

# Stress test executable for overclock governor development
add_executable(rawrxd_stress
    src/oc_stress.cpp
    src/telemetry.cpp
)
target_link_libraries(rawrxd_stress PRIVATE wbemuuid pdh)
set_target_properties(rawrxd_stress PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-${COMPILER_SUFFIX}")
if(MSVC)
    target_compile_options(model_loader_bench PRIVATE $<$<CONFIG:Release>:/O2> /EHsc)
else()
    target_compile_options(model_loader_bench PRIVATE -O2 -fexceptions)
endif()
set_target_properties(model_loader_bench PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-${COMPILER_SUFFIX}"
)
endif()

# Unit test targets (separate small executables) - DISABLED - files don't exist
# add_executable(rawrxd_test_baseline
#     tests/test_baseline_main.cpp
#     src/baseline_profile.cpp
#     src/settings.cpp
# )
# target_link_libraries(rawrxd_test_baseline PRIVATE wbemuuid pdh)
# set_target_properties(rawrxd_test_baseline PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# add_executable(rawrxd_test_pid
#     tests/test_pid_main.cpp
#     src/overclock_governor.cpp
#     src/overclock_vendor.cpp
#     src/settings.cpp
# )
# target_link_libraries(rawrxd_test_pid PRIVATE wbemuuid pdh)
# set_target_properties(rawrxd_test_pid PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

if(FALSE) # Disabled until headers exist
# Native Win32 IDE executable (no Qt dependencies)
add_executable(RawrXD-IDE WIN32
    src/ide_main.cpp
    src/ide_window.cpp
)

target_include_directories(RawrXD-IDE PRIVATE include)
target_link_libraries(RawrXD-IDE PRIVATE 
    comctl32 
    comdlg32 
    shell32
)

set_target_properties(RawrXD-IDE PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    WIN32_EXECUTABLE TRUE
)
endif()

if(FALSE) # Disabled until headers exist
# Simple C++ IDE with advanced features stubs
add_executable(RawrXD-SimpleIDE
    src/qtapp/main_simple.cpp
    src/qtapp/MainWindowSimple.cpp
    src/qtapp/MainWindowSimple.h
    src/editor_buffer.cpp
    src/syntax_engine.cpp
    src/overclock_vendor.cpp
    src/overclock_governor.cpp
    src/settings.cpp
    src/telemetry.cpp
    src/baseline_profile.cpp
    src/gguf_loader.cpp
    src/telemetry/ai_metrics.cpp
    src/session/ai_session.cpp
    src/backend/ollama_client.cpp
    src/backend/websocket_server.cpp
    src/backend/agentic_tools.cpp
    src/tools/file_ops.cpp
    src/tools/git_client.cpp
    src/context/indexer.cpp
    src/context/semantic_store.cpp
    src/ui/split_layout.cpp
    src/ui/chat_panel.cpp
)

target_include_directories(RawrXD-SimpleIDE PRIVATE include)
target_link_libraries(RawrXD-SimpleIDE PRIVATE 
    user32 
    gdi32 
    wbemuuid 
    pdh
    winhttp
    ws2_32
)

set_target_properties(RawrXD-SimpleIDE PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Enable standard exception semantics and optimization for SimpleIDE
if(MSVC)
    target_compile_options(RawrXD-SimpleIDE PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
else()
    target_compile_options(RawrXD-SimpleIDE PRIVATE -fexceptions -O2)
endif()
target_compile_definitions(RawrXD-SimpleIDE PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Chromatic Wave Demo - Chameleon/Neon effects with D3D11 (Windows-only)
# Target: 540Hz @ 3840x2160 (4K UHD)
if(WIN32)
add_executable(RawrXD-Chromatic WIN32
    src/chromatic_main.cpp
    src/ui/chromatic_window.cpp
)

target_include_directories(RawrXD-Chromatic PRIVATE 
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(RawrXD-Chromatic PRIVATE 
    user32 
    gdi32 
    d3d11
    dxgi
    d3dcompiler
)

set_target_properties(RawrXD-Chromatic PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    WIN32_EXECUTABLE TRUE
)

if(MSVC)
    target_compile_options(RawrXD-Chromatic PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
else()
    target_compile_options(RawrXD-Chromatic PRIVATE -fexceptions -O2)
endif()
target_compile_definitions(RawrXD-Chromatic PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
endif() # WIN32 - RawrXD-Chromatic

# Agentic IDE - Advanced AI-powered IDE with terminal integration (Qt-based GUI app)
# Enabled with Qt6 6.7.2+ support
if(Qt6_FOUND AND Qt6_VERSION VERSION_GREATER_EQUAL 6.7.2)
    message(STATUS "Building RawrXD-AgenticIDE with Qt ${Qt6_VERSION}")
    
    # Check for required source files - v5.0 Clean Implementation
    set(AGENTICIDE_SOURCES
        src/qtapp/main_v5.cpp
        src/qtapp/MainWindow_v5.cpp
    )
    
    # Check if additional source files exist
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/agentic_ide.cpp")
        list(APPEND AGENTICIDE_SOURCES src/agentic_ide.cpp)
    endif()

    if(EXISTS "${CMAKE_SOURCE_DIR}/src/production_agentic_ide.cpp")
        list(APPEND AGENTICIDE_SOURCES src/production_agentic_ide.cpp)
    endif()

    if(EXISTS "${CMAKE_SOURCE_DIR}/include/production_agentic_ide.h")
        list(APPEND AGENTICIDE_SOURCES include/production_agentic_ide.h)
        set_source_files_properties(include/production_agentic_ide.h PROPERTIES SKIP_AUTOMOC OFF)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/scalar_server.cpp")
        list(APPEND AGENTICIDE_SOURCES src/scalar_server.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/agentic_chat.cpp")
        list(APPEND AGENTICIDE_SOURCES src/agentic_chat.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/chat_workspace.cpp")
        list(APPEND AGENTICIDE_SOURCES src/chat_workspace.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/multi_tab_editor.cpp")
        list(APPEND AGENTICIDE_SOURCES src/multi_tab_editor.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/terminal_pool.cpp")
        list(APPEND AGENTICIDE_SOURCES src/terminal_pool.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/agentic_engine.cpp")
        list(APPEND AGENTICIDE_SOURCES src/agentic_engine.cpp)
        list(APPEND AGENTICIDE_SOURCES src/zero_day_agentic_engine.cpp)
        if(EXISTS "${CMAKE_SOURCE_DIR}/include/zero_day_agentic_engine.hpp")
            list(APPEND AGENTICIDE_SOURCES include/zero_day_agentic_engine.hpp)
        endif()
        # Add tool registry initialization for agent system
        # NOTE: tool_registry_init.cpp has JSON initialization issues with MSVC
        # Temporarily disabled until fixed
        # if(EXISTS "${CMAKE_SOURCE_DIR}/src/tool_registry_init.cpp")
        #     list(APPEND AGENTICIDE_SOURCES src/tool_registry_init.cpp)
        # endif()
        if(EXISTS "${CMAKE_SOURCE_DIR}/include/tool_registry_init.hpp")
            list(APPEND AGENTICIDE_SOURCES include/tool_registry_init.hpp)
        endif()
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/chat_interface.cpp")
        list(APPEND AGENTICIDE_SOURCES src/chat_interface.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/agentic_copilot_bridge.cpp")
        list(APPEND AGENTICIDE_SOURCES src/agentic_copilot_bridge.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/ai_code_assistant.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/ai_code_assistant.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/ai_code_assistant_panel.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/ai_code_assistant_panel.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/settings_dialog.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/settings_dialog.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/settings_manager.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/settings_manager.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/gui/ModelConversionDialog.cpp")
        list(APPEND AGENTICIDE_SOURCES src/gui/ModelConversionDialog.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/TerminalManager.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/TerminalManager.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/utils/InferenceSettingsManager.cpp")
        list(APPEND AGENTICIDE_SOURCES src/utils/InferenceSettingsManager.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/ui/InferenceSettingsDialog.cpp")
        list(APPEND AGENTICIDE_SOURCES src/ui/InferenceSettingsDialog.cpp)
    endif()
    # if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/distributed_trainer.cpp")  # Temporarily disabled
    #     list(APPEND AGENTICIDE_SOURCES src/qtapp/distributed_trainer.cpp)
    # endif()
    # if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/interpretability_panel.cpp")  # Temporarily disabled
    #     list(APPEND AGENTICIDE_SOURCES src/qtapp/interpretability_panel.cpp)
    # endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/tokenizer_selector.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/tokenizer_selector.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/tokenizer_selector.h")
        set_source_files_properties(src/qtapp/tokenizer_selector.h PROPERTIES SKIP_AUTOMOC ON)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/real_time_completion_engine.cpp")
        list(APPEND AGENTICIDE_SOURCES src/real_time_completion_engine.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/include/tokenizer_selector.h")
        list(APPEND AGENTICIDE_SOURCES include/tokenizer_selector.h)
        set_source_files_properties(include/tokenizer_selector.h PROPERTIES SKIP_AUTOMOC OFF)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/ci_cd_settings.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/ci_cd_settings.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/ci_cd_settings.h")
        set_source_files_properties(src/qtapp/ci_cd_settings.h PROPERTIES SKIP_AUTOMOC ON)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/include/ci_cd_settings.h")
        list(APPEND AGENTICIDE_SOURCES include/ci_cd_settings.h)
        set_source_files_properties(include/ci_cd_settings.h PROPERTIES SKIP_AUTOMOC OFF)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/checkpoint_manager.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/checkpoint_manager.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/checkpoint_manager.h")
        set_source_files_properties(src/qtapp/checkpoint_manager.h PROPERTIES SKIP_AUTOMOC ON)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/include/checkpoint_manager.h")
        list(APPEND AGENTICIDE_SOURCES include/checkpoint_manager.h)
        set_source_files_properties(include/checkpoint_manager.h PROPERTIES SKIP_AUTOMOC OFF)
    endif()

    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/inflate_deflate_cpp.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/inflate_deflate_cpp.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/file_browser.cpp")
        list(APPEND AGENTICIDE_SOURCES src/file_browser.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/inference_engine.cpp")
        list(APPEND AGENTICIDE_SOURCES src/inference_engine.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/inference_engine.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/inference_engine.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/sentencepiece_tokenizer.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/sentencepiece_tokenizer.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/vocabulary_loader.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/vocabulary_loader.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/bpe_tokenizer.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/bpe_tokenizer.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/transformer_inference.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/transformer_inference.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/gguf_loader.hpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/gguf_loader.hpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/gguf_loader.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/gguf_loader.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/gguf_loader.cpp")
        list(APPEND AGENTICIDE_SOURCES src/gguf_loader.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/gguf_vocab_resolver.cpp")
        list(APPEND AGENTICIDE_SOURCES src/gguf_vocab_resolver.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/vulkan_compute.cpp")
        list(APPEND AGENTICIDE_SOURCES src/vulkan_compute.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/transformer_block_scalar.cpp")
        list(APPEND AGENTICIDE_SOURCES src/transformer_block_scalar.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/settings.cpp")
        list(APPEND AGENTICIDE_SOURCES src/settings.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/planning_agent.cpp")
        list(APPEND AGENTICIDE_SOURCES src/planning_agent.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/plan_orchestrator.cpp")
        list(APPEND AGENTICIDE_SOURCES src/plan_orchestrator.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/lsp_client.cpp")
        list(APPEND AGENTICIDE_SOURCES src/lsp_client.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/agentic_text_edit.cpp")
        list(APPEND AGENTICIDE_SOURCES src/agentic_text_edit.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/ghost_text_renderer.cpp")
        list(APPEND AGENTICIDE_SOURCES src/ghost_text_renderer.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/universal_model_router.cpp")
        list(APPEND AGENTICIDE_SOURCES src/universal_model_router.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/cloud_api_client.cpp")
        list(APPEND AGENTICIDE_SOURCES src/cloud_api_client.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/cloud_api_client.h")
        list(APPEND AGENTICIDE_SOURCES src/cloud_api_client.h)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/tool_registry.cpp")
        list(APPEND AGENTICIDE_SOURCES src/tool_registry.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/ai_completion_provider.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/ai_completion_provider.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/model_loader_thread.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/model_loader_thread.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/telemetry.cpp")
        list(APPEND AGENTICIDE_SOURCES src/telemetry.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/todo_manager.cpp")
        list(APPEND AGENTICIDE_SOURCES src/todo_manager.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/todo_dock.cpp")
        list(APPEND AGENTICIDE_SOURCES src/todo_dock.cpp)
    endif()
    # NOTE: test_agentic_executor.cpp is excluded - it has its own main() for standalone testing
    # if(EXISTS "${CMAKE_SOURCE_DIR}/src/test_agentic_executor.cpp")
    #     list(APPEND AGENTICIDE_SOURCES src/test_agentic_executor.cpp)
    # endif()
    # NOTE: inference_engine_stub.cpp is excluded because src/qtapp/inference_engine.cpp is the primary implementation
    # if(EXISTS "${CMAKE_SOURCE_DIR}/src/inference_engine_stub.cpp")
    #     list(APPEND AGENTICIDE_SOURCES src/inference_engine_stub.cpp)
    # endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/agentic_executor.cpp")
        list(APPEND AGENTICIDE_SOURCES src/agentic_executor.cpp)
    endif()
    # Add marketplace components - include headers for MOC processing
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/marketplace/extension_marketplace_manager.cpp")
        list(APPEND AGENTICIDE_SOURCES src/marketplace/extension_marketplace_manager.cpp)
        list(APPEND AGENTICIDE_SOURCES include/marketplace/extension_marketplace_manager.h)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/marketplace/vsix_installer.cpp")
        list(APPEND AGENTICIDE_SOURCES src/marketplace/vsix_installer.cpp)
        list(APPEND AGENTICIDE_SOURCES include/marketplace/vsix_installer.h)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/marketplace/enterprise_policy_engine.cpp")
        list(APPEND AGENTICIDE_SOURCES src/marketplace/enterprise_policy_engine.cpp)
        list(APPEND AGENTICIDE_SOURCES include/marketplace/enterprise_policy_engine.h)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/marketplace/offline_cache_store.cpp")
        list(APPEND AGENTICIDE_SOURCES src/marketplace/offline_cache_store.cpp)
        list(APPEND AGENTICIDE_SOURCES include/marketplace/offline_cache_store.h)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/marketplace/marketplace_ui_view.cpp")
        list(APPEND AGENTICIDE_SOURCES src/marketplace/marketplace_ui_view.cpp)
        list(APPEND AGENTICIDE_SOURCES include/marketplace/marketplace_ui_view.h)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/model_trainer.cpp")
        list(APPEND AGENTICIDE_SOURCES src/model_trainer.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/agentic_file_operations.cpp")
        list(APPEND AGENTICIDE_SOURCES src/agentic_file_operations.cpp)
        list(APPEND AGENTICIDE_SOURCES include/agentic_file_operations.h)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/memory_space_manager.cpp")
        list(APPEND AGENTICIDE_SOURCES src/memory_space_manager.cpp)
        list(APPEND AGENTICIDE_SOURCES include/memory_space_manager.h)
    endif()
    
    # Error handler (used by AgenticEngine)
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/agentic_error_handler.cpp")
        list(APPEND AGENTICIDE_SOURCES src/agentic_error_handler.cpp)
        list(APPEND AGENTICIDE_SOURCES include/agentic_error_handler.h)
    endif()
    
    # Observability and Loop State (used by AgenticErrorHandler)
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/agentic_observability.cpp")
        list(APPEND AGENTICIDE_SOURCES src/agentic_observability.cpp)
        list(APPEND AGENTICIDE_SOURCES include/agentic_observability.h)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/agentic_loop_state.cpp")
        list(APPEND AGENTICIDE_SOURCES src/agentic_loop_state.cpp)
        list(APPEND AGENTICIDE_SOURCES include/agentic_loop_state.h)
    endif()
    
    # Phase 1: ModelTrainer UI Components
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/training_dialog.cpp")
        list(APPEND AGENTICIDE_SOURCES src/training_dialog.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/training_progress_dock.cpp")
        list(APPEND AGENTICIDE_SOURCES src/training_progress_dock.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/model_registry.cpp")
        list(APPEND AGENTICIDE_SOURCES src/model_registry.cpp)
    endif()
    
    # Phase 2: Advanced Monitoring Components
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/profiler.cpp")
        list(APPEND AGENTICIDE_SOURCES src/profiler.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/observability_dashboard.cpp")
        list(APPEND AGENTICIDE_SOURCES src/observability_dashboard.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/hardware_backend_selector.cpp")
        list(APPEND AGENTICIDE_SOURCES src/hardware_backend_selector.cpp)
    endif()
    
    # Phase 2 Polish: UI Enhancement Components (Investor Demo Features)
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/ui/diff_dock.cpp")
        list(APPEND AGENTICIDE_SOURCES src/ui/diff_dock.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/ui/gpu_backend_selector.cpp")
        list(APPEND AGENTICIDE_SOURCES src/ui/gpu_backend_selector.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/ui/auto_model_downloader.cpp")
        list(APPEND AGENTICIDE_SOURCES src/ui/auto_model_downloader.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/ui/model_download_dialog_new.cpp")
        list(APPEND AGENTICIDE_SOURCES src/ui/model_download_dialog_new.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/ui/telemetry_optin_dialog.cpp")
        list(APPEND AGENTICIDE_SOURCES src/ui/telemetry_optin_dialog.cpp)
    endif()
    
    # Phase 3: Production Enhancements
    # Security, checkpoint, and CI/CD management components
    # TEMPORARILY DISABLED - not needed for v5.0 clean build
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/security_manager.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/security_manager.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/checkpoint_manager.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/checkpoint_manager.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/ci_cd_settings.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/ci_cd_settings.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/tokenizer_selector.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/tokenizer_selector.cpp)
    endif()
    
    # Add moc_includes.cpp to force AUTOMOC to process all Q_OBJECT headers
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/moc_includes.cpp")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/moc_includes.cpp)
    endif()
    
    # Enterprise Telemetry Window - must be included for MOC processing
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/qtapp/TelemetryWindow.h")
        list(APPEND AGENTICIDE_SOURCES src/qtapp/TelemetryWindow.h)
    endif()
    
    # Phase 1 & 2: Response Parsing, Model Testing, and Library Integration
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/response_parser.cpp")
        list(APPEND AGENTICIDE_SOURCES src/response_parser.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/model_tester.cpp")
        list(APPEND AGENTICIDE_SOURCES src/model_tester.cpp)
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/library_integration.cpp")
        list(APPEND AGENTICIDE_SOURCES src/library_integration.cpp)
    endif()
    
    # Phase 3: Real AI Implementation with Multi-Backend LLM Support
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/ai_implementation.cpp")
        list(APPEND AGENTICIDE_SOURCES src/ai_implementation.cpp)
    endif()
    
    # Phase 3: Production Streaming Support
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/streaming_engine.cpp")
        list(APPEND AGENTICIDE_SOURCES src/streaming_engine.cpp)
    endif()

    # ========================================
    # Main Application Target: RawrXD-AgenticIDE
    # ========================================
    add_library(brutal_compression_lib STATIC kernels/deflate_brutal_masm.asm)
    set_target_properties(brutal_compression_lib PROPERTIES LINKER_LANGUAGE ASM_MASM)

    add_executable(RawrXD-AgenticIDE ${AGENTICIDE_SOURCES})
    
    target_link_libraries(RawrXD-AgenticIDE
        PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Concurrent
        Qt6::Network
        Qt6::WebSockets
        brutal_compression_lib
    )

    # Link ggml library if it was built
    if(TARGET ggml)
        target_link_libraries(RawrXD-AgenticIDE PRIVATE ggml)
        target_compile_definitions(RawrXD-AgenticIDE PRIVATE HAVE_GGML=1)
    endif()

    # Enable Qt MOC for QObject-derived classes - must be set BEFORE any other properties
    if(TARGET RawrXD-AgenticIDE)
        set_target_properties(RawrXD-AgenticIDE PROPERTIES 
            AUTOMOC ON
            AUTOMOC_MOC_OPTIONS "-I${CMAKE_SOURCE_DIR}/include;-I${CMAKE_CURRENT_SOURCE_DIR}/src/qtapp;-I${CMAKE_CURRENT_SOURCE_DIR}/src/ui;-I${CMAKE_CURRENT_SOURCE_DIR}/src/utils;-I${CMAKE_CURRENT_SOURCE_DIR}/src/gui"
        )
    endif()

    # MOC wrapping for checkpoint_manager, ci_cd_settings, tokenizer_selector is handled
    # by RawrXD-QtShell target via qt_wrap_cpp to avoid duplicate generation

    # Explicitly set MOC include paths
    target_include_directories(RawrXD-AgenticIDE BEFORE PRIVATE 
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src/qtapp
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/src
    )
    target_link_libraries(RawrXD-AgenticIDE PRIVATE 
        user32 
        gdi32 
        wbemuuid 
        pdh
        winhttp
        ws2_32
        comctl32
        d3d11
        dxgi
        d3dcompiler
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Network
        Qt6::Sql
        brutal_compression_lib
        quant_utils
        ggml_interface
    )

    if(CURL_FOUND)
        target_link_libraries(RawrXD-AgenticIDE PRIVATE CURL::libcurl)
        target_compile_definitions(RawrXD-AgenticIDE PRIVATE HAVE_CURL=1)
    else()
        target_compile_definitions(RawrXD-AgenticIDE PRIVATE HAVE_CURL=0)
    endif()

    if(ZSTD_FOUND)
        target_link_libraries(RawrXD-AgenticIDE PRIVATE zstd::libzstd_shared)
        target_compile_definitions(RawrXD-AgenticIDE PRIVATE HAVE_ZSTD=1)
    else()
        target_compile_definitions(RawrXD-AgenticIDE PRIVATE HAVE_ZSTD=0)
    endif()
    
    # Add Vulkan linkage if available
    if(Vulkan_FOUND)
        target_link_libraries(RawrXD-AgenticIDE PRIVATE Vulkan::Vulkan)
        target_compile_definitions(RawrXD-AgenticIDE PRIVATE HAVE_VULKAN=1)
    endif()

    set_target_properties(RawrXD-AgenticIDE PROPERTIES 
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        WIN32_EXECUTABLE TRUE
    )

    if(MSVC)
        target_compile_options(RawrXD-AgenticIDE PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(RawrXD-AgenticIDE PRIVATE -fexceptions -O2)
    endif()
    target_compile_definitions(RawrXD-AgenticIDE PRIVATE _CRT_SECURE_NO_WARNINGS)
    
    # Automatic DLL deployment for RawrXD-AgenticIDE
    deploy_runtime_dependencies(RawrXD-AgenticIDE)
    
    # Include smoke tests
    if(EXISTS "${CMAKE_SOURCE_DIR}/smoke_tests.cmake")
        include(${CMAKE_SOURCE_DIR}/smoke_tests.cmake)
    endif()
    
    message(STATUS "RawrXD-AgenticIDE: Advanced AI-powered IDE enabled with Qt ${Qt6_VERSION}")
    message(STATUS "AgenticIDE sources: ${AGENTICIDE_SOURCES}")
    
else()
    message(STATUS "Qt6 not found or version < 6.7.2; skipping RawrXD-AgenticIDE target")
endif()

message(STATUS "RawrXD-ModelLoader configured successfully with Clang C++20")

# Stub test to verify WinMain can be reached at all (Windows-only source)
if(WIN32)
    add_executable(stub_test WIN32 src/stub_main.cpp)
    # std::ofstream can throw; without /EHsc MSVC warns C4530 under /W4 /WX.
    if(MSVC)
        target_compile_options(stub_test PRIVATE /EHsc)
    else()
        target_compile_options(stub_test PRIVATE -fexceptions)
    endif()
endif()

# Qt-dependent target: test_ide_main (requires Qt6)
if(Qt6_FOUND)
    # Test IDE main - test if Qt can initialize
    add_executable(test_ide_main WIN32 src/test_ide_main.cpp src/agentic_ide.cpp)
    set_target_properties(test_ide_main PROPERTIES AUTOMOC ON)
    target_link_libraries(test_ide_main PRIVATE 
        Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network Qt6::Sql
        user32 gdi32 wbemuuid pdh winhttp ws2_32 comctl32 d3d11 dxgi d3dcompiler
    )
    target_include_directories(test_ide_main PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/qtapp)

    # Copy Qt DLLs for test_ide_main
    add_custom_command(TARGET test_ide_main POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:Qt6::Core>"
            "$<TARGET_FILE:Qt6::Gui>"
            "$<TARGET_FILE:Qt6::Widgets>"
            "$<TARGET_FILE_DIR:test_ide_main>"
        COMMENT "Copying Qt DLLs for test_ide_main"
    )

    # Copy platform plugins for test_ide_main
    add_custom_command(TARGET test_ide_main POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:test_ide_main>/platforms"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${Qt6_DIR}/../../../plugins/platforms/qwindows.dll"
            "$<TARGET_FILE_DIR:test_ide_main>/platforms/"
        COMMENT "Copying Qt platform plugins for test_ide_main"
    )
else()
    list(APPEND RAWRXD_QT_TARGETS test_ide_main)
    message(STATUS "Qt target excluded (Qt6 unavailable): test_ide_main")
endif()
# Qt-dependent target: test_qmainwindow (requires Qt6)
if(Qt6_FOUND)
    # Test QMainWindow - simplest Qt GUI application
    add_executable(test_qmainwindow WIN32 src/test_qmainwindow.cpp)
    set_target_properties(test_qmainwindow PROPERTIES AUTOMOC ON)
    target_link_libraries(test_qmainwindow PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets)
    target_include_directories(test_qmainwindow PRIVATE ${CMAKE_SOURCE_DIR}/include)

    # Copy Qt DLLs for test_qmainwindow
    add_custom_command(TARGET test_qmainwindow POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:Qt6::Core>"
            "$<TARGET_FILE:Qt6::Gui>"
            "$<TARGET_FILE:Qt6::Widgets>"
            "$<TARGET_FILE_DIR:test_qmainwindow>"
        COMMENT "Copying Qt DLLs for test_qmainwindow"
    )

    # Copy platform plugins for test_qmainwindow
    add_custom_command(TARGET test_qmainwindow POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:test_qmainwindow>/platforms"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${Qt6_DIR}/../../../plugins/platforms/qwindows.dll"
            "$<TARGET_FILE_DIR:test_qmainwindow>/platforms/"
        COMMENT "Copying Qt platform plugins for test_qmainwindow"
    )
else()
    list(APPEND RAWRXD_QT_TARGETS test_qmainwindow)
    message(STATUS "Qt target excluded (Qt6 unavailable): test_qmainwindow")
endif()
# Qt-dependent target: test_header (requires Qt6)
if(Qt6_FOUND)
    # Test if agentic_ide.h header itself causes a crash
    add_executable(test_header src/agentic_ide_test.cpp)
    set_target_properties(test_header PROPERTIES AUTOMOC ON)
    target_link_libraries(test_header PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets)
    target_include_directories(test_header PRIVATE ${CMAKE_SOURCE_DIR}/include)
else()
    list(APPEND RAWRXD_QT_TARGETS test_header)
    message(STATUS "Qt target excluded (Qt6 unavailable): test_header")
endif()
if(FALSE) # Disabled until headers exist
# IDE Test Runner - Comprehensive function testing
add_executable(RawrXD-TestRunner
    src/win32app/test_runner.cpp
    src/win32app/Win32IDE.cpp
    src/win32app/Win32IDE_Commands.cpp
    src/win32app/Win32IDE_Debugger.cpp
    src/win32app/Win32IDE_FileOps.cpp
    src/win32app/Win32IDE_PowerShell.cpp
    src/win32app/Win32IDE_PowerShellPanel.cpp
    src/win32app/Win32IDE_Sidebar.cpp
    src/win32app/Win32IDE_VSCodeUI.cpp
    src/win32app/Win32IDE_AgenticBridge.cpp
    src/win32app/Win32IDE_AgentCommands.cpp
    src/win32app/Win32TerminalManager.cpp
    src/win32app/TransparentRenderer.cpp
    src/win32app/VulkanRenderer.cpp
    src/gguf_loader.cpp
    src/streaming_gguf_loader.cpp
)

target_include_directories(RawrXD-TestRunner PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/win32app
)

target_link_libraries(RawrXD-TestRunner PRIVATE
    user32 gdi32 comctl32 comdlg32 shell32 shlwapi
    d3d11 dxgi d3dcompiler
    d2d1 dwrite dcomp dwmapi
    winhttp
)

set_target_properties(RawrXD-TestRunner PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    WIN32_EXECUTABLE TRUE
)

target_compile_options(RawrXD-TestRunner PRIVATE -O2)
target_compile_definitions(RawrXD-TestRunner PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()

# Q8_0 AVX2 end-to-end bench
if(RAWRXD_BUILD_BENCHMARKS AND EXISTS "${CMAKE_SOURCE_DIR}/tests/bench_q8_0_end2end.cpp")
    add_executable(bench_q8_0_end2end
        tests/bench_q8_0_end2end.cpp
        kernels/q8_0_avx2.cc
        kernels/matmul_kernel_avx2.cc
    )
    target_include_directories(bench_q8_0_end2end PRIVATE ${CMAKE_SOURCE_DIR})
    target_compile_options(bench_q8_0_end2end PRIVATE /arch:AVX2 $<$<CONFIG:Release>:/O2>)
    target_compile_definitions(bench_q8_0_end2end PRIVATE __AVX2__=1)
    set_target_properties(bench_q8_0_end2end PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
endif()

# Flash-Attention AVX2 bench
if(RAWRXD_BUILD_BENCHMARKS AND EXISTS "${CMAKE_SOURCE_DIR}/tests/bench_flash_attn.cpp")
    add_executable(bench_flash_attn
        tests/bench_flash_attn.cpp
        kernels/flash_attn_avx2.cc
        kernels/matmul_kernel_avx2.cc
    )
    target_include_directories(bench_flash_attn PRIVATE ${CMAKE_SOURCE_DIR})
    target_compile_options(bench_flash_attn PRIVATE /arch:AVX2 $<$<CONFIG:Release>:/O2>)
    target_compile_definitions(bench_flash_attn PRIVATE __AVX2__=1)
    set_target_properties(bench_flash_attn PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
endif()
# Flash-Attention All-Quant bench
if(RAWRXD_BUILD_BENCHMARKS AND EXISTS "${CMAKE_SOURCE_DIR}/tests/bench_flash_all_quant.cpp")
    add_executable(bench_flash_all_quant
        tests/bench_flash_all_quant.cpp
        kernels/flash_attn_avx2.cc
        kernels/matmul_kernel_avx2.cc
    )
    target_include_directories(bench_flash_all_quant PRIVATE ${CMAKE_SOURCE_DIR})
    target_compile_options(bench_flash_all_quant PRIVATE /arch:AVX2 $<$<CONFIG:Release>:/O2>)
    target_compile_definitions(bench_flash_all_quant PRIVATE __AVX2__=1)
    set_target_properties(bench_flash_all_quant PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
endif()

# Flash-Attention ASM Puppeteer (Phase 4 Final Form)
if(RAWRXD_BUILD_BENCHMARKS AND EXISTS "${CMAKE_SOURCE_DIR}/tests/bench_flash_asm_puppeteer.cpp")
    if(MSVC)
        # Assemble NASM file via custom command to avoid MSBuild flags leakage
        set(FLASH_ASM_SRC ${CMAKE_SOURCE_DIR}/kernels/flash_attn_asm_avx2.asm)
        set(FLASH_ASM_OBJ ${CMAKE_CURRENT_BINARY_DIR}/flash_attn_asm_avx2.obj)
        add_custom_command(
            OUTPUT ${FLASH_ASM_OBJ}
            COMMAND nasm -f win64 -o ${FLASH_ASM_OBJ} ${FLASH_ASM_SRC}
            DEPENDS ${FLASH_ASM_SRC}
            COMMENT "Assembling flash_attn_asm_avx2.asm with nasm"
        )
        add_custom_target(flash_attn_asm_obj DEPENDS ${FLASH_ASM_OBJ})
        
        add_executable(bench_flash_asm_puppeteer
            tests/bench_flash_asm_puppeteer.cpp
            kernels/flash_attn_avx2.cc
            kernels/matmul_kernel_avx2.cc
        )
        add_dependencies(bench_flash_asm_puppeteer flash_attn_asm_obj)
        target_sources(bench_flash_asm_puppeteer PRIVATE ${FLASH_ASM_OBJ})
        target_include_directories(bench_flash_asm_puppeteer PRIVATE ${CMAKE_SOURCE_DIR})
        target_compile_options(bench_flash_asm_puppeteer PRIVATE /arch:AVX2 $<$<CONFIG:Release>:/O2>)
        target_compile_definitions(bench_flash_asm_puppeteer PRIVATE __AVX2__=1)
        set_target_properties(bench_flash_asm_puppeteer PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        )
    endif()
endif()

# MASM God-Mode deflate benchmark
if(MSVC)
    enable_language(ASM_MASM)
    
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/bench_deflate_masm.cpp")
        # Disabled: deflate_godmode_masm.asm has broken syntax - bench only, not required for IDE
        # add_executable(bench_deflate_godmode tests/bench_deflate_masm.cpp kernels/deflate_godmode_masm.asm)
        # target_compile_definitions(bench_deflate_godmode PRIVATE NO_ZLIB_REF=1 DEFLATE_GODMODE=1)
        # set_target_properties(bench_deflate_godmode PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    endif()

    # Brutal MASM benchmark
    if(RAWRXD_BUILD_BENCHMARKS AND EXISTS "${CMAKE_SOURCE_DIR}/tests/bench_deflate_brutal.cpp")
        add_executable(bench_deflate_brutal tests/bench_deflate_brutal.cpp kernels/deflate_brutal_masm.asm)
        set_target_properties(bench_deflate_brutal PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    endif()

endif()

# ARM-NEON benchmark (cross-compile or native ARM64)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
    enable_language(ASM)
    # Existing generic NEON bench (if present)
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/bench_deflate_neon.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/kernels/deflate_neon.S")
        add_executable(bench_deflate_neon tests/bench_deflate_neon.cpp kernels/deflate_neon.S)
        set_target_properties(bench_deflate_neon PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    endif()

    # Brutal stored-block ARM64 bench
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/bench_deflate_brutal_arm64.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/kernels/deflate_brutal_neon.S")
        add_executable(bench_deflate_brutal_arm64
            tests/bench_deflate_brutal_arm64.cpp
            kernels/deflate_brutal_neon.S
        )
        set_target_properties(bench_deflate_brutal_arm64 PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    endif()
endif()

# Add benchmark for 50MB payload
if(RAWRXD_BUILD_BENCHMARKS AND EXISTS "${CMAKE_SOURCE_DIR}/tests/bench_deflate_50mb.cpp" AND Qt6_FOUND)
    add_executable(bench_deflate_50mb tests/bench_deflate_50mb.cpp)
    target_link_libraries(bench_deflate_50mb PRIVATE brutal_compression_lib)
    set_target_properties(bench_deflate_50mb PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
else()
    list(APPEND RAWRXD_QT_TARGETS bench_deflate_50mb)
    message(STATUS "Qt target excluded (Qt6 unavailable): bench_deflate_50mb")
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/tests/quant_engine_smoke.cpp" AND Qt6_FOUND)
    add_executable(quant_engine_test
        tests/quant_engine_smoke.cpp
    )
    target_link_libraries(quant_engine_test PRIVATE Qt6::Core quant_utils)
    set_target_properties(quant_engine_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
else()
    list(APPEND RAWRXD_QT_TARGETS quant_engine_test)
    message(STATUS "Qt target excluded (Qt6 unavailable): quant_engine_test")
endif()

# Simple scalar quantization smoke test (Q5/Q6 bit-packers)
add_executable(quant_scalar_smoke tests/quant_scalar_smoke.cpp)
set_target_properties(quant_scalar_smoke PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    AUTOMOC OFF
)
# The smoke test uses try/catch around the quant kernels; without /EHsc MSVC
# warns C4530 (and /W4 /WX turns it into an error).
if(MSVC)
    target_compile_options(quant_scalar_smoke PRIVATE /EHsc)
else()
    target_compile_options(quant_scalar_smoke PRIVATE -fexceptions)
endif()

# Qt-dependent target: quant_correctness_tests (requires Qt6)
if(Qt6_FOUND)
    # Comprehensive quantization correctness tests (pack/unpack, error bounds)
    add_executable(quant_correctness_tests tests/quant_correctness_tests.cpp)
    target_link_libraries(quant_correctness_tests PRIVATE Qt6::Core quant_utils)
    set_target_properties(quant_correctness_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        AUTOMOC OFF
    )
else()
    list(APPEND RAWRXD_QT_TARGETS quant_correctness_tests)
    message(STATUS "Qt target excluded (Qt6 unavailable): quant_correctness_tests")
endif()
# Qt-dependent target: test_agent_coordinator (requires Qt6)
if(Qt6_FOUND)
    # Agent Coordinator comprehensive tests (scheduling, cancellation, failure paths)
    add_executable(test_agent_coordinator tests/test_agent_coordinator.cpp)
    target_link_libraries(test_agent_coordinator PRIVATE 
        Qt6::Core 
        Qt6::Test 
        RawrXDOrchestration
    )
    target_include_directories(test_agent_coordinator PRIVATE 
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src/orchestration
    )
    set_target_properties(test_agent_coordinator PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        AUTOMOC ON
    )
else()
    list(APPEND RAWRXD_QT_TARGETS test_agent_coordinator)
    message(STATUS "Qt target excluded (Qt6 unavailable): test_agent_coordinator")
endif()
# Qt-dependent target: test_agent_coordinator_integration (requires Qt6)
if(Qt6_FOUND)
    # Agent Coordinator integration tests (real GGUF model loading + inference)
    add_executable(test_agent_coordinator_integration
        tests/test_agent_coordinator_integration.cpp
        src/model_loader/model_loader.cpp
        src/inference_engine_stub.cpp
        src/qtapp/gguf_server.cpp
        src/gguf_loader.cpp
        src/qtapp/inflate_deflate_cpp.cpp
    )
    target_link_libraries(test_agent_coordinator_integration PRIVATE
        Qt6::Core
        Qt6::Test
        Qt6::Network
        RawrXDOrchestration
        brutal_compression_lib
    )
    target_include_directories(test_agent_coordinator_integration PRIVATE 
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src/orchestration
        ${CMAKE_SOURCE_DIR}/src/model_loader
        ${CMAKE_SOURCE_DIR}/src/qtapp
        ${CMAKE_SOURCE_DIR}/include
    )
    set_target_properties(test_agent_coordinator_integration PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        AUTOMOC ON
    )
else()
    list(APPEND RAWRXD_QT_TARGETS test_agent_coordinator_integration)
    message(STATUS "Qt target excluded (Qt6 unavailable): test_agent_coordinator_integration")
endif()
# KV Cache Infrastructure Test
if(ENABLE_VULKAN)
add_executable(test_kv_cache 
    src/test_kv_cache.cpp
    src/vulkan_compute.cpp
)
target_link_libraries(test_kv_cache PRIVATE Vulkan::Vulkan)
target_include_directories(test_kv_cache PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${Vulkan_INCLUDE_DIRS}
)
set_target_properties(test_kv_cache PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
)
endif()

# Qt-dependent target: test_gguf_loader (requires Qt6)
if(Qt6_FOUND)
    # GGUF Loader Improvements Test
    add_executable(test_gguf_loader
        tests/test_gguf_loader.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
    )
    target_link_libraries(test_gguf_loader PRIVATE 
        Qt6::Core
        brutal_compression_lib  # Supplies codec::deflate, codec::inflate, deflate_brutal_masm
    )
    target_include_directories(test_gguf_loader PRIVATE 
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    set_target_properties(test_gguf_loader PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        AUTOMOC ON
    )
else()
    list(APPEND RAWRXD_QT_TARGETS test_gguf_loader)
    message(STATUS "Qt target excluded (Qt6 unavailable): test_gguf_loader")
endif()
# Qt-dependent target: test_gguf_loader_simple (requires Qt6)
if(Qt6_FOUND)
    # GGUF Loader Simple Test
    add_executable(test_gguf_loader_simple
        tests/test_gguf_loader_simple.cpp
        src/gguf_loader.cpp
        src/gguf_vocab_resolver.cpp
    )
    target_link_libraries(test_gguf_loader_simple PRIVATE 
        Qt6::Core
        brutal_compression_lib  # Supplies codec::deflate, codec::inflate, deflate_brutal_masm
    )
    target_include_directories(test_gguf_loader_simple PRIVATE 
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    set_target_properties(test_gguf_loader_simple PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        AUTOMOC ON
    )
else()
    list(APPEND RAWRXD_QT_TARGETS test_gguf_loader_simple)
    message(STATUS "Qt target excluded (Qt6 unavailable): test_gguf_loader_simple")
endif()
#endif()

# ========================================
# MASM Compiler Suite
# ========================================
# Custom command to assemble MASM files for the compiler suite
if(MSVC)
    enable_language(ASM_MASM)

    # ============================================================
    # MASM Self-Compiling Compiler Suite Integration
    # ============================================================
    # cmake/MASMCompiler.cmake is not present in this tree (the suite's
    # sources are absent). Report explicitly instead of failing configure;
    # ASM_MASM itself remains enabled above for the assembler targets.
    if(EXISTS "${CMAKE_SOURCE_DIR}/cmake/MASMCompiler.cmake")
        include(cmake/MASMCompiler.cmake)
    else()
        message(STATUS "MASM Compiler Suite skipped: cmake/MASMCompiler.cmake not present in this tree")
    endif()
endif()

# ========================================
# TEST SUITE INTEGRATION
# ========================================
if(RAWRXD_BUILD_TESTS)
    message(STATUS "========================================")
    message(STATUS "Building Test Suite")
    message(STATUS "========================================")

    # ------------------------------------------------------------------
    # Qt-FREE agentic resilience tests.
    # These cover the three dependency-free subsystems that give RawrXD its
    # differentiation over competing IDEs:
    #   * adaptive retries  (circuit breaker, exponential backoff + jitter)
    #   * conflict handling (3-way merge, semantic detection, auto-resolution)
    #   * delegated agents  (lifecycle, resource quotas, cross-agent messaging)
    # They MUST build and pass without Qt6, so they stay outside the Qt guard.
    # The target is configured only when every source is present in the tree;
    # when they are absent the exclusion is REPORTED - never silently claimed
    # as built or tested.
    # ------------------------------------------------------------------
    set(AGENTIC_RESILIENCE_SOURCES
        tests/agentic_resilience/agentic_resilience_test.cpp
        src/agent/adaptive_retry.cpp
        src/agent/delegated_agents.cpp
        src/agentic/conflict_resolution.cpp
    )
    set(_AGENTIC_RESILIENCE_COMPLETE TRUE)
    foreach(_src ${AGENTIC_RESILIENCE_SOURCES})
        if(NOT EXISTS "${CMAKE_SOURCE_DIR}/${_src}")
            set(_AGENTIC_RESILIENCE_COMPLETE FALSE)
        endif()
    endforeach()

    if(_AGENTIC_RESILIENCE_COMPLETE)
        add_executable(agentic-resilience-tests
            tests/agentic_resilience/agentic_resilience_test.cpp
            src/agent/adaptive_retry.cpp
            src/agent/delegated_agents.cpp
            src/agentic/conflict_resolution.cpp
        )
        target_include_directories(agentic-resilience-tests PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/agent
            ${CMAKE_SOURCE_DIR}/src/agentic
        )
        if(MSVC)
            target_compile_options(agentic-resilience-tests PRIVATE /std:c++20 /EHsc /W4)
        else()
            target_compile_options(agentic-resilience-tests PRIVATE -std=c++20 -Wall -Wextra)
            find_package(Threads REQUIRED)
            target_link_libraries(agentic-resilience-tests PRIVATE Threads::Threads)
        endif()
        add_test(NAME agentic-resilience COMMAND agentic-resilience-tests)
    else()
        list(APPEND RAWRXD_QT_TARGETS agentic-resilience-tests)
        message(STATUS "agentic-resilience-tests EXCLUDED: sources absent from this tree "
            "(tests/agentic_resilience/agentic_resilience_test.cpp, src/agent/adaptive_retry.cpp, "
            "src/agent/delegated_agents.cpp, src/agentic/conflict_resolution.cpp)")
    endif()

    if(Qt6_FOUND)
        add_subdirectory(tests)
        message(STATUS "Test executables configured - run 'ctest' to execute")
    else()
        list(APPEND RAWRXD_QT_TARGETS test-suite)
        message(STATUS "Qt-dependent test suite EXCLUDED (Qt6 not installed)")
    endif()

    # ------------------------------------------------------------------
    # Component tests (Qt-coupled components): voice_processor, terminal
    # sandbox, semantic diff, model registry, zero retention, AI merge
    # resolver. The components themselves live in src/orchestration,
    # src/terminal, src/git and src/ and are Qt6-based, so these targets
    # are configured only when Qt6 is present. Each is additionally
    # guarded on its sources being present; missing pieces are REPORTED,
    # never silently skipped. Build with Qt6 + gtest available (the CI
    # component jobs provision both).
    # ------------------------------------------------------------------
    # GoogleTest: provisioned by the CI component jobs into 3rdparty/googletest
    # (renamed from the downloaded archive). Without it the component targets
    # are excluded and reported rather than failing configure.
    set(RAWRXD_GTEST_AVAILABLE OFF)
    if(EXISTS "${CMAKE_SOURCE_DIR}/3rdparty/googletest/CMakeLists.txt")
        set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
        set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        add_subdirectory(3rdparty/googletest EXCLUDE_FROM_ALL)
        set(RAWRXD_GTEST_AVAILABLE ON)
    else()
        message(STATUS "Component tests: 3rdparty/googletest not present - "
            "GoogleTest-based component tests will be excluded")
    endif()
    if(Qt6_FOUND AND RAWRXD_GTEST_AVAILABLE AND EXISTS "${CMAKE_SOURCE_DIR}/tests/voice_processor_test.cpp")
        add_executable(voice_processor_test
            tests/voice_processor_test.cpp
            src/orchestration/voice_processor.cpp
        )
        target_include_directories(voice_processor_test PRIVATE
            ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests
        )
        target_link_libraries(voice_processor_test PRIVATE
            Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network Qt6::Multimedia
            Qt6::Test GTest::gtest
        )
        set_target_properties(voice_processor_test PROPERTIES
            AUTOMOC ON RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        add_test(NAME voice-processor COMMAND voice_processor_test)
    else()
        list(APPEND RAWRXD_QT_TARGETS voice_processor_test)
        message(STATUS "voice_processor_test EXCLUDED (Qt6 or sources absent)")
    endif()

    if(Qt6_FOUND AND RAWRXD_GTEST_AVAILABLE AND EXISTS "${CMAKE_SOURCE_DIR}/tests/sandboxed_terminal_test.cpp")
        add_executable(sandboxed_terminal_test
            tests/sandboxed_terminal_test.cpp
            src/terminal/sandboxed_terminal.cpp
        )
        target_include_directories(sandboxed_terminal_test PRIVATE
            ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests
        )
        target_link_libraries(sandboxed_terminal_test PRIVATE
            Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network
            Qt6::Test GTest::gtest
        )
        set_target_properties(sandboxed_terminal_test PROPERTIES
            AUTOMOC ON RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        add_test(NAME sandboxed-terminal COMMAND sandboxed_terminal_test)
    else()
        list(APPEND RAWRXD_QT_TARGETS sandboxed_terminal_test)
        message(STATUS "sandboxed_terminal_test EXCLUDED (Qt6 or sources absent)")
    endif()

    if(Qt6_FOUND AND RAWRXD_GTEST_AVAILABLE AND EXISTS "${CMAKE_SOURCE_DIR}/tests/semantic_diff_analyzer_test.cpp")
        add_executable(semantic_diff_analyzer_test
            tests/semantic_diff_analyzer_test.cpp
            src/git/semantic_diff_analyzer.cpp
        )
        target_include_directories(semantic_diff_analyzer_test PRIVATE
            ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests
        )
        target_link_libraries(semantic_diff_analyzer_test PRIVATE
            Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network
            Qt6::Test GTest::gtest
        )
        set_target_properties(semantic_diff_analyzer_test PROPERTIES
            AUTOMOC ON RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        add_test(NAME semantic-diff-analyzer COMMAND semantic_diff_analyzer_test)
    else()
        list(APPEND RAWRXD_QT_TARGETS semantic_diff_analyzer_test)
        message(STATUS "semantic_diff_analyzer_test EXCLUDED (Qt6 or sources absent)")
    endif()

    if(Qt6_FOUND AND RAWRXD_GTEST_AVAILABLE AND EXISTS "${CMAKE_SOURCE_DIR}/tests/model_registry_test.cpp")
        add_executable(model_registry_test
            tests/model_registry_test.cpp
            src/model_registry.cpp
        )
        target_include_directories(model_registry_test PRIVATE
            ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests
        )
        target_link_libraries(model_registry_test PRIVATE
            Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network Qt6::Sql
            Qt6::Test GTest::gtest
        )
        set_target_properties(model_registry_test PROPERTIES
            AUTOMOC ON RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        add_test(NAME model-registry COMMAND model_registry_test)
    else()
        list(APPEND RAWRXD_QT_TARGETS model_registry_test)
        message(STATUS "model_registry_test EXCLUDED (Qt6 or sources absent)")
    endif()

    if(Qt6_FOUND AND RAWRXD_GTEST_AVAILABLE AND EXISTS "${CMAKE_SOURCE_DIR}/tests/zero_retention_manager_test.cpp")
        add_executable(zero_retention_manager_test
            tests/zero_retention_manager_test.cpp
            src/terminal/zero_retention_manager.cpp
        )
        target_include_directories(zero_retention_manager_test PRIVATE
            ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests
        )
        target_link_libraries(zero_retention_manager_test PRIVATE
            Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network
            Qt6::Test GTest::gtest
        )
        set_target_properties(zero_retention_manager_test PROPERTIES
            AUTOMOC ON RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        add_test(NAME zero-retention COMMAND zero_retention_manager_test)
    else()
        list(APPEND RAWRXD_QT_TARGETS zero_retention_manager_test)
        message(STATUS "zero_retention_manager_test EXCLUDED (Qt6 or sources absent)")
    endif()

    if(Qt6_FOUND AND RAWRXD_GTEST_AVAILABLE AND EXISTS "${CMAKE_SOURCE_DIR}/src/git/ai_merge_resolver.cpp")
        add_executable(ai_merge_resolver_test
            tests/ai_merge_resolver_test.cpp
            src/git/ai_merge_resolver.cpp
        )
        target_include_directories(ai_merge_resolver_test PRIVATE
            ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests
        )
        target_link_libraries(ai_merge_resolver_test PRIVATE
            Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network
            Qt6::Test GTest::gtest
        )
        set_target_properties(ai_merge_resolver_test PROPERTIES
            AUTOMOC ON RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        add_test(NAME ai-merge-resolver-command COMMAND ai_merge_resolver_test)
    else()
        list(APPEND RAWRXD_QT_TARGETS ai_merge_resolver_test)
        message(STATUS "ai_merge_resolver_test EXCLUDED (Qt6 or sources absent)")
    endif()
endif()

# ============================================================================
# RawrXD Agentic Backend Library (Deep2 + Ollama unified inference)
# ============================================================================
# Dependency-free C++20 static library providing:
#   - InferenceBackend abstraction (Deep2 primary, Ollama backup)
#   - BackendRouter with auto/deep2/ollama/manual selection + failover
#   - ToolCallBridge (shared tool registry for both backends)
#   - PersistentTaskBacklog (durable task state)
#   - SelfRepairLoop (autonomous compile/test/diagnose/repair/rollback)
# No Qt dependency. Uses WinHTTP on Windows for HTTP transport.
#
add_library(rawrxd_agentic_backend STATIC
    src/agentic/OllamaBackend.cpp
    src/agentic/Deep2Backend.cpp
    src/agentic/BackendRouter.cpp
    src/agentic/PersistentTaskBacklog.cpp
    src/agentic/SelfRepairLoop.cpp
    src/agentic/AgentMode.cpp
    src/agentic/AgentSession.cpp
    src/agentic/WorkspaceToolHost.cpp
    src/agentic/StructuredAction.cpp
    src/agentic/RawrSwarmEvents.cpp
    src/agentic/RawrLiveTools.cpp
    src/backend/ollama_client.cpp
)
target_include_directories(rawrxd_agentic_backend PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
)
target_link_libraries(rawrxd_agentic_backend PUBLIC
    nlohmann_json::nlohmann_json
)
if(MSVC)
    target_compile_options(rawrxd_agentic_backend PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    target_compile_definitions(rawrxd_agentic_backend PRIVATE NOMINMAX _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
    target_link_libraries(rawrxd_agentic_backend PUBLIC winhttp)
else()
    target_compile_options(rawrxd_agentic_backend PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    find_package(Threads REQUIRED)
    target_link_libraries(rawrxd_agentic_backend PUBLIC Threads::Threads)
endif()
    message(STATUS "rawrxd_agentic_backend: Deep2 + Ollama unified backend library enabled")

# ============================================================================
# Q8_K activation parity harness
# ============================================================================
# Proves that Deep2's Q8_K activation preparation is byte-identical to the
# authoritative ggml reference (3rdparty/ggml/src/ggml-quants.c:2555)
# across zero blocks, signed extrema, rounding ties, saturation and partial
# super-blocks. This is the gate for the DeepSeek 67-position parity run.
if(EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/Q8KParity.cpp")
    add_executable(q8k_parity_tool src/deep2/q8k_parity_tool.cpp
                                 src/deep2/Q8KParity.cpp)
    add_executable(q8k_edge_tests src/deep2/q8k_parity_edge_tests.cpp
                               src/deep2/Q8KParity.cpp)
    foreach(tgt q8k_parity_tool q8k_edge_tests)
        target_include_directories(${tgt} PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/deep2
            ${CMAKE_SOURCE_DIR}/include)
        target_compile_features(${tgt} PRIVATE cxx_std_20)
        target_compile_options(${tgt} PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
        target_compile_definitions(${tgt} PRIVATE
            NOMINMAX _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
    endforeach()
    set_target_properties(q8k_parity_tool q8k_edge_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-${COMPILER_SUFFIX}")

    # Model Genie capability admission + parity certification.
    add_executable(quant_parity_cert src/deep2/quant_parity_cert.cpp
                                  src/deep2/QuantParityRegistry.cpp
                                  src/deep2/Q8KParity.cpp)
    target_include_directories(quant_parity_cert PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${CMAKE_SOURCE_DIR}/include)
    target_compile_features(quant_parity_cert PRIVATE cxx_std_20)
    target_compile_options(quant_parity_cert PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
    target_compile_definitions(quant_parity_cert PRIVATE
        NOMINMAX _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
    set_target_properties(quant_parity_cert PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-${COMPILER_SUFFIX}")

    # K-quant dot-product parity gate (Q8_K packing + Q4_K/Q6_K x Q8_K dots).
    # Compares Deep2's kernels against the vendored ggml reference in this
    # repository, so drift on either side fails the build.
    add_executable(kquant_dot_parity src/deep2/test_kquant_dot_parity.cpp)
    target_include_directories(kquant_dot_parity PRIVATE
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/src/deep2/modelgenie
        ${CMAKE_SOURCE_DIR}/include)
    target_compile_features(kquant_dot_parity PRIVATE cxx_std_20)
    target_compile_options(kquant_dot_parity PRIVATE /EHsc $<$<CONFIG:Release>:/O2>)
    target_compile_definitions(kquant_dot_parity PRIVATE
        NOMINMAX _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
    set_target_properties(kquant_dot_parity PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-${COMPILER_SUFFIX}")

    enable_testing()
    add_test(NAME q8k_edge_tests COMMAND q8k_edge_tests)
    add_test(NAME q8k_byte_parity COMMAND q8k_parity_tool --blocks 8 --seed 12345)
    add_test(NAME quant_parity_cert COMMAND quant_parity_cert --blocks 8 --seed 12345)
    add_test(NAME kquant_dot_parity COMMAND kquant_dot_parity)
    # Gate 2 (MODEL_GENIE_NATIVE_FORWARD_001): manifest consistency. Cross-checks
    # the authoritative registry emitter (quant_parity_cert --json) against the
    # CLI manifest (rawr capabilities --json), rejecting stale or contradictory
    # claims: revision must equal HEAD, primitive binding statuses must agree,
    # "verified" quants must be backed by an executed gate, and every cited
    # parity artifact must exist and record PASS.
    add_test(NAME gate2_manifest_consistency
             COMMAND ${CMAKE_COMMAND} -E env POWERSHELL_TELEMETRY_OPTOUT=1
             powershell -ExecutionPolicy Bypass -NoProfile -File
             "${CMAKE_SOURCE_DIR}/tools/gate2_manifest_consistency.ps1"
             -BuildDir "${CMAKE_BINARY_DIR}")
    message(STATUS "q8k parity harness: Q8_K byte-level verification targets enabled")
endif()

# ============================================================================
# Unified RawrXD CLI (first-class CLI replacing rawrxd_cli.cpp)
# ============================================================================
# Exposes all RawrXD capabilities via CLI: model management, chat, agent,
# build, test, parity, git, and autonomous development. No Qt dependency.
#
if(EXISTS "${CMAKE_SOURCE_DIR}/src/rawrxd_cli_v2.cpp")
    add_executable(RawrXD-CLI-V2 src/rawrxd_cli_v2.cpp
        src/reap_cli_contract.cpp
        src/core/qt_elimination.cpp
        src/project_wizard/project_spec.cpp
        src/project_wizard/project_state_manager.cpp
        src/project_wizard/project_wizard.cpp
        src/project_wizard/project_workflow.cpp
    )
    target_link_libraries(RawrXD-CLI-V2 PRIVATE
        rawrxd_agentic_backend
        deep2_engine_lib
        deep2_snap
        rawrxd_agent_esp
        snap_process_guard
        nlohmann_json::nlohmann_json
        ws2_32
        winmm
    )
    if(Vulkan_FOUND)
        target_link_libraries(RawrXD-CLI-V2 PRIVATE Vulkan::Vulkan)
    endif()
    if(TARGET ggml_interface)
        target_link_libraries(RawrXD-CLI-V2 PRIVATE ggml_interface)
    endif()
    target_include_directories(RawrXD-CLI-V2 PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
        ${CMAKE_SOURCE_DIR}/src/deep2
    )
    target_compile_options(RawrXD-CLI-V2 PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    target_link_options(RawrXD-CLI-V2 PRIVATE /LTCG:OFF)
    target_compile_definitions(RawrXD-CLI-V2 PRIVATE NOMINMAX _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
    set_target_properties(RawrXD-CLI-V2 PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-${COMPILER_SUFFIX}"
        OUTPUT_NAME "rawr"
    )
    message(STATUS "RawrXD-CLI-V2: Unified CLI enabled (output: rawr.exe)")
else()
    list(APPEND RAWRXD_QT_TARGETS RawrXD-CLI-V2)
    message(STATUS "RawrXD-CLI-V2 EXCLUDED: src/rawrxd_cli_v2.cpp not present in this tree")
endif()

# Pure contract/admission tests for the guarded REAP CLI surface.  These tests
# exercise real parsing, semantic validation, and the mandatory fail-closed
# admission result without inventing model/calibration evidence.
if(EXISTS "${CMAKE_SOURCE_DIR}/tests/reap_cli_contract_test.cpp" AND
   EXISTS "${CMAKE_SOURCE_DIR}/src/reap_cli_contract.cpp")
    add_executable(rawr-reap-cli-contract-test
        tests/reap_cli_contract_test.cpp
        src/reap_cli_contract.cpp)
    target_include_directories(rawr-reap-cli-contract-test PRIVATE
        ${CMAKE_SOURCE_DIR}/src)
    target_compile_features(rawr-reap-cli-contract-test PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(rawr-reap-cli-contract-test PRIVATE /EHsc /std:c++20)
    endif()
    enable_testing()
    add_test(NAME rawr_reap_cli_contract COMMAND rawr-reap-cli-contract-test)
endif()

# Read-only REAP inventory/planning surface.  This intentionally does not
# rewrite checkpoints until calibration, router remapping and parity gates
# are implemented; it is the only safe way to expose real model evidence.
if(EXISTS "${CMAKE_SOURCE_DIR}/src/reap_cli.cpp")
    add_executable(rawr-reap src/reap_cli.cpp src/reap_cli_contract.cpp)
    target_link_libraries(rawr-reap PRIVATE deep2_engine_lib)
    target_include_directories(rawr-reap PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/deep2)
    set_target_properties(rawr-reap PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-${COMPILER_SUFFIX}")
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/src/reap_corpus_cli.cpp")
    add_executable(rawr-reap-corpus src/reap_corpus_cli.cpp)
    # Corpus generation is intentionally isolated from the monolithic inference
    # library.  CanonicalTokenizer and the metadata-only GGUF loader are header
    # implemented; linking deep2_engine_lib here creates unnecessary rebuild
    # contention and can accidentally pull GPU execution into a read-only tool.
    target_link_libraries(rawr-reap-corpus PRIVATE bcrypt)
    target_include_directories(rawr-reap-corpus PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/deep2)
    set_target_properties(rawr-reap-corpus PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-${COMPILER_SUFFIX}")
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/mla_lifecycle_test.cpp")
    add_executable(deep2_mla_lifecycle_test
        src/deep2/mla_lifecycle_test.cpp
        src/deep2/Deep2MlaLifecycleAdapter.cpp)
    target_include_directories(deep2_mla_lifecycle_test PRIVATE
        ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/deep2)
    target_compile_features(deep2_mla_lifecycle_test PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(deep2_mla_lifecycle_test PRIVATE /EHsc /std:c++20)
    endif()
    enable_testing()
    add_test(NAME deep2_mla_lifecycle_test COMMAND deep2_mla_lifecycle_test)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/src/reap_writer_cli.cpp" AND EXISTS "${CMAKE_SOURCE_DIR}/src/deep2/ReapWriter.cpp")
    add_executable(rawr-reap-writer src/reap_writer_cli.cpp src/deep2/ReapWriter.cpp)
    target_include_directories(rawr-reap-writer PRIVATE
        ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/deep2
        ${CMAKE_SOURCE_DIR}/include)
    target_compile_features(rawr-reap-writer PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(rawr-reap-writer PRIVATE /EHsc /std:c++20)
    endif()
    set_target_properties(rawr-reap-writer PROPERTIES RUNTIME_OUTPUT_DIRECTORY
        "${CMAKE_BINARY_DIR}/bin-msvc")
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/src/reap_mask_cli.cpp")
  add_executable(rawr-reap-mask src/reap_mask_cli.cpp)
  target_link_libraries(rawr-reap-mask PRIVATE bcrypt)
  set_target_properties(rawr-reap-mask PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-msvc")
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/src/reap_replay_cli.cpp" AND TARGET deep2_engine_lib)
  add_executable(rawr-reap-replay src/reap_replay_cli.cpp)
  target_link_libraries(rawr-reap-replay PRIVATE deep2_engine_lib)
  target_include_directories(rawr-reap-replay PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/deep2 ${CMAKE_SOURCE_DIR}/include)
  set_target_properties(rawr-reap-replay PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin-${COMPILER_SUFFIX}")
endif()

# ============================================================================
# Final Project Summary
# ============================================================================
message(STATUS "========================================")
message(STATUS "RawrXD Project Configuration Summary")
message(STATUS "========================================")
# ... (summary messages)


# ============================================================
# Qt availability summary (RAWRXD_GITHUB_CONTROL_LOOP_001)
# Qt-dependent targets excluded from a native build are REPORTED here.
# They are never silently claimed as configured, built, or tested.
# ============================================================
if(Qt6_FOUND)
    message(STATUS "Qt6 ${Qt6_VERSION} available - Qt-dependent targets enabled")
else()
    if(RAWRXD_QT_TARGETS)
        list(REMOVE_DUPLICATES RAWRXD_QT_TARGETS)
        message(STATUS "Qt-dependent targets EXCLUDED (Qt6 not installed): ${RAWRXD_QT_TARGETS}")
    else()
        message(STATUS "No Qt-dependent targets were excluded")
    endif()
endif()

# ============================================================
# PRODUCTION HARDENING - RawrXD Security Library
# ============================================================
# Dependency-free (C++20 standard library only, NO Qt) so that every target in
# this tree - including the native, Qt-free engines - can link it, and so the
# security guarantees are testable in the narrowest possible toolchain.
#
#   rawrxd_security: input validation boundary, secure memory, crash containment
#
# These components are the executable form of PRODUCTION_HARDENING.md.
option(RAWRXD_BUILD_SECURITY_LIB "Build the rawrxd_security hardening library" ON)

if(RAWRXD_BUILD_SECURITY_LIB)
    set(RAWRXD_SECURITY_SOURCES
        src/utils/input_sanitizer.cpp
        src/utils/secure_buffer.cpp
        src/utils/crash_handler.cpp
    )
    set(RAWRXD_SECURITY_HEADERS
        include/input_sanitizer.h
        include/secure_buffer.h
        include/crash_handler.h
    )

    # Every source is verified to exist: a missing hardening component must fail
    # configure loudly rather than silently producing an incomplete lib.
    foreach(_src IN LISTS RAWRXD_SECURITY_SOURCES RAWRXD_SECURITY_HEADERS)
        if(NOT EXISTS "${CMAKE_SOURCE_DIR}/${_src}")
            message(FATAL_ERROR
                "rawrxd_security requires '${_src}', which is missing. "
                "The hardening library must not be built partially.")
        endif()
    endforeach()

    add_library(rawrxd_security STATIC ${RAWRXD_SECURITY_SOURCES} ${RAWRXD_SECURITY_HEADERS})
    add_library(RawrXD::security ALIAS rawrxd_security)

    target_include_directories(rawrxd_security PUBLIC ${CMAKE_SOURCE_DIR}/include)
    # Also expose src/_utils for internal headers that may live beside sources.
    target_include_directories(rawrxd_security PRIVATE ${CMAKE_SOURCE_DIR}/src/utils)

    set_target_properties(rawrxd_security PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        POSITION_INDEPENDENT_CODE ON
        DEBUG_POSTFIX ""
    )

    if(MSVC)
        # /W4 is the floor for the security library, and warnings are errors:
        # hardening code that cannot be audited cleanly is not hardened.
        target_compile_options(rawrxd_security PRIVATE /W4 /WX /permissive- /EHsc)
        target_link_libraries(rawrxd_security PUBLIC dbghelp bcrypt)
    else()
        target_compile_options(rawrxd_security PRIVATE -Wall -Wextra -Wpedantic -Werror)
        if(WIN32)
            target_link_libraries(rawrxd_security PUBLIC dbghelp bcrypt)
        endif()
    endif()

    list(LENGTH RAWRXD_SECURITY_SOURCES _sec_src_count)
    message(STATUS "rawrxd_security: hardening library ENABLED (${_sec_src_count} sources)")

    # ---- Hardening test suite (dependency-free: no Qt required) -----------
    if(RAWRXD_BUILD_TESTS)
        set(RAWRXD_HARDENING_TEST_SOURCES
            tests/test_harness.h
            tests/test_input_sanitizer.cpp
            tests/test_crash_resilience.cpp
            tests/main_hardening_tests.cpp
        )
        foreach(_t IN LISTS RAWRXD_HARDENING_TEST_SOURCES)
            if(NOT EXISTS "${CMAKE_SOURCE_DIR}/${_t}")
                message(FATAL_ERROR "Hardening test suite requires '${_t}'")
            endif()
        endforeach()

        add_executable(rawrxd_hardening_tests ${RAWRXD_HARDENING_TEST_SOURCES})
        target_link_libraries(rawrxd_hardening_tests PRIVATE rawrxd_security)

        set_target_properties(rawrxd_hardening_tests PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
            CXX_STANDARD 20
            CXX_STANDARD_REQUIRED ON
        )

        # Enable CTest so `ctest` discovers the hardening suite.
        enable_testing()
        add_test(NAME hardening_security COMMAND rawrxd_hardening_tests)
        set_tests_properties(hardening_security PROPERTIES
            LABELS "security;hardening"
            TIMEOUT 300
        )
        message(STATUS "rawrxd_hardening_tests: registered with CTest (run: ctest -L security)")
    endif()

    # ---- Loader integration tests (needs the Vulkan SDK) ----------------
    # Separate from the suite above on purpose: the security suite is
    # dependency-free and CI-runnable anywhere, while these tests link the real
    # GGUFLoader + vocab resolver + Vulkan headers to prove the validation
    # boundary actually changes runtime behaviour at the model-load call site.
    if(RAWRXD_BUILD_TESTS AND ENABLE_VULKAN
       AND EXISTS "${CMAKE_SOURCE_DIR}/src/gguf_loader.cpp"
       AND EXISTS "${CMAKE_SOURCE_DIR}/src/gguf_vocab_resolver.cpp"
       AND EXISTS "${CMAKE_SOURCE_DIR}/tests/test_gguf_loader_hardening.cpp")
        add_executable(rawrxd_loader_hardening_tests
            tests/test_harness.h
            tests/test_input_sanitizer.cpp
            tests/test_gguf_loader_hardening.cpp
            tests/test_crash_resilience.cpp
            tests/main_hardening_tests.cpp
            src/gguf_loader.cpp
            src/gguf_vocab_resolver.cpp
        )
        target_include_directories(rawrxd_loader_hardening_tests PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/utils)
        # Reuse the hardening library's own sources rather than guessing at
        # which of them gguf_loader.cpp needs.
        target_link_libraries(rawrxd_loader_hardening_tests PRIVATE rawrxd_security)
        if(Vulkan_FOUND)
            target_link_libraries(rawrxd_loader_hardening_tests PRIVATE Vulkan::Vulkan)
        endif()
        set_target_properties(rawrxd_loader_hardening_tests PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
            CXX_STANDARD 20
            CXX_STANDARD_REQUIRED ON
        )
        add_test(NAME hardening_model_loader COMMAND rawrxd_loader_hardening_tests)
        set_tests_properties(hardening_model_loader PROPERTIES
            LABELS "security;hardening;models"
            TIMEOUT 300
        )
        message(STATUS "rawrxd_loader_hardening_tests: loader integration tests registered with CTest")
    endif()
else()
    add_compile_definitions(RAWRXD_SECURITY_DISABLED=1)
    message(WARNING "rawrxd_security DISABLED: input validation and crash containment "
                    "will NOT be linked. Do not ship this configuration.")
endif()

# ============================================================
# HEADLESS DEEP2 INFERENCE TEST
# ============================================================
if(EXISTS "${CMAKE_SOURCE_DIR}/test_deep2_inference.cpp" AND TARGET deep2_engine_lib)
    add_executable(test_deep2_inference test_deep2_inference.cpp)
    target_include_directories(test_deep2_inference PRIVATE
        "${CMAKE_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/src"
        "${CMAKE_SOURCE_DIR}/src/deep2")
    target_link_libraries(test_deep2_inference PRIVATE deep2_engine_lib ggml_interface rawrxd_agentic_backend rawrxd_security snap_process_guard)
    target_compile_options(test_deep2_inference PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    set_target_properties(test_deep2_inference PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    message(STATUS "test_deep2_inference enabled (headless Deep2 inference harness)")
else()
    message(STATUS "test_deep2_inference EXCLUDED: source or deep2_engine_lib unavailable")
endif()

# ============================================================
# DEEP2 ASYNC WEIGHT STREAMER CONTRACT TEST
# ============================================================
# This target exercises the scheduler and its fail-closed ticket/lifetime
# contract without requiring a Vulkan device.  The production adapter still
# has to provide the real queue submission and timeline wait callbacks.
option(DEEP2_BUILD_STREAMER_TEST
       "Build the fail-closed asynchronous weight streamer contract test" OFF)
if(DEEP2_BUILD_STREAMER_TEST)
    enable_testing()
    add_executable(deep2_weight_streamer_test
        tests/deep2_weight_streamer_test.cpp
        tests/stream_transfer_emit_compile.cpp
        src/deep2/VulkanWeightStreamer.cpp)
    target_include_directories(deep2_weight_streamer_test PRIVATE
        "${CMAKE_SOURCE_DIR}/src")
    set_target_properties(deep2_weight_streamer_test PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    add_test(NAME deep2_weight_streamer_contract
             COMMAND deep2_weight_streamer_test)
    set_tests_properties(deep2_weight_streamer_contract PROPERTIES
        LABELS "deep2;streaming;contract"
        TIMEOUT 60)
endif()

# ============================================================
# CPACK - PACKAGE GENERATION
# ============================================================
option(RAWRXD_ENABLE_PACKAGING "Enable CPack packaging (ZIP, NSIS, etc.)" OFF)

if(RAWRXD_ENABLE_PACKAGING)
    # Package metadata
    set(CPACK_PACKAGE_NAME "RawrXD")
    set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
    set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
    set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
    set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "RawrXD - AI-Native Autonomous IDE")
    set(CPACK_PACKAGE_VENDOR "RawrXD Project")
    set(CPACK_PACKAGE_CONTACT "https://github.com/ItsMehRAWRXD/RawrXD")
    set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_SOURCE_DIR}/README.md")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")

    # Windows ZIP package
    set(CPACK_GENERATOR "ZIP")
    set(CPACK_ZIP_COMPRESSION "ZSTD")

    # NSIS installer (if NSIS is available)
    find_program(MAKENSIS_EXE makensis)
    if(MAKENSIS_EXE)
        list(APPEND CPACK_GENERATOR "NSIS")
        set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES64/RawrXD")
        set(CPACK_NSIS_MODIFY_PATH ON)
        set(CPACK_NSIS_DISPLAY_NAME "RawrXD ${PROJECT_VERSION}")
        set(CPACK_NSIS_HELP_LINK "https://github.com/ItsMehRAWRXD/RawrXD")
        set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/ItsMehRAWRXD/RawrXD")
        set(CPACK_NSIS_CONTACT "RawrXD Project")
        set(CPACK_NSIS_INSTALLED_ICON_NAME "bin/RawrXD-Chromatic.exe")
        set(CPACK_NSIS_MUI_ICON "${CMAKE_SOURCE_DIR}/assets/icon.ico")
        set(CPACK_NSIS_MUI_UNIICON "${CMAKE_SOURCE_DIR}/assets/icon.ico")
    endif()

    # Package components
    set(CPACK_COMPONENTS_ALL "Runtime;Development;Documentation")
    set(CPACK_COMPONENT_RUNTIME_DISPLAY_NAME "Runtime")
    set(CPACK_COMPONENT_RUNTIME_DESCRIPTION "RawrXD runtime binaries")
    set(CPACK_COMPONENT_DEVELOPMENT_DISPLAY_NAME "Development")
    set(CPACK_COMPONENT_DEVELOPMENT_DESCRIPTION "Headers and libraries for development")
    set(CPACK_COMPONENT_DOCUMENTATION_DISPLAY_NAME "Documentation")
    set(CPACK_COMPONENT_DOCUMENTATION_DESCRIPTION "Documentation and examples")

    # Include files for packaging
    install(DIRECTORY "${CMAKE_BINARY_DIR}/bin/" DESTINATION "bin" COMPONENT Runtime)
    install(DIRECTORY "${CMAKE_SOURCE_DIR}/include/" DESTINATION "include" COMPONENT Development)
    install(FILES "${CMAKE_SOURCE_DIR}/README.md" "${CMAKE_SOURCE_DIR}/LICENSE" DESTINATION "." COMPONENT Documentation)

    include(CPack)
    message(STATUS "CPack packaging enabled: ${CPACK_GENERATOR}")
endif()
