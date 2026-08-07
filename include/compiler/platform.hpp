// platform.hpp - Compiler-neutral platform detection
// RawrXD Sovereign Build System
// This header provides compiler/platform abstraction for MSVC, Clang, and RawrXD native

#pragma once

// Compiler detection
#if defined(_MSC_VER)
    #define RAWRXD_COMPILER_MSVC 1
    #define RAWRXD_COMPILER_VERSION _MSC_VER
#elif defined(__clang__)
    #define RAWRXD_COMPILER_CLANG 1
    #define RAWRXD_COMPILER_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#elif defined(__GNUC__)
    #define RAWRXD_COMPILER_GCC 1
    #define RAWRXD_COMPILER_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#else
    #define RAWRXD_COMPILER_UNKNOWN 1
    #define RAWRXD_COMPILER_VERSION 0
#endif

// Platform detection
#if defined(_WIN32)
    #define RAWRXD_PLATFORM_WINDOWS 1
    #if defined(_WIN64)
        #define RAWRXD_PLATFORM_WIN64 1
    #else
        #define RAWRXD_PLATFORM_WIN32 1
    #endif
#elif defined(__linux__)
    #define RAWRXD_PLATFORM_LINUX 1
#elif defined(__APPLE__)
    #define RAWRXD_PLATFORM_MACOS 1
#else
    #define RAWRXD_PLATFORM_UNKNOWN 1
#endif

// Architecture detection
#if defined(_M_X64) || defined(__x86_64__)
    #define RAWRXD_ARCH_X64 1
    #define RAWRXD_ARCH_BITS 64
#elif defined(_M_IX86) || defined(__i386__)
    #define RAWRXD_ARCH_X86 1
    #define RAWRXD_ARCH_BITS 32
#elif defined(_M_ARM64) || defined(__aarch64__)
    #define RAWRXD_ARCH_ARM64 1
    #define RAWRXD_ARCH_BITS 64
#else
    #define RAWRXD_ARCH_UNKNOWN 1
    #define RAWRXD_ARCH_BITS 0
#endif

// Build configuration
#if defined(NDEBUG) || defined(_NDEBUG)
    #define RAWRXD_BUILD_RELEASE 1
#else
    #define RAWRXD_BUILD_DEBUG 1
#endif

// Feature detection
#if RAWRXD_COMPILER_MSVC
    #include <intrin.h>
    #define RAWRXD_HAS_SSE 1
    #define RAWRXD_HAS_AVX 1
    #define RAWRXD_HAS_AVX2 (__AVX2__)
    #define RAWRXD_HAS_AVX512 (__AVX512F__)
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #include <cpuid.h>
    #include <x86intrin.h>
    #define RAWRXD_HAS_SSE __SSE__
    #define RAWRXD_HAS_AVX __AVX__
    #define RAWRXD_HAS_AVX2 __AVX2__
    #define RAWRXD_HAS_AVX512 __AVX512F__
#endif

// Export macros
#if RAWRXD_PLATFORM_WINDOWS
    #if RAWRXD_BUILD_RELEASE
        #define RAWRXD_API __declspec(dllexport)
        #define RAWRXD_IMPORT __declspec(dllimport)
    #else
        #define RAWRXD_API
        #define RAWRXD_IMPORT
    #endif
#else
    #define RAWRXD_API __attribute__((visibility("default")))
    #define RAWRXD_IMPORT
#endif

// Inline macros
#if RAWRXD_COMPILER_MSVC
    #define RAWRXD_FORCEINLINE __forceinline
    #define RAWRXD_NOINLINE __declspec(noinline)
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_FORCEINLINE __attribute__((always_inline)) inline
    #define RAWRXD_NOINLINE __attribute__((noinline))
#else
    #define RAWRXD_FORCEINLINE inline
    #define RAWRXD_NOINLINE
#endif

// Alignment macros
#if RAWRXD_COMPILER_MSVC
    #define RAWRXD_ALIGN(x) __declspec(align(x))
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_ALIGN(x) __attribute__((aligned(x)))
#else
    #define RAWRXD_ALIGN(x)
#endif

// Branch prediction hints
#if RAWRXD_COMPILER_MSVC
    #define RAWRXD_LIKELY(x) (x)
    #define RAWRXD_UNLIKELY(x) (x)
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_LIKELY(x) __builtin_expect(!!(x), 1)
    #define RAWRXD_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
    #define RAWRXD_LIKELY(x) (x)
    #define RAWRXD_UNLIKELY(x) (x)
#endif

// Static assert
#if __cplusplus >= 201103L
    #define RAWRXD_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
    #define RAWRXD_STATIC_ASSERT(cond, msg) typedef char _static_assert_##__LINE__[(cond) ? 1 : -1]
#endif

// Compile-time constants
namespace rawrxd {
    constexpr bool is_msvc = RAWRXD_COMPILER_MSVC;
    constexpr bool is_clang = RAWRXD_COMPILER_CLANG;
    constexpr bool is_gcc = RAWRXD_COMPILER_GCC;
    constexpr bool is_windows = RAWRXD_PLATFORM_WINDOWS;
    constexpr bool is_x64 = RAWRXD_ARCH_X64;
    constexpr bool is_release = RAWRXD_BUILD_RELEASE;
    constexpr int arch_bits = RAWRXD_ARCH_BITS;
}
