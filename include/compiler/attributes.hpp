// attributes.hpp - Compiler-neutral attribute macros
// RawrXD Sovereign Build System

#pragma once

#include "platform.hpp"

// [[nodiscard]] support
#if __cplusplus >= 201703L
    #define RAWRXD_NODISCARD [[nodiscard]]
#elif RAWRXD_COMPILER_MSVC && _MSC_VER >= 1911
    #define RAWRXD_NODISCARD _Check_return_
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_NODISCARD __attribute__((warn_unused_result))
#else
    #define RAWRXD_NODISCARD
#endif

// [[maybe_unused]] support
#if __cplusplus >= 201703L
    #define RAWRXD_MAYBE_UNUSED [[maybe_unused]]
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_MAYBE_UNUSED __attribute__((unused))
#else
    #define RAWRXD_MAYBE_UNUSED
#endif

// [[fallthrough]] support
#if __cplusplus >= 201703L
    #define RAWRXD_FALLTHROUGH [[fallthrough]]
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_FALLTHROUGH __attribute__((fallthrough))
#else
    #define RAWRXD_FALLTHROUGH
#endif

// [[noreturn]] support
#if __cplusplus >= 201103L
    #define RAWRXD_NORETURN [[noreturn]]
#elif RAWRXD_COMPILER_MSVC
    #define RAWRXD_NORETURN __declspec(noreturn)
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_NORETURN __attribute__((noreturn))
#else
    #define RAWRXD_NORETURN
#endif

// [[deprecated]] support
#if __cplusplus >= 201402L
    #define RAWRXD_DEPRECATED(msg) [[deprecated(msg)]]
#elif RAWRXD_COMPILER_MSVC
    #define RAWRXD_DEPRECATED(msg) __declspec(deprecated(msg))
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_DEPRECATED(msg) __attribute__((deprecated(msg)))
#else
    #define RAWRXD_DEPRECATED(msg)
#endif

// [[no_unique_address]] support (C++20)
#if __cplusplus >= 202002L
    #define RAWRXD_NO_UNIQUE_ADDRESS [[no_unique_address]]
#elif RAWRXD_COMPILER_MSVC && _MSC_VER >= 1929
    #define RAWRXD_NO_UNIQUE_ADDRESS [[msvc::no_unique_address]]
#else
    #define RAWRXD_NO_UNIQUE_ADDRESS
#endif

// [[likely]] / [[unlikely]] support (C++20)
#if __cplusplus >= 202002L
    #define RAWRXD_LIKELY_ATTR [[likely]]
    #define RAWRXD_UNLIKELY_ATTR [[unlikely]]
#else
    #define RAWRXD_LIKELY_ATTR
    #define RAWRXD_UNLIKELY_ATTR
#endif

// Restrict pointer
#if RAWRXD_COMPILER_MSVC
    #define RAWRXD_RESTRICT __restrict
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_RESTRICT __restrict__
#else
    #define RAWRXD_RESTRICT
#endif

// Thread-local storage
#if RAWRXD_COMPILER_MSVC
    #define RAWRXD_THREAD_LOCAL __declspec(thread)
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_THREAD_LOCAL __thread
#else
    #define RAWRXD_THREAD_LOCAL thread_local
#endif

// Packed structure
#if RAWRXD_COMPILER_MSVC
    #define RAWRXD_PACKED
    #define RAWRXD_PACKED_BEGIN __pragma(pack(push, 1))
    #define RAWRXD_PACKED_END __pragma(pack(pop))
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_PACKED __attribute__((packed))
    #define RAWRXD_PACKED_BEGIN
    #define RAWRXD_PACKED_END
#else
    #define RAWRXD_PACKED
    #define RAWRXD_PACKED_BEGIN
    #define RAWRXD_PACKED_END
#endif

// Visibility
#if RAWRXD_COMPILER_MSVC
    #define RAWRXD_HIDDEN
    #define RAWRXD_VISIBLE
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_HIDDEN __attribute__((visibility("hidden")))
    #define RAWRXD_VISIBLE __attribute__((visibility("default")))
#else
    #define RAWRXD_HIDDEN
    #define RAWRXD_VISIBLE
#endif

// Pure function (no side effects)
#if RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_PURE __attribute__((pure))
    #define RAWRXD_CONST __attribute__((const))
#else
    #define RAWRXD_PURE
    #define RAWRXD_CONST
#endif

// Hot/cold function hints
#if RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_HOT __attribute__((hot))
    #define RAWRXD_COLD __attribute__((cold))
#else
    #define RAWRXD_HOT
    #define RAWRXD_COLD
#endif

// Constructor/destructor priority
#if RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_CONSTRUCTOR(prio) __attribute__((constructor(prio)))
    #define RAWRXD_DESTRUCTOR(prio) __attribute__((destructor(prio)))
#else
    #define RAWRXD_CONSTRUCTOR(prio)
    #define RAWRXD_DESTRUCTOR(prio)
#endif

// Weak symbol
#if RAWRXD_COMPILER_MSVC
    #define RAWRXD_WEAK
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_WEAK __attribute__((weak))
#else
    #define RAWRXD_WEAK
#endif

// Alias
#if RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_ALIAS(name) __attribute__((alias(name)))
#else
    #define RAWRXD_ALIAS(name)
#endif

// Section placement
#if RAWRXD_COMPILER_MSVC
    #define RAWRXD_SECTION(name) __declspec(allocate(name))
#elif RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_SECTION(name) __attribute__((section(name)))
#else
    #define RAWRXD_SECTION(name)
#endif

// Used/unused
#if RAWRXD_COMPILER_CLANG || RAWRXD_COMPILER_GCC
    #define RAWRXD_USED __attribute__((used))
    #define RAWRXD_UNUSED __attribute__((unused))
#else
    #define RAWRXD_USED
    #define RAWRXD_UNUSED
#endif
