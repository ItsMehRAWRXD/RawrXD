#pragma once
// ============================================================================
// SEG Core - Base definitions for SEG (Sovereign Execution Graph)
// ============================================================================

#include <cstdint>
#include <cstddef>

namespace SEG {

// Version info
constexpr uint32_t SEG_VERSION_MAJOR = 1;
constexpr uint32_t SEG_VERSION_MINOR = 0;
constexpr uint32_t SEG_VERSION_PATCH = 0;

// Status codes
enum class Status : int32_t {
    OK = 0,
    Error = -1,
    NotImplemented = -2,
    InvalidArgument = -3,
    OutOfMemory = -4,
};

// Memory alignment constants
constexpr size_t SEG_DEFAULT_ALIGNMENT = 64;
constexpr size_t SEG_CACHE_LINE_SIZE = 64;

// Helper macros
#define SEG_LIKELY(x) __builtin_expect(!!(x), 1)
#define SEG_UNLIKELY(x) __builtin_expect(!!(x), 0)

} // namespace SEG
