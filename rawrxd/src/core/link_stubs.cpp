// ============================================================================
// link_stubs.cpp — Stub implementations for missing dependencies
// ============================================================================
// Temporary stubs to allow VAL-051.2.B build to complete.
// These should be replaced with real implementations.
// ============================================================================

#include <vector>
#include <string>
#include <map>
#include <cstdint>

// Stub ModelSlice to avoid missing swarm_scheduler.hpp
namespace RawrXD {
    struct ModelSlice {
        std::string model_path;
        int32_t start_layer = 0;
        int32_t end_layer = 0;
        bool is_loaded = false;
    };
}

// codec::deflate/inflate are implemented in src/codec/compression.cpp
// Do NOT add stubs here - they cause ODR violations with the real implementations

// brutal::compress/decompress are implemented in src/codec/brutal_gzip.cpp
// Do NOT add stubs here - they cause ODR violations with the real implementations

// Logging is now provided by src/logging/Logger.cpp - no stubs needed
