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

namespace codec {

// Production fallback: deflate/inflate are not implemented.
// Callers MUST check the success flag. If false, the data is NOT compressed/decompressed.
// This prevents silent data corruption from passing through raw compressed bytes.

std::vector<unsigned char> deflate(const std::vector<unsigned char>& input, bool* success) {
    if (success) *success = false;
    // Return empty to force caller to handle failure explicitly
    return {};
}

std::vector<unsigned char> inflate(const std::vector<unsigned char>& input, bool* success) {
    if (success) *success = false;
    // Return empty to force caller to handle failure explicitly
    return {};
}

} // namespace codec

namespace brutal {

// Stub for compress
std::vector<unsigned char> compress(const std::vector<unsigned char>& input) {
    return input; // Return uncompressed
}

} // namespace brutal

// Logging is now provided by src/logging/Logger.cpp - no stubs needed
