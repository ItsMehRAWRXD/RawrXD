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

// Include the actual header for ModelSlice
#include "core/swarm_scheduler.hpp"

namespace codec {

// Stub for deflate
std::vector<unsigned char> deflate(const std::vector<unsigned char>& input, bool* success) {
    if (success) *success = false;
    return input; // Return uncompressed
}

// Stub for inflate  
std::vector<unsigned char> inflate(const std::vector<unsigned char>& input, bool* success) {
    if (success) *success = false;
    return input; // Return as-is
}

} // namespace codec

namespace brutal {

// Stub for compress
std::vector<unsigned char> compress(const std::vector<unsigned char>& input) {
    return input; // Return uncompressed
}

} // namespace brutal

// Logging is now provided by src/logging/Logger.cpp - no stubs needed
