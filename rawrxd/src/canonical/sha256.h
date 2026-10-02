// ============================================================================
// sha256.h — real SHA-256 for model file integrity
//
// RAWRXD_UNSIMULATE_001 / RAWRXD_END_TO_END_STATE_001
//
// `UnifiedModelLoader.cpp` has included "sha256.h" since before this tree was
// assembled, and the header has never existed, so that translation unit has
// never compiled. It is included "or fallback if not available" -- and the
// fallback that was actually written was:
//
//     bool UnifiedModelLoader::VerifySHA256(const std::string&) const {
//         return true; // placeholder
//     }
//
// A model-integrity check that always passes. Every certification in this tree
// binds a receipt to a model by hash, so a verifier that never reads the file
// makes each of those bindings unfalsifiable. This header exists so the check
// can be real instead of absent.
//
// FIPS 180-4 SHA-256. Self-contained, no dependencies beyond <cstdint>,
// <cstddef> and <string>.
// ============================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace rawrxd {
namespace sha256 {

// Streaming state.
class Sha256 {
public:
    Sha256() { Reset(); }
    void Reset();
    void Update(const void* data, size_t len);
    // Finalises into a 32-byte digest. The object must be Reset() before reuse.
    void Final(uint8_t out[32]);

    uint64_t bytesProcessed() const noexcept { return totalBytes_; }

private:
    void Compress(const uint8_t block[64]);

    uint32_t state_[8];
    uint64_t bitLen_;
    uint64_t totalBytes_;
    uint8_t  buf_[64];
    size_t   bufLen_;
};

// Lowercase hex of the 32-byte digest.
std::string HexDigest(const uint8_t digest[32]);

// Whole-buffer convenience.
std::string HexOfBuffer(const void* data, size_t len);

// Whole-FILE convenience. Returns an empty string if the file cannot be opened
// or read -- an empty string is deliberately NOT a valid digest, so a caller
// cannot mistake a read failure for a hash of nothing.
std::string HexOfFile(const std::string& path);

// Case-insensitive, whitespace-tolerant comparison of two hex digests, so
// "AABB..." and "aabb..." compare equal and a trailing newline does not cause a
// spurious mismatch. Both sides must be exactly 64 hex characters.
bool EqualDigest(const std::string& a, const std::string& b);

}  // namespace sha256
}  // namespace rawrxd