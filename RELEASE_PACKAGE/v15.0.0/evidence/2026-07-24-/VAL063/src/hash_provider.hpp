#pragma once

#include "execution_types.hpp"
#include <vector>
#include <string_view>

namespace val063 {

// SHA-256 computation boundary
// Provides canonical hashing without external dependencies
class HashProvider {
public:
    HashProvider();
    ~HashProvider();

    // Delete copy to prevent state issues
    HashProvider(const HashProvider&) = delete;
    HashProvider& operator=(const HashProvider&) = delete;

    // Hash single buffer
    Hash256 hash_bytes(const uint8_t* data, size_t len);
    Hash256 hash_bytes(std::span<const uint8_t> data);

    // Hash string (UTF-8 bytes)
    Hash256 hash_string(std::string_view str);

    // Hash file contents
    std::optional<Hash256> hash_file(const std::string& path);

    // Streaming hash (for large files)
    void reset();
    void update(const uint8_t* data, size_t len);
    Hash256 finalize();

    // Canonical identity composition
    // Concatenates hashes in fixed order: prompt || config || model || runtime
    static Hash256 combine_identity(const ExecutionIdentity& identity);

    // Verify hash matches expected value (constant-time)
    static bool verify(const Hash256& computed, const Hash256& expected);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Convenience functions for common operations
namespace hash {
    // One-shot hash of bytes
    Hash256 of_bytes(const uint8_t* data, size_t len);
    Hash256 of_bytes(std::span<const uint8_t> data);
    
    // One-shot hash of string
    Hash256 of_string(std::string_view str);
    
    // Hash of file
    std::optional<Hash256> of_file(const std::string& path);
    
    // Combine multiple hashes into one
    Hash256 combine(std::span<const Hash256> hashes);
    
    // Canonical identity composition
    Hash256 identity(const ExecutionIdentity& ident);
}

} // namespace val063
