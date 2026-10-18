#pragma once
// Deep2NoDepSha256 — zero-dependency SHA-256 for evidence receipts.
// Provides NoDepSha256::hash(const std::string&) -> hex std::string
// Wraps the existing deep2::Sha256 implementation.

#include "deep2_sha256.hpp"
#include <string>

namespace Deep2 {

struct NoDepSha256 {
    static std::string hash(const std::string& input) noexcept {
        auto bytes = deep2::sha256_bytes(input.data(), input.size());
        return deep2::hex32(bytes);
    }
    static std::string hash(const void* data, size_t len) noexcept {
        auto bytes = deep2::sha256_bytes(data, len);
        return deep2::hex32(bytes);
    }
};

} // namespace Deep2