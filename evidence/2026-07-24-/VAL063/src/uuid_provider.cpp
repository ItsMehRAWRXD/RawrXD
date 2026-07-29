#include "uuid_provider.hpp"
#include <random>
#include <chrono>

// UUID v4 generation using cryptographically secure randomness
// For Gate A, we use std::random_device as entropy source

namespace val063 {

namespace {

// Platform-specific entropy source
class EntropySource {
public:
    EntropySource() {
        // Seed with high-resolution clock + random_device
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        std::random_device rd;
        std::seed_seq seed{
            static_cast<uint32_t>(now >> 32),
            static_cast<uint32_t>(now & 0xFFFFFFFF),
            rd(), rd(), rd(), rd()
        };
        rng_.seed(seed);
    }

    uint8_t next_byte() {
        std::uniform_int_distribution<int> dist(0, 255);
        return static_cast<uint8_t>(dist(rng_));
    }

    void fill_bytes(uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            data[i] = next_byte();
        }
    }

private:
    std::mt19937_64 rng_;
};

// Thread-local entropy source
EntropySource& get_entropy() {
    thread_local EntropySource source;
    return source;
}

} // anonymous namespace

class UuidProvider::Impl {
public:
    ExecutionId generate_v4() {
        ExecutionId id;
        
        // Fill with random bytes
        get_entropy().fill_bytes(id.bytes.data(), id.bytes.size());
        
        // Set version (4) - bits 12-15 of time_hi_and_version field
        id.bytes[6] = (id.bytes[6] & 0x0F) | 0x40;
        
        // Set variant (10xxxxxx) - bits 6-7 of clock_seq_hi_and_reserved
        id.bytes[8] = (id.bytes[8] & 0x3F) | 0x80;
        
        return id;
    }
};

UuidProvider::UuidProvider() : impl_(std::make_unique<Impl>()) {}
UuidProvider::~UuidProvider() = default;

ExecutionId UuidProvider::generate() {
    return impl_->generate_v4();
}

std::optional<ExecutionId> UuidProvider::parse(std::string_view str) {
    return ExecutionId::from_string(str);
}

std::string UuidProvider::to_string(const ExecutionId& id) {
    return id.to_string();
}

bool UuidProvider::is_valid(std::string_view str) {
    if (str.length() != 36) return false;
    
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (str[i] != '-') return false;
        } else {
            if (!std::isxdigit(str[i])) return false;
        }
    }
    
    // Check version (should be 4 for UUID v4)
    char version_char = str[14];
    if (version_char != '4') return false;
    
    // Check variant (should be 8, 9, a, or b for RFC 4122)
    char variant_char = str[19];
    if (variant_char != '8' && variant_char != '9' && 
        variant_char != 'a' && variant_char != 'b' &&
        variant_char != 'A' && variant_char != 'B') {
        return false;
    }
    
    return true;
}

// ============================================================================
// Convenience namespace
// ============================================================================

namespace uuid {

ExecutionId generate() {
    return UuidProvider().generate();
}

std::optional<ExecutionId> parse(std::string_view str) {
    return UuidProvider::parse(str);
}

std::string to_string(const ExecutionId& id) {
    return UuidProvider::to_string(id);
}

} // namespace uuid

} // namespace val063
