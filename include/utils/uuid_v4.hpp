// uuid_v4.hpp — Lightweight Header-Only UUID v4 Generator
// Production-ready, cryptographically secure random UUID generation
// No external dependencies, C++17 compatible
// ============================================================================

#pragma once

#include <array>
#include <string>
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>

namespace rawrxd {
namespace utils {

// ============================================================================
// UUID v4 Implementation
// ============================================================================

class UUID {
public:
    // Default constructor creates nil UUID
    UUID() : data_{} {}
    
    // Construct from raw bytes
    explicit UUID(const std::array<uint8_t, 16>& bytes) : data_(bytes) {}
    
    // Generate a new random UUID v4
    static UUID generate_v4() {
        UUID uuid;
        
        // Use high-quality random number generator
        static thread_local std::random_device rd;
        static thread_local std::mt19937_64 gen(rd());
        static thread_local std::uniform_int_distribution<uint64_t> dis;
        
        // Fill with random bytes
        uint64_t high = dis(gen);
        uint64_t low = dis(gen);
        
        std::memcpy(uuid.data_.data(), &high, 8);
        std::memcpy(uuid.data_.data() + 8, &low, 8);
        
        // Set version (4) and variant (RFC 4122)
        uuid.data_[6] = (uuid.data_[6] & 0x0F) | 0x40; // Version 4
        uuid.data_[8] = (uuid.data_[8] & 0x3F) | 0x80; // Variant 10
        
        return uuid;
    }
    
    // Generate from string (with or without dashes)
    static UUID from_string(const std::string& str) {
        UUID uuid;
        std::string clean = str;
        
        // Remove dashes if present
        clean.erase(std::remove(clean.begin(), clean.end(), '-'), clean.end());
        
        if (clean.length() != 32) {
            return UUID(); // Return nil UUID on invalid input
        }
        
        for (size_t i = 0; i < 16; ++i) {
            std::string byte_str = clean.substr(i * 2, 2);
            try {
                uuid.data_[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
            } catch (...) {
                return UUID(); // Return nil UUID on parse error
            }
        }
        
        return uuid;
    }
    
    // Convert to standard string format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    std::string to_string() const {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        
        for (size_t i = 0; i < 16; ++i) {
            if (i == 4 || i == 6 || i == 8 || i == 10) {
                oss << '-';
            }
            oss << std::setw(2) << static_cast<int>(data_[i]);
        }
        
        return oss.str();
    }
    
    // Convert to compact string (no dashes)
    std::string to_compact_string() const {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        
        for (size_t i = 0; i < 16; ++i) {
            oss << std::setw(2) << static_cast<int>(data_[i]);
        }
        
        return oss.str();
    }
    
    // Check if nil UUID
    bool is_nil() const {
        for (auto b : data_) {
            if (b != 0) return false;
        }
        return true;
    }
    
    // Get raw bytes
    const std::array<uint8_t, 16>& bytes() const { return data_; }
    
    // Comparison operators
    bool operator==(const UUID& other) const { return data_ == other.data_; }
    bool operator!=(const UUID& other) const { return data_ != other.data_; }
    bool operator<(const UUID& other) const { return data_ < other.data_; }
    
    // Hash support for unordered containers
    struct Hash {
        size_t operator()(const UUID& uuid) const {
            // Combine all bytes into a hash
            size_t hash = 0;
            for (auto b : uuid.data_) {
                hash = hash * 31 + b;
            }
            return hash;
        }
    };

private:
    std::array<uint8_t, 16> data_;
};

// ============================================================================
// Session ID Generator
// ============================================================================

class SessionIDGenerator {
public:
    // Generate a session ID with timestamp prefix for sorting
    static std::string generate_session_id() {
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        
        UUID uuid = UUID::generate_v4();
        
        // Format: sess_{timestamp}_{uuid_short}
        std::ostringstream oss;
        oss << "sess_" << timestamp << "_" << uuid.to_compact_string().substr(0, 12);
        
        return oss.str();
    }
    
    // Generate a simple UUID-based ID
    static std::string generate_uuid_id() {
        return UUID::generate_v4().to_string();
    }
    
    // Generate a request ID for tracking
    static std::string generate_request_id() {
        return "req_" + UUID::generate_v4().to_compact_string().substr(0, 16);
    }
};

// ============================================================================
// Convenience Functions
// ============================================================================

inline std::string generate_uuid_v4() {
    return UUID::generate_v4().to_string();
}

inline std::string generate_session_id() {
    return SessionIDGenerator::generate_session_id();
}

inline std::string generate_request_id() {
    return SessionIDGenerator::generate_request_id();
}

} // namespace utils
} // namespace rawrxd

// ============================================================================
// std::hash specialization for UUID
// ============================================================================

namespace std {
    template<>
    struct hash<rawrxd::utils::UUID> {
        size_t operator()(const rawrxd::utils::UUID& uuid) const {
            return rawrxd::utils::UUID::Hash{}(uuid);
        }
    };
}
