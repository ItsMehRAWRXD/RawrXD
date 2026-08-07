#include "execution_types.hpp"
#include <iomanip>
#include <sstream>
#include <iostream>
#include <charconv>

namespace val063 {

// ============================================================================
// Hash256 Implementation
// ============================================================================

std::optional<Hash256> Hash256::from_hex(std::string_view hex) {
    if (hex.length() != 64) {
        return std::nullopt;
    }
    
    Hash256 result;
    for (size_t i = 0; i < 32; ++i) {
        std::string_view byte_str = hex.substr(i * 2, 2);
        uint8_t value;
        auto [ptr, ec] = std::from_chars(byte_str.data(), byte_str.data() + 2, value, 16);
        if (ec != std::errc()) {
            return std::nullopt;
        }
        result.bytes[i] = value;
    }
    return result;
}

std::string Hash256::hex() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

bool Hash256::is_null() const {
    for (uint8_t byte : bytes) {
        if (byte != 0) return false;
    }
    return true;
}

size_t Hash256::Hash::operator()(const Hash256& h) const noexcept {
    // FNV-1a inspired hash for first 8 bytes
    size_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < 8 && i < h.bytes.size(); ++i) {
        hash ^= h.bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

// ============================================================================
// ExecutionId (UUID) Implementation
// ============================================================================

ExecutionId ExecutionId::generate() {
    // This will be implemented by uuid_provider.cpp using crypto RNG
    // For now, return zero-initialized
    return ExecutionId{};
}

std::optional<ExecutionId> ExecutionId::from_string(std::string_view str) {
    if (str.length() != 36) {
        return std::nullopt;
    }
    
    // Check format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (str[i] != '-') return std::nullopt;
        } else {
            if (!std::isxdigit(str[i])) return std::nullopt;
        }
    }
    
    ExecutionId result;
    size_t byte_idx = 0;
    
    for (size_t i = 0; i < 36 && byte_idx < 16; i += 2) {
        if (str[i] == '-') {
            i--;
            continue;
        }
        
        std::string_view byte_str = str.substr(i, 2);
        uint8_t value;
        auto [ptr, ec] = std::from_chars(byte_str.data(), byte_str.data() + 2, value, 16);
        if (ec != std::errc()) {
            return std::nullopt;
        }
        result.bytes[byte_idx++] = value;
    }
    
    return result;
}

std::string ExecutionId::to_string() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            oss << '-';
        }
        oss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    
    return oss.str();
}

size_t ExecutionId::Hash::operator()(const ExecutionId& id) const noexcept {
    size_t hash = 14695981039346656037ULL;
    for (uint8_t byte : id.bytes) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

// ============================================================================
// Timestamp Implementation
// ============================================================================

Timestamp Timestamp::now() {
    return Timestamp{
        Clock::now(),
        WallClock::now()
    };
}

std::chrono::nanoseconds Timestamp::elapsed_since(const Timestamp& other) const {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        monotonic - other.monotonic
    );
}

std::string Timestamp::iso8601() const {
    auto time_t = WallClock::to_time_t(wall_clock);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        wall_clock.time_since_epoch()
    ) % 1000;
    
    std::tm utc{};
    gmtime_s(&utc, &time_t);
    
    std::ostringstream oss;
    oss << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    oss << 'Z';
    
    return oss.str();
}

int64_t Timestamp::wall_ns_since_epoch() const {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        wall_clock.time_since_epoch()
    ).count();
}

int64_t Timestamp::monotonic_ns_since_epoch() const {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        monotonic.time_since_epoch()
    ).count();
}

// ============================================================================
// RuntimeVersion Implementation
// ============================================================================

std::string RuntimeVersion::to_string() const {
    std::ostringstream oss;
    oss << major << '.' << minor << '.' << patch;
    if (!commit_hash.empty()) {
        oss << '+' << commit_hash;
    }
    return oss.str();
}

bool RuntimeVersion::operator==(const RuntimeVersion& other) const {
    return major == other.major && 
           minor == other.minor && 
           patch == other.patch &&
           commit_hash == other.commit_hash;
}

bool RuntimeVersion::operator<(const RuntimeVersion& other) const {
    if (major != other.major) return major < other.major;
    if (minor != other.minor) return minor < other.minor;
    if (patch != other.patch) return patch < other.patch;
    return commit_hash < other.commit_hash;
}

// ============================================================================
// ExecutionIdentity Implementation
// ============================================================================

Hash256 ExecutionIdentity::combined_identity() const {
    // Canonical concatenation: prompt || config || model || runtime
    std::array<uint8_t, 128> combined = to_canonical_bytes();
    
    // SHA-256 of combined (placeholder - will use hash_provider)
    // For now, return first 32 bytes as identity marker
    Hash256 result;
    std::copy(combined.begin(), combined.begin() + 32, result.bytes.begin());
    return result;
}

std::array<uint8_t, 128> ExecutionIdentity::to_canonical_bytes() const {
    std::array<uint8_t, 128> result{};
    
    // Fixed order: prompt (0-31), config (32-63), model (64-95), runtime (96-127)
    std::copy(prompt_hash.bytes.begin(), prompt_hash.bytes.end(), result.begin());
    std::copy(configuration_hash.bytes.begin(), configuration_hash.bytes.end(), result.begin() + 32);
    std::copy(model_hash.bytes.begin(), model_hash.bytes.end(), result.begin() + 64);
    std::copy(runtime_hash.bytes.begin(), runtime_hash.bytes.end(), result.begin() + 96);
    
    return result;
}

bool ExecutionIdentity::operator==(const ExecutionIdentity& other) const {
    return prompt_hash == other.prompt_hash &&
           configuration_hash == other.configuration_hash &&
           model_hash == other.model_hash &&
           runtime_hash == other.runtime_hash;
}

bool ExecutionIdentity::is_complete() const {
    return !prompt_hash.is_null() &&
           !configuration_hash.is_null() &&
           !model_hash.is_null() &&
           !runtime_hash.is_null();
}

// ============================================================================
// AttestedExecution Implementation
// ============================================================================

std::string AttestedExecution::to_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"execution_id\": \"" << execution_id.to_string() << "\",\n";
    oss << "  \"identity\": {\n";
    oss << "    \"prompt_hash\": \"" << identity.prompt_hash.hex() << "\",\n";
    oss << "    \"configuration_hash\": \"" << identity.configuration_hash.hex() << "\",\n";
    oss << "    \"model_hash\": \"" << identity.model_hash.hex() << "\",\n";
    oss << "    \"runtime_hash\": \"" << identity.runtime_hash.hex() << "\"\n";
    oss << "  },\n";
    oss << "  \"start_time\": \"" << start_time.iso8601() << "\",\n";
    if (end_time) {
        oss << "  \"end_time\": \"" << end_time->iso8601() << "\",\n";
    }
    oss << "  \"runtime_version\": \"" << runtime_version.to_string() << "\",\n";
    oss << "  \"output_hash\": \"" << output_hash.hex() << "\",\n";
    oss << "  \"deterministic\": " << (deterministic ? "true" : "false") << ",\n";
    oss << "  \"correlated\": " << (correlated ? "true" : "false") << "\n";
    oss << "}";
    return oss.str();
}

std::optional<AttestedExecution> AttestedExecution::from_json(std::string_view json) {
    // Simplified JSON parsing - production would use proper parser
    // For now, return nullopt to indicate not implemented
    return std::nullopt;
}

// ============================================================================
// GateAEvidence Implementation
// ============================================================================

std::string GateAEvidence::to_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"gate\": \"" << gate << "\",\n";
    oss << "  \"component\": \"" << component << "\",\n";
    oss << "  \"sha256\": \"" << sha256_status << "\",\n";
    oss << "  \"uuid\": \"" << uuid_status << "\",\n";
    oss << "  \"timestamp\": \"" << timestamp_status << "\",\n";
    oss << "  \"identity_composition\": \"" << identity_composition_status << "\",\n";
    oss << "  \"deterministic\": " << (deterministic ? "true" : "false") << ",\n";
    oss << "  \"captured_at\": \"" << captured_at.iso8601() << "\"\n";
    oss << "}";
    return oss.str();
}

} // namespace val063
