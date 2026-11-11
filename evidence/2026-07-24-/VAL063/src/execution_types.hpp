#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <chrono>
#include <functional>

namespace val063 {

// Fixed-width 256-bit hash (SHA-256 output)
struct Hash256 {
    static constexpr size_t SIZE = 32;
    std::array<uint8_t, SIZE> bytes{};

    // Default constructor - zero-initialized
    Hash256() = default;

    // Construct from byte array
    explicit Hash256(const std::array<uint8_t, SIZE>& data) : bytes(data) {}

    // Construct from hex string (64 characters)
    static std::optional<Hash256> from_hex(std::string_view hex);

    // Convert to lowercase hex string
    std::string hex() const;

    // Binary comparison
    bool operator==(const Hash256& other) const { return bytes == other.bytes; }
    bool operator!=(const Hash256& other) const { return bytes != other.bytes; }
    bool operator<(const Hash256& other) const { return bytes < other.bytes; }

    // Check if hash is all zeros (uninitialized/null)
    bool is_null() const;

    // Hash specialization for std::hash
    struct Hash {
        size_t operator()(const Hash256& h) const noexcept;
    };
};

// UUID v4 for execution correlation
struct ExecutionId {
    static constexpr size_t SIZE = 16;
    std::array<uint8_t, SIZE> bytes{};

    ExecutionId() = default;
    explicit ExecutionId(const std::array<uint8_t, SIZE>& data) : bytes(data) {}

    // Generate new UUID v4 (random)
    static ExecutionId generate();

    // Parse from string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
    static std::optional<ExecutionId> from_string(std::string_view str);

    // Convert to standard UUID string format
    std::string to_string() const;

    bool operator==(const ExecutionId& other) const { return bytes == other.bytes; }
    bool operator!=(const ExecutionId& other) const { return bytes != other.bytes; }

    struct Hash {
        size_t operator()(const ExecutionId& id) const noexcept;
    };
};

// High-resolution timestamps
struct Timestamp {
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using WallClock = std::chrono::system_clock;
    using WallTimePoint = WallClock::time_point;

    TimePoint monotonic;
    WallTimePoint wall_clock;

    Timestamp() = default;
    explicit Timestamp(TimePoint mono, WallTimePoint wall) 
        : monotonic(mono), wall_clock(wall) {}

    // Capture current time from both clocks
    static Timestamp now();

    // Duration since another timestamp (monotonic)
    std::chrono::nanoseconds elapsed_since(const Timestamp& other) const;

    // Convert wall clock to ISO 8601 string
    std::string iso8601() const;

    // Serialize to nanoseconds since epoch
    int64_t wall_ns_since_epoch() const;
    int64_t monotonic_ns_since_epoch() const;
};

// Runtime version identification
struct RuntimeVersion {
    uint32_t major{0};
    uint32_t minor{0};
    uint32_t patch{0};
    std::string commit_hash;  // Git commit (first 8 chars)
    std::string build_timestamp;

    RuntimeVersion() = default;
    RuntimeVersion(uint32_t maj, uint32_t min, uint32_t pat, 
                   std::string commit = "", std::string build = "")
        : major(maj), minor(min), patch(pat), 
          commit_hash(std::move(commit)), build_timestamp(std::move(build)) {}

    // Canonical string representation: "major.minor.patch+commit"
    std::string to_string() const;

    // Hash of the runtime binary (captured at build time)
    Hash256 binary_hash;

    bool operator==(const RuntimeVersion& other) const;
    bool operator<(const RuntimeVersion& other) const;
};

// Complete execution identity (the behavioral identity model)
struct ExecutionIdentity {
    Hash256 prompt_hash;          // SHA256(prompt text)
    Hash256 configuration_hash;     // SHA256(sampler config)
    Hash256 model_hash;             // SHA256(GGUF file)
    Hash256 runtime_hash;           // SHA256(runtime binary)

    ExecutionIdentity() = default;
    ExecutionIdentity(Hash256 prompt, Hash256 config, Hash256 model, Hash256 runtime)
        : prompt_hash(prompt), configuration_hash(config), 
          model_hash(model), runtime_hash(runtime) {}

    // Canonical combined identity hash
    // Concatenates all component hashes in fixed order and SHA-256s them
    Hash256 combined_identity() const;

    // Canonical binary serialization (deterministic, no JSON)
    std::array<uint8_t, 128> to_canonical_bytes() const;

    bool operator==(const ExecutionIdentity& other) const;
    bool operator!=(const ExecutionIdentity& other) const { return !(*this == other); }

    // Verify all components are non-null
    bool is_complete() const;
};

// Identity with execution correlation
struct AttestedExecution {
    ExecutionId execution_id;
    ExecutionIdentity identity;
    Timestamp start_time;
    std::optional<Timestamp> end_time;
    RuntimeVersion runtime_version;

    // The final output hash (populated after execution)
    Hash256 output_hash;

    // Deterministic flag (set by replay verification)
    bool deterministic{false};

    // Correlation flag (all stages share execution_id)
    bool correlated{false};

    AttestedExecution() = default;
    AttestedExecution(ExecutionId id, ExecutionIdentity ident, Timestamp start, RuntimeVersion ver)
        : execution_id(id), identity(ident), start_time(start), runtime_version(ver) {}

    // Canonical JSON serialization (for evidence files)
    std::string to_json() const;

    // Deserialize from JSON
    static std::optional<AttestedExecution> from_json(std::string_view json);
};

// Gate A acceptance evidence structure
struct GateAEvidence {
    std::string gate{"A"};
    std::string component{"identity_primitives"};
    std::string sha256_status{"pending"};
    std::string uuid_status{"pending"};
    std::string timestamp_status{"pending"};
    std::string identity_composition_status{"pending"};
    bool deterministic{false};
    Timestamp captured_at;

    std::string to_json() const;
    bool all_passed() const {
        return sha256_status == "passed" && 
               uuid_status == "passed" && 
               timestamp_status == "passed" && 
               identity_composition_status == "passed";
    }
};

} // namespace val063
