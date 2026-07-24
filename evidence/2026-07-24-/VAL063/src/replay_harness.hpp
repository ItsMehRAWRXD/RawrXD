#pragma once

#include "streaming_adapter.hpp"
#include "execution_gateway.hpp"
#include <vector>
#include <optional>

namespace val063 {

// Replay verification result
struct ReplayResult {
    bool success{false};
    
    // Verification checks
    bool identity_verified{false};
    bool sequence_verified{false};
    bool hash_chain_verified{false};
    bool temporal_integrity_verified{false};
    bool runtime_equivalence_verified{false};
    bool output_equivalence_verified{false};
    
    // Event statistics
    uint64_t events_processed{0};
    uint64_t events_verified{0};
    uint64_t events_failed{0};
    
    // Failure details (if any)
    std::optional<std::string> failure_reason;
    std::optional<uint64_t> failure_sequence_id;
    
    // Timing
    std::chrono::nanoseconds replay_duration{0};
    
    // Determinism flag
    bool deterministic{false};
    
    // Canonical JSON output
    std::string to_json() const;
    
    // All checks passed
    bool all_verified() const {
        return identity_verified &&
               sequence_verified &&
               hash_chain_verified &&
               temporal_integrity_verified &&
               runtime_equivalence_verified &&
               output_equivalence_verified;
    }
};

// Replay configuration
struct ReplayConfig {
    // Verification strictness
    bool verify_identity{true};
    bool verify_sequence{true};
    bool verify_hashes{true};
    bool verify_temporal{true};
    bool verify_runtime{true};
    bool verify_output{true};
    
    // Tolerance for timing comparison (nanoseconds)
    std::chrono::nanoseconds timing_tolerance{std::chrono::milliseconds(100)};
    
    // Maximum events to process (0 = unlimited)
    uint64_t max_events{0};
    
    // Enable detailed logging
    bool verbose{false};
};

// The Replay Harness (Gate D)
//
// RESPONSIBILITY: Verify that an execution trace is reproducible
// CONTRACT:
//   - Identity chain is unbroken
//   - Sequence is complete and ordered
//   - Event hashes verify integrity
//   - Temporal properties are consistent
//   - Output is deterministic
//
class ReplayHarness {
public:
    explicit ReplayHarness(const ReplayConfig& config = ReplayConfig{});
    ~ReplayHarness() = default;

    // Non-copyable
    ReplayHarness(const ReplayHarness&) = delete;
    ReplayHarness& operator=(const ReplayHarness&) = delete;

    // Load execution trace for replay
    void load_trace(std::vector<StreamingEvent> events);
    void load_trace(const AttestationRecord& attestation);

    // Execute replay verification
    ReplayResult replay();

    // Execute replay with expected identity
    ReplayResult replay(const ExecutionIdentity& expected_identity);

    // Execute replay with full context
    ReplayResult replay(
        const ExecutionIdentity& expected_identity,
        const RuntimeVersion& expected_runtime
    );

    // Get last result
    std::optional<ReplayResult> last_result() const { return last_result_; }

    // Statistics
    struct Statistics {
        uint64_t replays_executed{0};
        uint64_t replays_passed{0};
        uint64_t replays_failed{0};
        uint64_t identity_mismatches{0};
        uint64_t sequence_corruptions{0};
        uint64_t hash_failures{0};
        uint64_t temporal_violations{0};
    };
    Statistics get_statistics() const;

    // Failure injection (for testing)
    void inject_sequence_corruption(uint64_t sequence_id);
    void inject_hash_mutation(uint64_t sequence_id);
    void inject_dropped_event(uint64_t sequence_id);
    void inject_reordered_events(uint64_t seq_a, uint64_t seq_b);
    void inject_temporal_anomaly(uint64_t sequence_id);
    void reset_injections();

private:
    ReplayConfig config_;
    std::vector<StreamingEvent> trace_;
    std::optional<ReplayResult> last_result_;
    
    mutable Statistics stats_;
    mutable std::mutex stats_mutex_;
    
    // Injection state (for testing)
    struct InjectionState {
        std::set<uint64_t> corrupted_sequences;
        std::set<uint64_t> mutated_hashes;
        std::set<uint64_t> dropped_events;
        std::set<std::pair<uint64_t, uint64_t>> reordered_pairs;
        std::set<uint64_t> temporal_anomalies;
    };
    InjectionState injections_;
    mutable std::mutex injection_mutex_;

    // Verification steps
    bool verify_identity_chain(const ExecutionIdentity& expected);
    bool verify_sequence_order();
    bool verify_event_hashes();
    bool verify_temporal_integrity();
    bool verify_runtime_equivalence(const RuntimeVersion& expected);
    bool verify_output_equivalence(const Hash256& expected_output);

    // Apply injections (for testing)
    std::vector<StreamingEvent> apply_injections(
        const std::vector<StreamingEvent>& events
    ) const;

    // Logging
    void log_verbose(const std::string& message) const;
};

// Factory
std::unique_ptr<ReplayHarness> create_replay_harness(
    const ReplayConfig& config = ReplayConfig{}
);

// Quick verification
bool quick_verify(
    std::span<const StreamingEvent> events,
    const ExecutionIdentity& identity
);

// Full verification with attestation
ReplayResult verify_attestation(
    const AttestationRecord& attestation,
    const ReplayConfig& config = ReplayConfig{}
);

// Gate D evidence structure
struct GateDEvidence {
    std::string gate{"D"};
    std::string name{"Replay Harness"};
    std::string status{"PENDING"};
    
    bool identity_verified{false};
    bool sequence_verified{false};
    bool hash_chain_verified{false};
    bool temporal_integrity_verified{false};
    bool runtime_equivalence_verified{false};
    bool output_equivalence_verified{false};
    
    uint64_t event_count{0};
    bool replay_deterministic{false};
    
    Timestamp captured_at;
    
    std::string to_json() const;
    bool all_passed() const {
        return identity_verified &&
               sequence_verified &&
               hash_chain_verified &&
               temporal_integrity_verified &&
               runtime_equivalence_verified &&
               output_equivalence_verified;
    }
};

} // namespace val063
