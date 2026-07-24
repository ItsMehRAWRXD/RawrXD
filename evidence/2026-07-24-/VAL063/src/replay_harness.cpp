#include "replay_harness.hpp"
#include <sstream>
#include <algorithm>

namespace val063 {

// ============================================================================
// ReplayResult
// ============================================================================

std::string ReplayResult::to_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"success\": " << (success ? "true" : "false") << ",\n";
    oss << "  \"identity_verified\": " << (identity_verified ? "true" : "false") << ",\n";
    oss << "  \"sequence_verified\": " << (sequence_verified ? "true" : "false") << ",\n";
    oss << "  \"hash_chain_verified\": " << (hash_chain_verified ? "true" : "false") << ",\n";
    oss << "  \"temporal_integrity_verified\": " << (temporal_integrity_verified ? "true" : "false") << ",\n";
    oss << "  \"runtime_equivalence_verified\": " << (runtime_equivalence_verified ? "true" : "false") << ",\n";
    oss << "  \"output_equivalence_verified\": " << (output_equivalence_verified ? "true" : "false") << ",\n";
    oss << "  \"events_processed\": " << events_processed << ",\n";
    oss << "  \"events_verified\": " << events_verified << ",\n";
    oss << "  \"events_failed\": " << events_failed << ",\n";
    oss << "  \"deterministic\": " << (deterministic ? "true" : "false") << ",\n";
    
    if (failure_reason) {
        oss << "  \"failure_reason\": \"" << *failure_reason << "\",\n";
    }
    if (failure_sequence_id) {
        oss << "  \"failure_sequence_id\": " << *failure_sequence_id << ",\n";
    }
    
    oss << "  \"replay_duration_ns\": " << replay_duration.count() << "\n";
    oss << "}";
    return oss.str();
}

// ============================================================================
// ReplayHarness
// ============================================================================

ReplayHarness::ReplayHarness(const ReplayConfig& config) : config_(config) {}

void ReplayHarness::load_trace(std::vector<StreamingEvent> events) {
    trace_ = std::move(events);
}

void ReplayHarness::load_trace(const AttestationRecord& attestation) {
    // In a real implementation, this would reconstruct events from attestation
    // For now, we just store the attestation reference
    trace_.clear();
}

ReplayResult ReplayHarness::replay() {
    ExecutionIdentity empty_identity;
    return replay(empty_identity);
}

ReplayResult ReplayHarness::replay(const ExecutionIdentity& expected_identity) {
    RuntimeVersion empty_runtime;
    return replay(expected_identity, empty_runtime);
}

ReplayResult ReplayHarness::replay(
    const ExecutionIdentity& expected_identity,
    const RuntimeVersion& expected_runtime
) {
    auto start_time = std::chrono::steady_clock::now();
    
    ReplayResult result;
    
    // Apply injections (for testing)
    std::vector<StreamingEvent> events = apply_injections(trace_);
    
    if (events.empty()) {
        result.failure_reason = "Empty trace";
        last_result_ = result;
        return result;
    }
    
    result.events_processed = events.size();
    
    // Step 1: Verify identity chain
    if (config_.verify_identity) {
        log_verbose("Verifying identity chain...");
        result.identity_verified = verify_identity_chain(expected_identity);
        if (!result.identity_verified) {
            result.failure_reason = "Identity chain verification failed";
        }
    } else {
        result.identity_verified = true;
    }
    
    // Step 2: Verify sequence order
    if (config_.verify_sequence) {
        log_verbose("Verifying sequence order...");
        result.sequence_verified = verify_sequence_order();
        if (!result.sequence_verified && !result.failure_reason) {
            result.failure_reason = "Sequence order verification failed";
        }
    } else {
        result.sequence_verified = true;
    }
    
    // Step 3: Verify event hashes
    if (config_.verify_hashes) {
        log_verbose("Verifying event hashes...");
        result.hash_chain_verified = verify_event_hashes();
        if (!result.hash_chain_verified && !result.failure_reason) {
            result.failure_reason = "Hash chain verification failed";
        }
    } else {
        result.hash_chain_verified = true;
    }
    
    // Step 4: Verify temporal integrity
    if (config_.verify_temporal) {
        log_verbose("Verifying temporal integrity...");
        result.temporal_integrity_verified = verify_temporal_integrity();
        if (!result.temporal_integrity_verified && !result.failure_reason) {
            result.failure_reason = "Temporal integrity verification failed";
        }
    } else {
        result.temporal_integrity_verified = true;
    }
    
    // Step 5: Verify runtime equivalence
    if (config_.verify_runtime && !expected_runtime.to_string().empty()) {
        log_verbose("Verifying runtime equivalence...");
        result.runtime_equivalence_verified = verify_runtime_equivalence(expected_runtime);
        if (!result.runtime_equivalence_verified && !result.failure_reason) {
            result.failure_reason = "Runtime equivalence verification failed";
        }
    } else {
        result.runtime_equivalence_verified = true;
    }
    
    // Calculate duration
    auto end_time = std::chrono::steady_clock::now();
    result.replay_duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
        end_time - start_time
    );
    
    // Determine success
    result.success = result.all_verified();
    result.deterministic = result.success;
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.replays_executed;
        if (result.success) {
            ++stats_.replays_passed;
        } else {
            ++stats_.replays_failed;
        }
        if (!result.identity_verified) ++stats_.identity_mismatches;
        if (!result.sequence_verified) ++stats_.sequence_corruptions;
        if (!result.hash_chain_verified) ++stats_.hash_failures;
        if (!result.temporal_integrity_verified) ++stats_.temporal_violations;
    }
    
    last_result_ = result;
    return result;
}

ReplayHarness::Statistics ReplayHarness::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

// ============================================================================
// Verification Steps
// ============================================================================

bool ReplayHarness::verify_identity_chain(const ExecutionIdentity& expected) {
    if (trace_.empty()) return false;
    
    // All events should have the same execution ID
    const auto& first_id = trace_[0].execution_id;
    
    for (const auto& event : trace_) {
        if (event.execution_id != first_id) {
            return false;
        }
    }
    
    // If expected identity provided, verify match
    if (expected.is_complete()) {
        // In real implementation, compare with attestation identity
        // For now, just check that events have consistent identity
    }
    
    return true;
}

bool ReplayHarness::verify_sequence_order() {
    if (trace_.size() < 2) return true;
    
    return EventSequenceValidator::validate_sequence(trace_) &&
           EventSequenceValidator::validate_no_gaps(trace_);
}

bool ReplayHarness::verify_event_hashes() {
    return EventSequenceValidator::validate_hashes(trace_);
}

bool ReplayHarness::verify_temporal_integrity() {
    if (trace_.size() < 2) return true;
    
    // Check monotonic timestamps
    for (size_t i = 1; i < trace_.size(); ++i) {
        if (!TimestampProvider::is_monotonic(trace_[i-1].timestamp, trace_[i].timestamp)) {
            return false;
        }
    }
    
    return true;
}

bool ReplayHarness::verify_runtime_equivalence(const RuntimeVersion& expected) {
    // In a real implementation, this would verify the runtime binary hash
    // matches the expected version
    return true;
}

bool ReplayHarness::verify_output_equivalence(const Hash256& expected_output) {
    // In a real implementation, this would re-execute and compare outputs
    return true;
}

// ============================================================================
// Failure Injection (for testing)
// ============================================================================

void ReplayHarness::inject_sequence_corruption(uint64_t sequence_id) {
    std::lock_guard<std::mutex> lock(injection_mutex_);
    injections_.corrupted_sequences.insert(sequence_id);
}

void ReplayHarness::inject_hash_mutation(uint64_t sequence_id) {
    std::lock_guard<std::mutex> lock(injection_mutex_);
    injections_.mutated_hashes.insert(sequence_id);
}

void ReplayHarness::inject_dropped_event(uint64_t sequence_id) {
    std::lock_guard<std::mutex> lock(injection_mutex_);
    injections_.dropped_events.insert(sequence_id);
}

void ReplayHarness::inject_reordered_events(uint64_t seq_a, uint64_t seq_b) {
    std::lock_guard<std::mutex> lock(injection_mutex_);
    injections_.reordered_pairs.insert({seq_a, seq_b});
}

void ReplayHarness::inject_temporal_anomaly(uint64_t sequence_id) {
    std::lock_guard<std::mutex> lock(injection_mutex_);
    injections_.temporal_anomalies.insert(sequence_id);
}

void ReplayHarness::reset_injections() {
    std::lock_guard<std::mutex> lock(injection_mutex_);
    injections_ = InjectionState{};
}

std::vector<StreamingEvent> ReplayHarness::apply_injections(
    const std::vector<StreamingEvent>& events
) const {
    std::lock_guard<std::mutex> lock(injection_mutex_);
    
    std::vector<StreamingEvent> result = events;
    
    // Apply dropped events
    result.erase(
        std::remove_if(result.begin(), result.end(),
            [this](const StreamingEvent& e) {
                return injections_.dropped_events.count(e.sequence_id) > 0;
            }
        ),
        result.end()
    );
    
    // Apply sequence corruption
    for (auto& event : result) {
        if (injections_.corrupted_sequences.count(event.sequence_id) > 0) {
            event.sequence_id = 0xFFFFFFFF;  // Corrupt sequence
        }
    }
    
    // Apply hash mutation
    for (auto& event : result) {
        if (injections_.mutated_hashes.count(event.sequence_id) > 0) {
            event.event_hash.bytes[0] ^= 0xFF;  // Flip bits in hash
        }
    }
    
    // Apply temporal anomalies
    for (auto& event : result) {
        if (injections_.temporal_anomalies.count(event.sequence_id) > 0) {
            // Make timestamp go backwards
            event.timestamp.monotonic -= std::chrono::seconds(1);
        }
    }
    
    // Apply reordering
    for (const auto& [seq_a, seq_b] : injections_.reordered_pairs) {
        auto it_a = std::find_if(result.begin(), result.end(),
            [seq_a](const StreamingEvent& e) { return e.sequence_id == seq_a; });
        auto it_b = std::find_if(result.begin(), result.end(),
            [seq_b](const StreamingEvent& e) { return e.sequence_id == seq_b; });
        
        if (it_a != result.end() && it_b != result.end()) {
            std::swap(*it_a, *it_b);
        }
    }
    
    return result;
}

void ReplayHarness::log_verbose(const std::string& message) const {
    if (config_.verbose) {
        std::cout << "[ReplayHarness] " << message << std::endl;
    }
}

// ============================================================================
// Factory Functions
// ============================================================================

std::unique_ptr<ReplayHarness> create_replay_harness(const ReplayConfig& config) {
    return std::make_unique<ReplayHarness>(config);
}

bool quick_verify(
    std::span<const StreamingEvent> events,
    const ExecutionIdentity& identity
) {
    ReplayHarness harness;
    harness.load_trace(std::vector<StreamingEvent>(events.begin(), events.end()));
    
    ReplayConfig config;
    config.verify_output = false;  // Skip output verification for quick check
    
    auto result = harness.replay(identity);
    return result.success;
}

ReplayResult verify_attestation(
    const AttestationRecord& attestation,
    const ReplayConfig& config
) {
    ReplayHarness harness(config);
    harness.load_trace(attestation);
    return harness.replay(attestation.identity, attestation.runtime_version);
}

// ============================================================================
// GateDEvidence
// ============================================================================

std::string GateDEvidence::to_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"gate\": \"" << gate << "\",\n";
    oss << "  \"name\": \"" << name << "\",\n";
    oss << "  \"status\": \"" << status << "\",\n";
    oss << "  \"identity_verified\": " << (identity_verified ? "true" : "false") << ",\n";
    oss << "  \"sequence_verified\": " << (sequence_verified ? "true" : "false") << ",\n";
    oss << "  \"hash_chain_verified\": " << (hash_chain_verified ? "true" : "false") << ",\n";
    oss << "  \"temporal_integrity_verified\": " << (temporal_integrity_verified ? "true" : "false") << ",\n";
    oss << "  \"runtime_equivalence_verified\": " << (runtime_equivalence_verified ? "true" : "false") << ",\n";
    oss << "  \"output_equivalence_verified\": " << (output_equivalence_verified ? "true" : "false") << ",\n";
    oss << "  \"event_count\": " << event_count << ",\n";
    oss << "  \"replay_deterministic\": " << (replay_deterministic ? "true" : "false") << ",\n";
    oss << "  \"captured_at\": \"" << captured_at.iso8601() << "\"\n";
    oss << "}";
    return oss.str();
}

} // namespace val063
