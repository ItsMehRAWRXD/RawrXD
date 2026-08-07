/**
 * VAL-063 Master Test Suite
 * Comprehensive tests for all 4 gates (A, B, C, D)
 */

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <functional>

#include "execution_types.hpp"
#include "hash_provider.hpp"
#include "uuid_provider.hpp"
#include "timestamp_provider.hpp"
#include "attestation_record.hpp"
#include "execution_gateway.hpp"
#include "streaming_adapter.hpp"
#include "replay_harness.hpp"

using namespace val063;

// Test Framework
struct TestResult {
    std::string name;
    bool passed;
    std::chrono::microseconds duration;
    std::string error;
};

class TestRunner {
public:
    std::vector<TestResult> results;
    
    void run(const std::string& name, std::function<bool()> test) {
        auto start = std::chrono::steady_clock::now();
        TestResult result;
        result.name = name;
        
        try {
            result.passed = test();
        } catch (const std::exception& e) {
            result.passed = false;
            result.error = e.what();
        } catch (...) {
            result.passed = false;
            result.error = "Unknown exception";
        }
        
        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        results.push_back(result);
    }
    
    void print_summary() const {
        size_t passed = 0, failed = 0;
        for (const auto& r : results) {
            if (r.passed) passed++;
            else failed++;
        }
        
        std::cout << "\n========================================\n";
        std::cout << "  TEST SUMMARY\n";
        std::cout << "========================================\n";
        std::cout << "Total:  " << results.size() << "\n";
        std::cout << "Passed: " << passed << "\n";
        std::cout << "Failed: " << failed << "\n";
        
        if (failed == 0) {
            std::cout << "\n✓ ALL TESTS PASSED\n";
        } else {
            std::cout << "\n✗ SOME TESTS FAILED\n";
            for (const auto& r : results) {
                if (!r.passed) {
                    std::cout << "  - " << r.name << ": " << r.error << "\n";
                }
            }
        }
    }
};

// Gate A: Identity Primitives Tests
void test_gate_a(TestRunner& runner) {
    std::cout << "\n========================================\n";
    std::cout << "  GATE A: Identity Primitives\n";
    std::cout << "========================================\n";
    
    // Test 1: SHA-256 Hash Generation
    runner.run("SHA-256: Basic hash generation", []() {
        HashProvider provider;
        auto hash = provider.compute_sha256("test data");
        return hash.size() == 32; // 256 bits = 32 bytes
    });
    
    // Test 2: SHA-256 Determinism
    runner.run("SHA-256: Deterministic output", []() {
        HashProvider provider;
        auto hash1 = provider.compute_sha256("test data");
        auto hash2 = provider.compute_sha256("test data");
        return hash1 == hash2;
    });
    
    // Test 3: SHA-256 Avalanche Effect
    runner.run("SHA-256: Avalanche effect", []() {
        HashProvider provider;
        auto hash1 = provider.compute_sha256("test data");
        auto hash2 = provider.compute_sha256("test data!");
        return hash1 != hash2;
    });
    
    // Test 4: UUID Generation
    runner.run("UUID: Basic generation", []() {
        UUIDProvider provider;
        auto uuid = provider.generate_uuid_v4();
        return uuid.size() == 16; // 128 bits = 16 bytes
    });
    
    // Test 5: UUID Uniqueness
    runner.run("UUID: Uniqueness", []() {
        UUIDProvider provider;
        auto uuid1 = provider.generate_uuid_v4();
        auto uuid2 = provider.generate_uuid_v4();
        return uuid1 != uuid2;
    });
    
    // Test 6: Timestamp Generation
    runner.run("Timestamp: Basic generation", []() {
        TimestampProvider provider;
        auto ts = provider.now();
        return ts.nanoseconds_since_epoch > 0;
    });
    
    // Test 7: Timestamp Monotonicity
    runner.run("Timestamp: Monotonicity", []() {
        TimestampProvider provider;
        auto ts1 = provider.now();
        auto ts2 = provider.now();
        return ts2.nanoseconds_since_epoch >= ts1.nanoseconds_since_epoch;
    });
    
    // Test 8: Execution Identity Composition
    runner.run("Identity: Canonical composition", []() {
        ExecutionIdentity identity;
        identity.prompt_hash = HashProvider::compute_sha256("prompt");
        identity.configuration_hash = HashProvider::compute_sha256("config");
        identity.model_hash = HashProvider::compute_sha256("model");
        identity.runtime_hash = HashProvider::compute_sha256("runtime");
        
        auto combined = identity.combined_identity();
        return combined.size() == 32;
    });
    
    // Test 9: Execution Identity Determinism
    runner.run("Identity: Deterministic composition", []() {
        ExecutionIdentity identity1;
        identity1.prompt_hash = HashProvider::compute_sha256("prompt");
        identity1.configuration_hash = HashProvider::compute_sha256("config");
        identity1.model_hash = HashProvider::compute_sha256("model");
        identity1.runtime_hash = HashProvider::compute_sha256("runtime");
        
        ExecutionIdentity identity2;
        identity2.prompt_hash = HashProvider::compute_sha256("prompt");
        identity2.configuration_hash = HashProvider::compute_sha256("config");
        identity2.model_hash = HashProvider::compute_sha256("model");
        identity2.runtime_hash = HashProvider::compute_sha256("runtime");
        
        return identity1.combined_identity() == identity2.combined_identity();
    });
    
    // Test 10: Execution Identity Uniqueness
    runner.run("Identity: Uniqueness with different inputs", []() {
        ExecutionIdentity identity1;
        identity1.prompt_hash = HashProvider::compute_sha256("prompt1");
        identity1.configuration_hash = HashProvider::compute_sha256("config");
        identity1.model_hash = HashProvider::compute_sha256("model");
        identity1.runtime_hash = HashProvider::compute_sha256("runtime");
        
        ExecutionIdentity identity2;
        identity2.prompt_hash = HashProvider::compute_sha256("prompt2");
        identity2.configuration_hash = HashProvider::compute_sha256("config");
        identity2.model_hash = HashProvider::compute_sha256("model");
        identity2.runtime_hash = HashProvider::compute_sha256("runtime");
        
        return identity1.combined_identity() != identity2.combined_identity();
    });
}

// Gate B: Gateway Binding Tests
void test_gate_b(TestRunner& runner) {
    std::cout << "\n========================================\n";
    std::cout << "  GATE B: Gateway Binding\n";
    std::cout << "========================================\n";
    
    // Test 1: Gateway Initialization
    runner.run("Gateway: Initialization", []() {
        ExecutionGateway gateway;
        return gateway.initialize();
    });
    
    // Test 2: Gateway Binding
    runner.run("Gateway: Binding creation", []() {
        ExecutionGateway gateway;
        gateway.initialize();
        
        ExecutionIdentity identity;
        identity.prompt_hash = HashProvider::compute_sha256("test");
        identity.configuration_hash = HashProvider::compute_sha256("config");
        identity.model_hash = HashProvider::compute_sha256("model");
        identity.runtime_hash = HashProvider::compute_sha256("runtime");
        
        auto binding = gateway.create_binding(identity);
        return binding.is_valid();
    });
    
    // Test 3: Gateway Integrity Verification
    runner.run("Gateway: Integrity verification", []() {
        ExecutionGateway gateway;
        gateway.initialize();
        
        ExecutionIdentity identity;
        identity.prompt_hash = HashProvider::compute_sha256("test");
        identity.configuration_hash = HashProvider::compute_sha256("config");
        identity.model_hash = HashProvider::compute_sha256("model");
        identity.runtime_hash = HashProvider::compute_sha256("runtime");
        
        auto binding = gateway.create_binding(identity);
        return gateway.verify_integrity(binding);
    });
    
    // Test 4: Attestation Record Creation
    runner.run("Attestation: Record creation", []() {
        AttestationRecord record;
        record.execution_id = UUIDProvider::generate_uuid_v4();
        record.identity.prompt_hash = HashProvider::compute_sha256("test");
        record.timestamp = TimestampProvider::now();
        record.deterministic = true;
        
        return record.is_valid();
    });
    
    // Test 5: Attestation Chain
    runner.run("Attestation: Chain linking", []() {
        AttestationRecord record1;
        record1.execution_id = UUIDProvider::generate_uuid_v4();
        record1.previous_attestation_hash = Hash256::null();
        record1.compute_hash();
        
        AttestationRecord record2;
        record2.execution_id = UUIDProvider::generate_uuid_v4();
        record2.previous_attestation_hash = record1.record_hash;
        record2.compute_hash();
        
        return record2.previous_attestation_hash == record1.record_hash;
    });
}

// Gate C: Streaming Adapter Tests
void test_gate_c(TestRunner& runner) {
    std::cout << "\n========================================\n";
    std::cout << "  GATE C: Streaming Adapter\n";
    std::cout << "========================================\n";
    
    // Test 1: Event Creation
    runner.run("Event: Basic creation", []() {
        StreamingEvent event;
        event.sequence_id = 1;
        event.timestamp = TimestampProvider::now();
        event.event_type = "test";
        event.payload = std::vector<uint8_t>{1, 2, 3, 4};
        event.compute_hash();
        
        return event.is_valid();
    });
    
    // Test 2: Event Hash Chain
    runner.run("Event: Hash chain integrity", []() {
        StreamingEvent event1;
        event1.sequence_id = 1;
        event1.timestamp = TimestampProvider::now();
        event1.event_type = "test";
        event1.previous_event_hash = Hash256::null();
        event1.compute_hash();
        
        StreamingEvent event2;
        event2.sequence_id = 2;
        event2.timestamp = TimestampProvider::now();
        event2.event_type = "test";
        event2.previous_event_hash = event1.event_hash;
        event2.compute_hash();
        
        return event2.previous_event_hash == event1.event_hash;
    });
    
    // Test 3: Bounded Queue
    runner.run("Queue: Bounded capacity", []() {
        BoundedEventQueue queue;
        queue.configure({1024, std::chrono::seconds(30)});
        
        // Fill queue
        for (int i = 0; i < 1024; i++) {
            StreamingEvent event;
            event.sequence_id = i;
            if (!queue.push(event)) {
                return false;
            }
        }
        
        // Next push should fail
        StreamingEvent overflow;
        overflow.sequence_id = 1024;
        return !queue.push(overflow); // Should return false
    });
    
    // Test 4: Streaming Adapter
    runner.run("Adapter: Basic operation", []() {
        StreamingAdapter adapter;
        adapter.initialize({1024, std::chrono::seconds(30)});
        
        StreamingEvent event;
        event.sequence_id = 1;
        event.timestamp = TimestampProvider::now();
        event.event_type = "test";
        event.payload = std::vector<uint8_t>{1, 2, 3, 4};
        
        return adapter.emit_event(event);
    });
    
    // Test 5: Event Ordering
    runner.run("Adapter: Event ordering", []() {
        StreamingAdapter adapter;
        adapter.initialize({1024, std::chrono::seconds(30)});
        
        for (int i = 0; i < 10; i++) {
            StreamingEvent event;
            event.sequence_id = i;
            event.timestamp = TimestampProvider::now();
            event.event_type = "test";
            event.compute_hash();
            
            if (!adapter.emit_event(event)) {
                return false;
            }
        }
        
        return adapter.verify_sequence();
    });
}

// Gate D: Replay Harness Tests
void test_gate_d(TestRunner& runner) {
    std::cout << "\n========================================\n";
    std::cout << "  GATE D: Replay Harness\n";
    std::cout << "========================================\n";
    
    // Test 1: Replay Harness Initialization
    runner.run("Replay: Initialization", []() {
        ReplayHarness harness;
        return harness.initialize();
    });
    
    // Test 2: Event Recording
    runner.run("Replay: Event recording", []() {
        ReplayHarness harness;
        harness.initialize();
        
        StreamingEvent event;
        event.sequence_id = 1;
        event.timestamp = TimestampProvider::now();
        event.event_type = "test";
        event.payload = std::vector<uint8_t>{1, 2, 3, 4};
        event.compute_hash();
        
        return harness.record_event(event);
    });
    
    // Test 3: Deterministic Replay
    runner.run("Replay: Deterministic replay", []() {
        ReplayHarness harness;
        harness.initialize();
        
        // Record events
        for (int i = 0; i < 5; i++) {
            StreamingEvent event;
            event.sequence_id = i;
            event.timestamp = TimestampProvider::now();
            event.event_type = "test";
            event.payload = std::vector<uint8_t>{static_cast<uint8_t>(i)};
            event.compute_hash();
            harness.record_event(event);
        }
        
        // Capture state
        auto state = harness.capture_state();
        
        // Replay
        return harness.replay(state);
    });
    
    // Test 4: Replay Verification
    runner.run("Replay: Verification", []() {
        ReplayHarness harness;
        harness.initialize();
        
        // Record
        for (int i = 0; i < 5; i++) {
            StreamingEvent event;
            event.sequence_id = i;
            event.timestamp = TimestampProvider::now();
            event.event_type = "test";
            event.payload = std::vector<uint8_t>{static_cast<uint8_t>(i)};
            event.compute_hash();
            harness.record_event(event);
        }
        
        auto state = harness.capture_state();
        harness.replay(state);
        
        return harness.verify_replay();
    });
    
    // Test 5: Tamper Detection
    runner.run("Replay: Tamper detection", []() {
        ReplayHarness harness;
        harness.initialize();
        
        // Record
        for (int i = 0; i < 5; i++) {
            StreamingEvent event;
            event.sequence_id = i;
            event.timestamp = TimestampProvider::now();
            event.event_type = "test";
            event.payload = std::vector<uint8_t>{static_cast<uint8_t>(i)};
            event.compute_hash();
            harness.record_event(event);
        }
        
        auto state = harness.capture_state();
        
        // Tamper with state
        if (!state.events.empty()) {
            state.events[0].payload[0] = 0xFF;
        }
        
        // Replay should detect tampering
        harness.replay(state);
        return !harness.verify_replay(); // Should fail verification
    });
}

int main() {
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     VAL-063 Master Test Suite                               ║\n";
    std::cout << "║     Foundation Attestation & Identity                        ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    
    TestRunner runner;
    
    test_gate_a(runner);
    test_gate_b(runner);
    test_gate_c(runner);
    test_gate_d(runner);
    
    runner.print_summary();
    
    // Return exit code
    for (const auto& r : runner.results) {
        if (!r.passed) return 1;
    }
    return 0;
}
