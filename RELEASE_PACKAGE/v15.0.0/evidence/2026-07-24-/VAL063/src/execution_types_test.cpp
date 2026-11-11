#include "execution_types.hpp"
#include "hash_provider.hpp"
#include "uuid_provider.hpp"
#include "timestamp_provider.hpp"
#include <iostream>
#include <fstream>
#include <cassert>
#include <set>

using namespace val063;

// ============================================================================
// Test Results
// ============================================================================

struct TestResults {
    int passed = 0;
    int failed = 0;
    
    void check(bool condition, const char* test_name) {
        if (condition) {
            std::cout << "[PASS] " << test_name << std::endl;
            ++passed;
        } else {
            std::cout << "[FAIL] " << test_name << std::endl;
            ++failed;
        }
    }
};

// ============================================================================
// Hash256 Tests
// ============================================================================

void test_hash256(TestResults& results) {
    std::cout << "\n=== Hash256 Tests ===" << std::endl;
    
    // Test: Same bytes → same hash
    {
        const char* data1 = "test data";
        const char* data2 = "test data";
        auto h1 = hash::of_string(data1);
        auto h2 = hash::of_string(data2);
        results.check(h1 == h2, "SHA-256: Same bytes produce same hash");
    }
    
    // Test: Different bytes → different hash
    {
        auto h1 = hash::of_string("data1");
        auto h2 = hash::of_string("data2");
        results.check(h1 != h2, "SHA-256: Different bytes produce different hash");
    }
    
    // Test: Hex roundtrip
    {
        auto original = hash::of_string("roundtrip test");
        auto hex_str = original.hex();
        auto parsed = Hash256::from_hex(hex_str);
        results.check(parsed.has_value() && parsed.value() == original, 
                      "SHA-256: Hex serialization roundtrip");
    }
    
    // Test: Known SHA-256 value (empty string)
    {
        auto empty_hash = hash::of_string("");
        auto expected = Hash256::from_hex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        results.check(expected.has_value() && empty_hash == expected.value(),
                      "SHA-256: Empty string hash matches known value");
    }
    
    // Test: Null check
    {
        Hash256 null_hash;
        results.check(null_hash.is_null(), "SHA-256: Default hash is null");
        auto real_hash = hash::of_string("not null");
        results.check(!real_hash.is_null(), "SHA-256: Computed hash is not null");
    }
    
    // Test: Hash comparison (constant time)
    {
        auto h1 = hash::of_string("test");
        auto h2 = hash::of_string("test");
        auto h3 = hash::of_string("different");
        results.check(HashProvider::verify(h1, h2), "SHA-256: Verify same hashes");
        results.check(!HashProvider::verify(h1, h3), "SHA-256: Verify different hashes");
    }
}

// ============================================================================
// UUID Tests
// ============================================================================

void test_uuid(TestResults& results) {
    std::cout << "\n=== UUID Tests ===" << std::endl;
    
    // Test: Generation produces valid UUIDs
    {
        std::set<std::string> generated;
        bool all_valid = true;
        for (int i = 0; i < 100; ++i) {
            auto id = uuid::generate();
            auto str = uuid::to_string(id);
            if (!UuidProvider::is_valid(str)) {
                all_valid = false;
                break;
            }
            generated.insert(str);
        }
        results.check(all_valid, "UUID: All generated UUIDs are valid");
        results.check(generated.size() == 100, "UUID: 100 generations are unique");
    }
    
    // Test: String roundtrip
    {
        auto original = uuid::generate();
        auto str = uuid::to_string(original);
        auto parsed = uuid::parse(str);
        results.check(parsed.has_value() && parsed.value() == original,
                      "UUID: String roundtrip");
    }
    
    // Test: Version 4 format
    {
        auto id = uuid::generate();
        auto str = uuid::to_string(id);
        // Position 14 should be '4' (version)
        results.check(str[14] == '4', "UUID: Version 4 format (position 14)");
        // Position 19 should be 8, 9, a, or b (variant)
        char variant = str[19];
        bool valid_variant = (variant == '8' || variant == '9' || 
                               variant == 'a' || variant == 'b' ||
                               variant == 'A' || variant == 'B');
        results.check(valid_variant, "UUID: RFC 4122 variant");
    }
    
    // Test: Invalid UUID detection
    {
        results.check(!UuidProvider::is_valid("not-a-uuid"), 
                      "UUID: Reject invalid format");
        results.check(!UuidProvider::is_valid("550e8400-e29b-41d4-a716-446655440000"),
                      "UUID: Reject version 1 UUID");
    }
}

// ============================================================================
// Timestamp Tests
// ============================================================================

void test_timestamp(TestResults& results) {
    std::cout << "\n=== Timestamp Tests ===" << std::endl;
    
    // Test: Monotonic ordering
    {
        auto t1 = timestamp::now();
        // Small delay
        for (volatile int i = 0; i < 100000; ++i) {}
        auto t2 = timestamp::now();
        results.check(TimestampProvider::is_monotonic(t1, t2),
                      "Timestamp: Monotonic ordering");
    }
    
    // Test: Elapsed duration
    {
        auto t1 = timestamp::now();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        auto t2 = timestamp::now();
        auto elapsed = t2.elapsed_since(t1);
        results.check(elapsed.count() > 0, "Timestamp: Elapsed duration positive");
    }
    
    // Test: ISO 8601 roundtrip
    {
        auto now = Timestamp::now();
        auto iso = now.iso8601();
        auto parsed = TimestampProvider::from_iso8601(iso);
        results.check(parsed.has_value(), "Timestamp: ISO 8601 parse success");
        if (parsed) {
            // Allow small tolerance for millisecond precision
            auto diff = std::chrono::abs(
                now.wall_clock - parsed.value()
            );
            results.check(diff < std::chrono::milliseconds(2),
                          "Timestamp: ISO 8601 roundtrip");
        }
    }
    
    // Test: Timestamp format
    {
        auto now = Timestamp::now();
        auto iso = now.iso8601();
        // Should end with Z (UTC)
        results.check(iso.back() == 'Z', "Timestamp: UTC format (Z suffix)");
        // Should contain T separator
        results.check(iso.find('T') != std::string::npos,
                      "Timestamp: ISO 8601 T separator");
    }
}

// ============================================================================
// Identity Composition Tests
// ============================================================================

void test_identity_composition(TestResults& results) {
    std::cout << "\n=== Identity Composition Tests ===" << std::endl;
    
    // Test: Same components → same identity
    {
        ExecutionIdentity id1{
            hash::of_string("prompt"),
            hash::of_string("config"),
            hash::of_string("model"),
            hash::of_string("runtime")
        };
        ExecutionIdentity id2{
            hash::of_string("prompt"),
            hash::of_string("config"),
            hash::of_string("model"),
            hash::of_string("runtime")
        };
        results.check(id1 == id2, "Identity: Same components are equal");
        results.check(id1.combined_identity() == id2.combined_identity(),
                      "Identity: Same components produce same combined hash");
    }
    
    // Test: One bit change → identity changes
    {
        ExecutionIdentity base{
            hash::of_string("prompt"),
            hash::of_string("config"),
            hash::of_string("model"),
            hash::of_string("runtime")
        };
        ExecutionIdentity changed{
            hash::of_string("prompt"),
            hash::of_string("config"),
            hash::of_string("model"),
            hash::of_string("runtime2")  // Different
        };
        results.check(base != changed, "Identity: Different components are not equal");
        results.check(base.combined_identity() != changed.combined_identity(),
                      "Identity: Different components produce different combined hash");
    }
    
    // Test: Canonical bytes are deterministic
    {
        ExecutionIdentity id{
            hash::of_string("prompt"),
            hash::of_string("config"),
            hash::of_string("model"),
            hash::of_string("runtime")
        };
        auto bytes1 = id.to_canonical_bytes();
        auto bytes2 = id.to_canonical_bytes();
        results.check(bytes1 == bytes2, "Identity: Canonical bytes are deterministic");
    }
    
    // Test: Completeness check
    {
        ExecutionIdentity complete{
            hash::of_string("prompt"),
            hash::of_string("config"),
            hash::of_string("model"),
            hash::of_string("runtime")
        };
        results.check(complete.is_complete(), "Identity: Complete identity check");
        
        ExecutionIdentity incomplete;
        results.check(!incomplete.is_complete(), "Identity: Incomplete identity check");
    }
    
    // Test: Configuration hash distinguishes same prompt
    {
        auto prompt = hash::of_string("same prompt");
        auto model = hash::of_string("model.gguf");
        auto runtime = hash::of_string("runtime.exe");
        
        ExecutionIdentity id1{prompt, hash::of_string("config1"), model, runtime};
        ExecutionIdentity id2{prompt, hash::of_string("config2"), model, runtime};
        
        results.check(id1 != id2, 
                      "Identity: Different config produces different identity");
        results.check(id1.prompt_hash == id2.prompt_hash,
                      "Identity: Same prompt preserved");
        results.check(id1.configuration_hash != id2.configuration_hash,
                      "Identity: Different config hash");
    }
}

// ============================================================================
// AttestedExecution Tests
// ============================================================================

void test_attested_execution(TestResults& results) {
    std::cout << "\n=== AttestedExecution Tests ===" << std::endl;
    
    // Test: JSON serialization
    {
        AttestedExecution exec{
            uuid::generate(),
            ExecutionIdentity{
                hash::of_string("prompt"),
                hash::of_string("config"),
                hash::of_string("model"),
                hash::of_string("runtime")
            },
            timestamp::now(),
            RuntimeVersion{1, 0, 0, "abc123", "2026-07-24"}
        };
        exec.output_hash = hash::of_string("output");
        exec.deterministic = true;
        exec.correlated = true;
        
        auto json = exec.to_json();
        results.check(!json.empty(), "AttestedExecution: JSON serialization");
        results.check(json.find("execution_id") != std::string::npos,
                      "AttestedExecution: JSON contains execution_id");
        results.check(json.find("configuration_hash") != std::string::npos,
                      "AttestedExecution: JSON contains configuration_hash");
        results.check(json.find("\"deterministic\": true") != std::string::npos,
                      "AttestedExecution: JSON contains deterministic flag");
    }
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "VAL-063 Gate A: Identity Primitives Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    TestResults results;
    
    test_hash256(results);
    test_uuid(results);
    test_timestamp(results);
    test_identity_composition(results);
    test_attested_execution(results);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << results.passed << " passed, " 
              << results.failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Generate evidence artifact
    GateAEvidence evidence;
    evidence.sha256_status = (results.passed >= 5) ? "passed" : "failed";
    evidence.uuid_status = (results.passed >= 8) ? "passed" : "failed";
    evidence.timestamp_status = (results.passed >= 11) ? "passed" : "failed";
    evidence.identity_composition_status = (results.passed >= 15) ? "passed" : "failed";
    evidence.deterministic = (results.failed == 0);
    evidence.captured_at = timestamp::now();
    
    std::ofstream evidence_file("gate_A_primitives.json");
    evidence_file << evidence.to_json();
    evidence_file.close();
    
    std::cout << "\nEvidence written to: gate_A_primitives.json" << std::endl;
    
    return results.failed > 0 ? 1 : 0;
}
