// ============================================================================
// PatternGeneratorTest.cpp - Comprehensive Pattern Generator Test Suite
// ============================================================================

#include "ComprehensivePatternGenerator.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <string>

using namespace RawrXD::Reverse;

// Test utilities
struct TestResult {
    std::string name;
    bool passed;
    std::string message;
    double duration_ms;
};

class TestRunner {
public:
    std::vector<TestResult> results;
    
    void run(const std::string& name, std::function<bool()> test) {
        auto start = std::chrono::high_resolution_clock::now();
        bool passed = false;
        std::string message;
        
        try {
            passed = test();
            message = passed ? "OK" : "FAILED";
        } catch (const std::exception& e) {
            message = std::string("EXCEPTION: ") + e.what();
        } catch (...) {
            message = "UNKNOWN EXCEPTION";
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        
        results.push_back({name, passed, message, duration});
    }
    
    void printSummary() {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "TEST SUMMARY\n";
        std::cout << std::string(70, '=') << "\n";
        
        size_t passed = 0, failed = 0;
        double total_time = 0.0;
        
        for (const auto& r : results) {
            std::cout << (r.passed ? "[PASS]" : "[FAIL]") << " " 
                      << std::left << std::setw(40) << r.name
                      << " " << std::right << std::setw(8) << std::fixed << std::setprecision(2) 
                      << r.duration_ms << "ms"
                      << " - " << r.message << "\n";
            
            if (r.passed) passed++;
            else failed++;
            total_time += r.duration_ms;
        }
        
        std::cout << std::string(70, '-') << "\n";
        std::cout << "Total: " << results.size() << " | Passed: " << passed 
                  << " | Failed: " << failed << " | Time: " << total_time << "ms\n";
        std::cout << std::string(70, '=') << "\n";
    }
};

// ============================================================================
// TEST CASES
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     Comprehensive Pattern Generator Test Suite v1.5                  ║\n";
    std::cout << "║     RawrXD Reverse Engineering Infrastructure                        ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════╝\n\n";
    
    TestRunner runner;
    ComprehensivePatternGenerator generator;
    
    // Test 1: Basic pattern generation
    runner.run("Basic Pattern Generation", [&]() {
        std::vector<uint8_t> source = {0x48, 0x89, 0x5C, 0x24, 0x08}; // x86 prologue
        
        GenerationRequest request;
        request.preserve_original = true;
        request.generate_inverses = true;
        request.generate_complements = true;
        request.generate_reversed = true;
        request.generate_xor_variants = true;
        request.xor_keys = {0xAA, 0x55};
        request.generate_anti_patterns = true;
        request.anti_pattern_count = 2;
        request.validate_generated = true;
        
        auto patterns = generator.generateAllPatterns(source, request);
        
        // Should have: original + inverse + complement + reversed + 2 XOR + 2 anti = 8 patterns
        return patterns.size() >= 7; // At least 7 patterns
    });
    
    // Test 2: Inverse generation
    runner.run("Inverse Generation", [&]() {
        std::vector<uint8_t> source = {0xAA, 0x55, 0xFF, 0x00};
        auto inverse = generator.generateInverse(source, "test");
        
        // Inverse should be: 0x55, 0xAA, 0x00, 0xFF
        bool correct = (inverse.bytes.size() == 4) &&
                       (inverse.bytes[0] == 0x55) &&
                       (inverse.bytes[1] == 0xAA) &&
                       (inverse.bytes[2] == 0x00) &&
                       (inverse.bytes[3] == 0xFF);
        
        return correct && inverse.type == PatternType::INVERSE;
    });
    
    // Test 3: Complement generation
    runner.run("Complement Generation", [&]() {
        std::vector<uint8_t> source = {0xAA, 0x55, 0xFF, 0x00};
        auto complement = generator.generateComplement(source, "test");
        
        // Complement should be: 0x55, 0xAA, 0x00, 0xFF
        bool correct = (complement.bytes.size() == 4) &&
                       (complement.bytes[0] == 0x55) &&
                       (complement.bytes[1] == 0xAA) &&
                       (complement.bytes[2] == 0x00) &&
                       (complement.bytes[3] == 0xFF);
        
        return correct && complement.type == PatternType::COMPLEMENT;
    });
    
    // Test 4: Reversed generation
    runner.run("Reversed Generation", [&]() {
        std::vector<uint8_t> source = {0x01, 0x02, 0x03, 0x04, 0x05};
        auto reversed = generator.generateReversed(source, "test");
        
        // Reversed should be: 0x05, 0x04, 0x03, 0x02, 0x01
        bool correct = (reversed.bytes.size() == 5) &&
                       (reversed.bytes[0] == 0x05) &&
                       (reversed.bytes[4] == 0x01);
        
        return correct && reversed.type == PatternType::REVERSED;
    });
    
    // Test 5: XOR variant generation
    runner.run("XOR Variant Generation", [&]() {
        std::vector<uint8_t> source = {0xAA, 0x55, 0xFF, 0x00};
        auto xor_pattern = generator.generateXORVariant(source, 0xAA, "test");
        
        // XOR with 0xAA: 0x00, 0xFF, 0x55, 0xAA
        bool correct = (xor_pattern.bytes.size() == 4) &&
                       (xor_pattern.bytes[0] == 0x00) &&
                       (xor_pattern.bytes[1] == 0xFF) &&
                       (xor_pattern.bytes[2] == 0x55) &&
                       (xor_pattern.bytes[3] == 0xAA);
        
        return correct && xor_pattern.type == PatternType::XOR_VARIANT;
    });
    
    // Test 6: Anti-pattern generation
    runner.run("Anti-Pattern Generation", [&]() {
        std::vector<uint8_t> source = {0x48, 0x89, 0x5C, 0x24, 0x08};
        auto anti_patterns = generator.generateAntiPatterns(source, 3);
        
        // Should generate 3 anti-patterns
        if (anti_patterns.size() != 3) return false;
        
        // Each should be different from source
        for (const auto& ap : anti_patterns) {
            bool different = false;
            for (size_t i = 0; i < source.size(); ++i) {
                if (ap.bytes[i] != source[i]) {
                    different = true;
                    break;
                }
            }
            if (!different) return false;
        }
        
        return true;
    });
    
    // Test 7: Pattern comparison
    runner.run("Pattern Comparison", [&]() {
        std::vector<uint8_t> source1 = {0x48, 0x89, 0x5C, 0x24, 0x08};
        std::vector<uint8_t> source2 = {0x48, 0x89, 0x5C, 0x24, 0x10}; // Last byte different
        
        ComprehensivePattern p1{}, p2{};
        p1.bytes = source1;
        p2.bytes = source2;
        
        auto comparison = generator.comparePatterns(p1, p2);
        
        // Hamming distance should be 1 (one byte different)
        // Similarity should be 4/5 = 0.8
        return comparison.hamming_distance == 1 && 
               std::abs(comparison.similarity - 0.8) < 0.01;
    });
    
    // Test 8: Metrics calculation
    runner.run("Metrics Calculation", [&]() {
        // High entropy pattern (random-looking)
        std::vector<uint8_t> high_entropy = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
        auto metrics = generator.calculateMetrics(high_entropy);
        
        // Should have reasonable entropy
        bool entropy_ok = metrics.shannon_entropy > 2.0 && metrics.shannon_entropy < 8.0;
        bool diversity_ok = metrics.byte_diversity > 0.0 && metrics.byte_diversity <= 1.0;
        bool complexity_ok = metrics.complexity_measure >= 0.0;
        
        return entropy_ok && diversity_ok && complexity_ok;
    });
    
    // Test 9: Pattern validation
    runner.run("Pattern Validation", [&]() {
        std::vector<uint8_t> source = {0x48, 0x89, 0x5C, 0x24, 0x08};
        
        ComprehensivePattern pattern{};
        pattern.bytes = source;
        pattern.entropy = 4.0;
        pattern.byte_diversity = 0.5;
        pattern.complexity = 5.0;
        
        auto validation = generator.validatePattern(pattern);
        
        return validation.valid && validation.confidence > 0.0;
    });
    
    // Test 10: JSON export
    runner.run("JSON Export", [&]() {
        std::vector<uint8_t> source = {0x48, 0x89, 0x5C, 0x24, 0x08};
        
        GenerationRequest request;
        request.preserve_original = true;
        request.generate_inverses = true;
        
        auto patterns = generator.generateAllPatterns(source, request);
        std::string json = generator.exportToJSON(patterns);
        
        // JSON should contain expected fields
        return json.find("generator") != std::string::npos &&
               json.find("patterns") != std::string::npos &&
               json.find("INVERSE") != std::string::npos;
    });
    
    // Test 11: Sliding window analysis
    runner.run("Sliding Window Analysis", [&]() {
        // Create test data with varying entropy
        std::vector<uint8_t> data(1024);
        for (size_t i = 0; i < 512; ++i) data[i] = 0xAA; // Low entropy
        for (size_t i = 512; i < 1024; ++i) data[i] = static_cast<uint8_t>(i); // Higher entropy
        
        auto results = generator.analyzeWithSlidingWindow(data.data(), data.size(), 256, 256);
        
        // Should have at least 4 windows
        return results.size() >= 4;
    });
    
    // Test 12: Pattern discovery
    runner.run("Pattern Discovery", [&]() {
        // Create data with repeated pattern
        std::vector<uint8_t> data;
        for (int i = 0; i < 10; ++i) {
            data.push_back(0x48);
            data.push_back(0x89);
            data.push_back(0x5C);
        }
        
        auto discovered = generator.discoverPatterns(data.data(), data.size(), 2, 4, 3);
        
        // Should find the repeated pattern
        return discovered.size() > 0;
    });
    
    // Test 13: Frequency-based discovery
    runner.run("Frequency-Based Discovery", [&]() {
        std::vector<uint8_t> data(1000, 0xAA); // 1000 0xAA bytes
        data[500] = 0xBB; // One different byte
        
        auto discovered = generator.discoverByFrequency(data.data(), data.size(), 500);
        
        // Should find 0xAA as frequent
        bool found_aa = false;
        for (const auto& p : discovered) {
            if (!p.bytes.empty() && p.bytes[0] == 0xAA && p.frequency >= 500) {
                found_aa = true;
            }
        }
        
        return found_aa;
    });
    
    // Test 14: Entropy-based discovery
    runner.run("Entropy-Based Discovery", [&]() {
        // Create data with different entropy regions
        std::vector<uint8_t> data(512);
        for (size_t i = 0; i < 256; ++i) data[i] = 0xAA; // Low entropy
        for (size_t i = 256; i < 512; ++i) data[i] = static_cast<uint8_t>(i * 7); // Higher entropy
        
        auto discovered = generator.discoverByEntropy(data.data(), data.size(), 3.0, 8.0);
        
        // Should find high entropy regions
        return discovered.size() > 0;
    });
    
    // Test 15: BigDaddyG model export
    runner.run("BigDaddyG Model Export", [&]() {
        std::vector<uint8_t> source = {0x48, 0x89, 0x5C, 0x24, 0x08};
        
        GenerationRequest request;
        request.preserve_original = true;
        request.generate_inverses = true;
        
        auto patterns = generator.generateAllPatterns(source, request);
        
        // Export to temp file
        bool exported = generator.exportToBigDaddyGModel(patterns, "d:/__test_model.json");
        
        return exported;
    });
    
    // Test 16: Statistics tracking
    runner.run("Statistics Tracking", [&]() {
        ComprehensivePatternGenerator gen;
        
        std::vector<uint8_t> source = {0x48, 0x89, 0x5C, 0x24, 0x08};
        
        GenerationRequest request;
        request.preserve_original = true;
        request.generate_inverses = true;
        request.generate_complements = true;
        
        gen.generateAllPatterns(source, request);
        
        auto stats = gen.getStats();
        
        return stats.total_patterns_generated >= 3 &&
               stats.total_inverses >= 1 &&
               stats.total_complements >= 1;
    });
    
    // Test 17: Empty source handling
    runner.run("Empty Source Handling", [&]() {
        std::vector<uint8_t> empty_source;
        
        GenerationRequest request;
        request.preserve_original = true;
        
        auto patterns = generator.generateAllPatterns(empty_source, request);
        
        // Should return empty vector for empty source
        return patterns.empty();
    });
    
    // Test 18: Large pattern handling
    runner.run("Large Pattern Handling", [&]() {
        std::vector<uint8_t> large_source(10000);
        for (size_t i = 0; i < large_source.size(); ++i) {
            large_source[i] = static_cast<uint8_t>(i % 256);
        }
        
        GenerationRequest request;
        request.preserve_original = true;
        request.generate_inverses = true;
        
        auto patterns = generator.generateAllPatterns(large_source, request);
        
        // Should handle large patterns
        return patterns.size() >= 2;
    });
    
    // Test 19: Pattern type strings
    runner.run("Pattern Type Strings", [&]() {
        // Test that all types have valid string representations
        bool all_valid = true;
        
        // We can't directly call getTypeString, but we can verify through pattern generation
        std::vector<uint8_t> source = {0x48, 0x89, 0x5C, 0x24, 0x08};
        
        GenerationRequest request;
        request.preserve_original = true;
        request.generate_inverses = true;
        request.generate_complements = true;
        request.generate_reversed = true;
        request.generate_xor_variants = true;
        request.xor_keys = {0xAA};
        
        auto patterns = generator.generateAllPatterns(source, request);
        auto json = generator.exportToJSON(patterns);
        
        // JSON should contain type strings
        return json.find("ORIGINAL") != std::string::npos &&
               json.find("INVERSE") != std::string::npos &&
               json.find("COMPLEMENT") != std::string::npos &&
               json.find("REVERSED") != std::string::npos &&
               json.find("XOR_VARIANT") != std::string::npos;
    });
    
    // Test 20: Performance benchmark
    runner.run("Performance Benchmark", [&]() {
        ComprehensivePatternGenerator gen;
        
        // Create a larger test pattern
        std::vector<uint8_t> source(1000);
        for (size_t i = 0; i < source.size(); ++i) {
            source[i] = static_cast<uint8_t>((i * 7 + 13) % 256);
        }
        
        GenerationRequest request;
        request.preserve_original = true;
        request.generate_inverses = true;
        request.generate_complements = true;
        request.generate_reversed = true;
        request.generate_xor_variants = true;
        request.xor_keys = {0xAA, 0x55, 0xFF};
        request.generate_anti_patterns = true;
        request.anti_pattern_count = 5;
        request.validate_generated = true;
        
        auto start = std::chrono::high_resolution_clock::now();
        auto patterns = gen.generateAllPatterns(source, request);
        auto end = std::chrono::high_resolution_clock::now();
        
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        
        std::cout << "\n      Generated " << patterns.size() << " patterns in " 
                  << std::fixed << std::setprecision(2) << duration << "ms";
        
        // Should complete in reasonable time (< 1000ms for 1000 byte pattern)
        return duration < 1000.0 && patterns.size() >= 10;
    });
    
    // Print summary
    runner.printSummary();
    
    // Calculate pass rate
    size_t passed = 0;
    for (const auto& r : runner.results) {
        if (r.passed) passed++;
    }
    
    std::cout << "\n";
    if (passed == runner.results.size()) {
        std::cout << "✓ ALL TESTS PASSED! Pattern Generator is fully operational.\n";
        return 0;
    } else {
        std::cout << "✗ Some tests failed. Review output above.\n";
        return 1;
    }
}
