//============================================================================
// nevm_kv_integrity.hpp
// RawrXD N-EVM - KV Cache Integrity Checking
// Page checksums for silent corruption detection
//============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
namespace NEVM {

//============================================================================
// KV Page Integrity Structure
//============================================================================

struct KVPageIntegrity {
    uint64_t page_id;
    uint64_t generation;      // Incremented on each write
    uint64_t checksum;      // xxHash or similar
    uint32_t sequence_length;
    uint32_t layer_id;
    uint64_t timestamp;       // For debugging
    
    bool IsValid() const {
        return page_id != 0xFFFFFFFFFFFFFFFFULL &&
               checksum != 0;
    }
};

//============================================================================
// Checksum Calculator
//============================================================================

class ChecksumCalculator {
public:
    // Simple xxHash-like checksum (production would use real xxHash)
    static uint64_t Calculate(const void* data, size_t size, uint64_t seed = 0) {
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        uint64_t hash = seed;
        
        // FNV-1a inspired hash
        for (size_t i = 0; i < size; ++i) {
            hash ^= bytes[i];
            hash *= 1099511628211ULL;  // FNV prime
        }
        
        return hash;
    }
    
    // Calculate checksum for KV page
    static uint64_t CalculateKVPage(const void* k_data, const void* v_data,
                                     size_t k_size, size_t v_size) {
        uint64_t k_hash = Calculate(k_data, k_size, 0);
        uint64_t v_hash = Calculate(v_data, v_size, k_hash);
        return v_hash;
    }
};

//============================================================================
// KV Integrity Tracker
//============================================================================

class KVIntegrityTracker {
public:
    struct IntegrityViolation {
        uint64_t page_id;
        uint64_t expected_checksum;
        uint64_t actual_checksum;
        std::string operation;  // "migrate", "evict", "reload"
        uint64_t timestamp;
    };
    
    std::vector<IntegrityViolation> violations;
    
    // Register a page before any operation
    void RegisterPage(uint64_t page_id, const void* k_data, const void* v_data,
                     size_t k_size, size_t v_size, uint32_t layer_id) {
        KVPageIntegrity integrity;
        integrity.page_id = page_id;
        integrity.generation = GetNextGeneration(page_id);
        integrity.checksum = ChecksumCalculator::CalculateKVPage(k_data, v_data, k_size, v_size);
        integrity.sequence_length = 0;  // Set by caller
        integrity.layer_id = layer_id;
        integrity.timestamp = GetTimestamp();
        
        page_integrity_[page_id] = integrity;
    }
    
    // Verify page integrity after operation
    bool VerifyPage(uint64_t page_id, const void* k_data, const void* v_data,
                   size_t k_size, size_t v_size, const std::string& operation) {
        auto it = page_integrity_.find(page_id);
        if (it == page_integrity_.end()) {
            // Page not registered - this is also a violation
            IntegrityViolation v;
            v.page_id = page_id;
            v.expected_checksum = 0;
            v.actual_checksum = 0;
            v.operation = operation + " (unregistered)";
            v.timestamp = GetTimestamp();
            violations.push_back(v);
            return false;
        }
        
        uint64_t expected = it->second.checksum;
        uint64_t actual = ChecksumCalculator::CalculateKVPage(k_data, v_data, k_size, v_size);
        
        if (expected != actual) {
            IntegrityViolation v;
            v.page_id = page_id;
            v.expected_checksum = expected;
            v.actual_checksum = actual;
            v.operation = operation;
            v.timestamp = GetTimestamp();
            violations.push_back(v);
            return false;
        }
        
        return true;
    }
    
    // Update checksum after legitimate modification
    void UpdateChecksum(uint64_t page_id, const void* k_data, const void* v_data,
                       size_t k_size, size_t v_size) {
        auto it = page_integrity_.find(page_id);
        if (it != page_integrity_.end()) {
            it->second.generation++;
            it->second.checksum = ChecksumCalculator::CalculateKVPage(k_data, v_data, k_size, v_size);
            it->second.timestamp = GetTimestamp();
        }
    }
    
    // Get integrity info for a page
    KVPageIntegrity GetIntegrity(uint64_t page_id) const {
        auto it = page_integrity_.find(page_id);
        if (it != page_integrity_.end()) {
            return it->second;
        }
        return {};
    }
    
    // Clear all tracking
    void Clear() {
        page_integrity_.clear();
        violations.clear();
    }
    
    // Check if any violations occurred
    bool HasViolations() const {
        return !violations.empty();
    }
    
    // Print violation report
    void PrintViolations() const {
        if (violations.empty()) {
            std::cout << "No KV integrity violations detected\n";
            return;
        }
        
        std::cout << "\n=== KV INTEGRITY VIOLATIONS ===\n";
        std::cout << "Total: " << violations.size() << "\n\n";
        
        for (const auto& v : violations) {
            std::cout << "Page " << v.page_id << " [" << v.operation << "]\n";
            std::cout << "  Expected: 0x" << std::hex << v.expected_checksum << std::dec << "\n";
            std::cout << "  Actual:   0x" << std::hex << v.actual_checksum << std::dec << "\n";
            std::cout << "  Time:     " << v.timestamp << "\n\n";
        }
    }
    
    // Get statistics
    struct IntegrityStats {
        size_t pages_tracked;
        size_t violations_count;
        size_t migrations_verified;
        size_t evictions_verified;
    };
    
    IntegrityStats GetStats() const {
        IntegrityStats stats;
        stats.pages_tracked = page_integrity_.size();
        stats.violations_count = violations.size();
        stats.migrations_verified = 0;  // Would track separately
        stats.evictions_verified = 0;
        return stats;
    }

private:
    std::unordered_map<uint64_t, KVPageIntegrity> page_integrity_;
    uint64_t next_generation_ = 1;
    
    uint64_t GetNextGeneration(uint64_t page_id) {
        (void)page_id;  // Could use page-specific generation
        return next_generation_++;
    }
    
    uint64_t GetTimestamp() {
        // Simple counter for now
        static uint64_t counter = 0;
        return counter++;
    }
};

//============================================================================
// Migration Guard
//============================================================================

class KVMigrationGuard {
public:
    KVMigrationGuard(KVIntegrityTracker& tracker, uint64_t page_id,
                    const void* k_data, const void* v_data,
                    size_t k_size, size_t v_size)
        : tracker_(tracker), page_id_(page_id), k_data_(k_data), v_data_(v_data),
          k_size_(k_size), v_size_(v_size), verified_(false) {
        // Verify before migration
        verified_ = tracker_.VerifyPage(page_id_, k_data_, v_data_, k_size_, v_size_, "migrate");
    }
    
    ~KVMigrationGuard() {
        // Verify after migration (if constructor succeeded)
        if (verified_) {
            tracker_.VerifyPage(page_id_, k_data_, v_data_, k_size_, v_size_, "migrate_complete");
        }
    }
    
    bool IsValid() const { return verified_; }

private:
    KVIntegrityTracker& tracker_;
    uint64_t page_id_;
    const void* k_data_;
    const void* v_data_;
    size_t k_size_;
    size_t v_size_;
    bool verified_;
};

} // namespace NEVM
} // namespace RawrXD
