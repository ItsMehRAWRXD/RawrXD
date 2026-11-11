//============================================================================
// nevm_kv_integrity.cpp
// RawrXD N-EVM - KV Cache Integrity Implementation
//============================================================================

#include "nevm_kv_integrity.hpp"
#include <iostream>
#include <chrono>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Checksum Calculator
//============================================================================

uint64_t ChecksumCalculator::Calculate(const void* data, size_t size, uint64_t seed) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint64_t hash = seed;
    
    // FNV-1a inspired hash
    for (size_t i = 0; i < size; ++i) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;  // FNV prime
    }
    
    return hash;
}

uint64_t ChecksumCalculator::CalculateKVPage(const void* k_data, const void* v_data,
                                            size_t k_size, size_t v_size) {
    uint64_t k_hash = Calculate(k_data, k_size, 0);
    uint64_t v_hash = Calculate(v_data, v_size, k_hash);
    return v_hash;
}

//============================================================================
// KV Integrity Tracker
//============================================================================

void KVIntegrityTracker::RegisterPage(uint64_t page_id, const void* k_data, const void* v_data,
                                      size_t k_size, size_t v_size, uint32_t layer_id) {
    KVPageIntegrity integrity;
    integrity.page_id = page_id;
    integrity.generation = GetNextGeneration(page_id);
    integrity.checksum = ChecksumCalculator::CalculateKVPage(k_data, v_data, k_size, v_size);
    integrity.sequence_length = 0;
    integrity.layer_id = layer_id;
    integrity.timestamp = GetTimestamp();
    
    page_integrity_[page_id] = integrity;
}

bool KVIntegrityTracker::VerifyPage(uint64_t page_id, const void* k_data, const void* v_data,
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

void KVIntegrityTracker::UpdateChecksum(uint64_t page_id, const void* k_data, const void* v_data,
                                        size_t k_size, size_t v_size) {
    auto it = page_integrity_.find(page_id);
    if (it != page_integrity_.end()) {
        it->second.generation++;
        it->second.checksum = ChecksumCalculator::CalculateKVPage(k_data, v_data, k_size, v_size);
        it->second.timestamp = GetTimestamp();
    }
}

KVPageIntegrity KVIntegrityTracker::GetIntegrity(uint64_t page_id) const {
    auto it = page_integrity_.find(page_id);
    if (it != page_integrity_.end()) {
        return it->second;
    }
    return {};
}

void KVIntegrityTracker::Clear() {
    page_integrity_.clear();
    violations.clear();
}

bool KVIntegrityTracker::HasViolations() const {
    return !violations.empty();
}

void KVIntegrityTracker::PrintViolations() const {
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

KVIntegrityTracker::IntegrityStats KVIntegrityTracker::GetStats() const {
    IntegrityStats stats;
    stats.pages_tracked = page_integrity_.size();
    stats.violations_count = violations.size();
    stats.migrations_verified = 0;
    stats.evictions_verified = 0;
    return stats;
}

uint64_t KVIntegrityTracker::GetNextGeneration(uint64_t page_id) {
    (void)page_id;
    return next_generation_++;
}

uint64_t KVIntegrityTracker::GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

} // namespace NEVM
} // namespace RawrXD
