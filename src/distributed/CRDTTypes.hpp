/**
 * CRDTTypes.hpp
 *
 * Phase D.3 Batch 2/5: State Synchronization Protocol
 *
 * Conflict-free Replicated Data Types (CRDTs) for distributed state.
 * Enables automatic conflict resolution without coordination.
 */

#pragma once

#include "NodeDiscovery.hpp"
#include <set>
#include <map>
#include <variant>
#include <optional>

namespace Distributed {

// ============================================================================
// Version Vector
// ============================================================================

/**
 * Version vector for tracking causality across nodes.
 * Used to determine happens-before relationships.
 */
class VersionVector {
public:
    VersionVector() = default;
    explicit VersionVector(const std::string& nodeId);
    
    // Increment version for a node
    void Increment(const std::string& nodeId);
    
    // Merge with another version vector
    void Merge(const VersionVector& other);
    
    // Comparison operators
    bool operator<=(const VersionVector& other) const;
    bool operator>=(const VersionVector& other) const;
    bool operator==(const VersionVector& other) const;
    bool operator!=(const VersionVector& other) const;
    
    // Causality checks
    bool HappensBefore(const VersionVector& other) const;
    bool HappensAfter(const VersionVector& other) const;
    bool IsConcurrentWith(const VersionVector& other) const;
    
    // Serialization
    std::string ToJson() const;
    static VersionVector FromJson(const std::string& json);
    
    // Access
    uint64_t GetVersion(const std::string& nodeId) const;
    std::map<std::string, uint64_t> GetAllVersions() const;
    bool IsEmpty() const;
    
private:
    std::map<std::string, uint64_t> versions_;
};

// ============================================================================
// G-Set (Grow-Only Set)
// ============================================================================

/**
 * Grow-only set CRDT.
 * Elements can only be added, never removed.
 */
template<typename T>
class GSet {
public:
    // Add element
    void Add(const T& element);
    void Add(const T& element, const VersionVector& version);
    
    // Query
    bool Contains(const T& element) const;
    std::set<T> GetElements() const;
    size_t Size() const;
    bool IsEmpty() const;
    
    // Merge
    void Merge(const GSet<T>& other);
    
    // Serialization
    std::string ToJson() const;
    static GSet<T> FromJson(const std::string& json);
    
private:
    std::set<T> elements_;
    std::map<T, VersionVector> versions_;
};

// ============================================================================
// OR-Set (Observed-Removed Set)
// ============================================================================

/**
 * Observed-removed set CRDT.
 * Supports both add and remove operations.
 */
template<typename T>
class ORSet {
public:
    struct Element {
        T value;
        std::string tag;  // Unique tag for each add
        VersionVector version;
        bool removed = false;
    };
    
    // Add element
    void Add(const T& element, const std::string& nodeId);
    void Add(const T& element, const std::string& tag, const VersionVector& version);
    
    // Remove element
    void Remove(const T& element);
    void Remove(const T& element, const VersionVector& version);
    
    // Query
    bool Contains(const T& element) const;
    std::set<T> GetElements() const;
    std::set<T> GetRemovedElements() const;
    size_t Size() const;
    bool IsEmpty() const;
    
    // Merge
    void Merge(const ORSet<T>& other);
    
    // Serialization
    std::string ToJson() const;
    static ORSet<T> FromJson(const std::string& json);
    
private:
    std::map<T, std::vector<Element>> elements_;  // Key -> list of adds
    
    std::string GenerateTag(const std::string& nodeId);
};

// ============================================================================
// LWW-Register (Last-Write-Wins Register)
// ============================================================================

/**
 * Last-write-wins register CRDT.
 * Stores a single value with timestamp.
 */
template<typename T>
class LWWRegister {
public:
    struct Value {
        T data;
        VersionVector version;
        uint64_t timestamp;
    };
    
    // Set value
    void Set(const T& value, const VersionVector& version);
    void Set(const T& value, const VersionVector& version, uint64_t timestamp);
    
    // Get value
    std::optional<T> Get() const;
    std::optional<Value> GetWithMetadata() const;
    
    // Merge
    void Merge(const LWWRegister<T>& other);
    
    // Serialization
    std::string ToJson() const;
    static LWWRegister<T> FromJson(const std::string& json);
    
private:
    std::optional<Value> value_;
};

// ============================================================================
// PN-Counter (Positive-Negative Counter)
// ============================================================================

/**
 * Positive-negative counter CRDT.
 * Supports increment and decrement operations.
 */
class PNCounter {
public:
    // Increment
    void Increment(const std::string& nodeId, uint64_t delta = 1);
    
    // Decrement
    void Decrement(const std::string& nodeId, uint64_t delta = 1);
    
    // Get value
    int64_t GetValue() const;
    
    // Merge
    void Merge(const PNCounter& other);
    
    // Serialization
    std::string ToJson() const;
    static PNCounter FromJson(const std::string& json);
    
private:
    std::map<std::string, uint64_t> positive_;  // Node -> increments
    std::map<std::string, uint64_t> negative_;  // Node -> decrements
};

// ============================================================================
// G-Counter (Grow-Only Counter)
// ============================================================================

/**
 * Grow-only counter CRDT.
 * Only supports increment operations.
 */
class GCounter {
public:
    // Increment
    void Increment(const std::string& nodeId, uint64_t delta = 1);
    
    // Get value
    uint64_t GetValue() const;
    
    // Merge
    void Merge(const GCounter& other);
    
    // Serialization
    std::string ToJson() const;
    static GCounter FromJson(const std::string& json);
    
private:
    std::map<std::string, uint64_t> counters_;  // Node -> count
};

// ============================================================================
// CRDT Map
// ============================================================================

/**
 * Map with CRDT values.
 * Supports nested CRDT types.
 */
template<typename K, typename V>
class CRDTMap {
public:
    // Set value
    void Set(const K& key, const V& value, const VersionVector& version);
    
    // Get value
    std::optional<V> Get(const K& key) const;
    
    // Remove
    void Remove(const K& key, const VersionVector& version);
    
    // Query
    bool Contains(const K& key) const;
    std::map<K, V> GetAll() const;
    size_t Size() const;
    bool IsEmpty() const;
    
    // Merge
    void Merge(const CRDTMap<K, V>& other);
    
    // Serialization
    std::string ToJson() const;
    static CRDTMap<K, V> FromJson(const std::string& json);
    
private:
    struct Entry {
        V value;
        VersionVector version;
        bool removed = false;
    };
    
    std::map<K, Entry> entries_;
};

// ============================================================================
// Delta Encoding
// ============================================================================

/**
 * Delta encoding for efficient state synchronization.
 * Only transmits changes since last sync.
 */
struct Delta {
    VersionVector fromVersion;
    VersionVector toVersion;
    std::vector<uint8_t> changes;
    uint64_t timestamp;
    
    std::string ToJson() const;
    static Delta FromJson(const std::string& json);
};

/**
 * Delta calculator for CRDTs.
 */
class DeltaCalculator {
public:
    // Calculate delta between two version vectors
    static Delta CalculateDelta(
        const VersionVector& from,
        const VersionVector& to,
        const std::vector<uint8_t>& changes
    );
    
    // Check if delta is applicable
    static bool IsApplicable(const Delta& delta, const VersionVector& current);
    
    // Merge deltas
    static Delta MergeDeltas(const std::vector<Delta>& deltas);
};

// ============================================================================
// CRDT Manager
// ============================================================================

/**
 * Manager for multiple CRDT instances.
 */
class CRDTManager {
public:
    CRDTManager();
    ~CRDTManager();
    
    // Registration
    void RegisterCounter(const std::string& name);
    void RegisterSet(const std::string& name);
    void RegisterRegister(const std::string& name);
    void RegisterMap(const std::string& name);
    
    // Access
    PNCounter* GetCounter(const std::string& name);
    ORSet<std::string>* GetSet(const std::string& name);
    LWWRegister<std::string>* GetRegister(const std::string& name);
    CRDTMap<std::string, std::string>* GetMap(const std::string& name);
    
    // Synchronization
    Delta GenerateDelta(const std::string& name, const VersionVector& from);
    bool ApplyDelta(const std::string& name, const Delta& delta);
    VersionVector GetCurrentVersion(const std::string& name);
    
    // Bulk operations
    std::vector<Delta> GenerateAllDeltas(const VersionVector& from);
    bool ApplyAllDeltas(const std::vector<Delta>& deltas);
    
    // Serialization
    std::string ToJson() const;
    static CRDTManager FromJson(const std::string& json);
    
private:
    std::map<std::string, PNCounter> counters_;
    std::map<std::string, ORSet<std::string>> sets_;
    std::map<std::string, LWWRegister<std::string>> registers_;
    std::map<std::string, CRDTMap<std::string, std::string>> maps_;
    
    mutable std::mutex mutex_;
};

} // namespace Distributed
