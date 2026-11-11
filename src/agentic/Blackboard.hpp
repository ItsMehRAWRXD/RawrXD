// ============================================================================
// Blackboard.hpp - Shared blackboard for asynchronous agent cooperation
// ============================================================================
#pragma once

#include "AgentTypes.hpp"
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <functional>
#include <iostream>
#include <algorithm>

namespace RawrXD::Agentic {

// ============================================================================
// Blackboard - agents subscribe to updates instead of calling each other
// ============================================================================

class Blackboard {
public:
    Blackboard() = default;
    ~Blackboard() = default;

    // Post an entry to the blackboard
    void postEntry(const BlackboardEntry& entry) {
        std::unique_lock lock(mutex_);
        entries_[entry.region_address] = entry;
        entry_count_++;
        lock.unlock();
        notifySubscribers(entry);
    }

    // Update an existing entry
    void updateEntry(uint64_t address, const std::string& field, const std::string& value) {
        std::unique_lock lock(mutex_);
        auto it = entries_.find(address);
        if (it != entries_.end()) {
            if (field == "entropy") it->second.entropy = std::stod(value);
            else if (field == "confidence") it->second.confidence = std::stod(value);
            else if (field == "status") it->second.status = value;
            else if (field == "updated_by") it->second.updated_by_agent = value;
            else if (field == "decompiler_pending") it->second.decompiler_pending = (value == "true");
            else if (field == "decompiler_complete") it->second.decompiler_complete = (value == "true");
            else if (field == "region_name") it->second.region_name = value;
            else if (field == "tag") it->second.tags.push_back(value);
            it->second.last_updated = std::chrono::steady_clock::now();
            
            BlackboardEntry updated = it->second;
            lock.unlock();
            notifySubscribers(updated);
        }
    }

    // Add a pattern candidate to an entry
    void addPatternCandidate(uint64_t address, const std::string& pattern_id) {
        std::unique_lock lock(mutex_);
        auto it = entries_.find(address);
        if (it != entries_.end()) {
            it->second.pattern_candidates.push_back(pattern_id);
            it->second.last_updated = std::chrono::steady_clock::now();
        }
    }

    // Get an entry by address
    std::optional<BlackboardEntry> getEntry(uint64_t address) const {
        std::shared_lock lock(mutex_);
        auto it = entries_.find(address);
        if (it != entries_.end()) return it->second;
        return std::nullopt;
    }

    // Get all entries
    std::vector<BlackboardEntry> getAllEntries() const {
        std::shared_lock lock(mutex_);
        std::vector<BlackboardEntry> result;
        for (const auto& [_, entry] : entries_) {
            result.push_back(entry);
        }
        return result;
    }

    // Find entries matching a predicate
    std::vector<BlackboardEntry> findEntries(std::function<bool(const BlackboardEntry&)> predicate) const {
        std::shared_lock lock(mutex_);
        std::vector<BlackboardEntry> result;
        for (const auto& [_, entry] : entries_) {
            if (predicate(entry)) result.push_back(entry);
        }
        return result;
    }

    // Find entries by status
    std::vector<BlackboardEntry> findByStatus(const std::string& status) const {
        return findEntries([&](const BlackboardEntry& e) { return e.status == status; });
    }

    // Find entries needing decompiler
    std::vector<BlackboardEntry> findPendingDecompiler() const {
        return findEntries([](const BlackboardEntry& e) { 
            return e.decompiler_pending && !e.decompiler_complete; 
        });
    }

    // Find high-entropy regions
    std::vector<BlackboardEntry> findHighEntropy(double threshold = 6.0) const {
        return findEntries([threshold](const BlackboardEntry& e) { 
            return e.entropy > threshold; 
        });
    }

    // Find low-confidence regions needing validation
    std::vector<BlackboardEntry> findNeedingValidation(double max_confidence = 0.5) const {
        return findEntries([max_confidence](const BlackboardEntry& e) { 
            return e.confidence < max_confidence; 
        });
    }

    // Subscribe to updates
    using SubscriberCallback = std::function<void(const BlackboardEntry&)>;
    uint64_t subscribe(SubscriberCallback callback) {
        std::unique_lock lock(mutex_);
        uint64_t id = next_subscriber_id_++;
        subscribers_[id] = std::move(callback);
        return id;
    }

    // Unsubscribe
    void unsubscribe(uint64_t subscriber_id) {
        std::unique_lock lock(mutex_);
        subscribers_.erase(subscriber_id);
    }

    // Clear all entries
    void clear() {
        std::unique_lock lock(mutex_);
        entries_.clear();
        entry_count_ = 0;
    }

    // Get statistics
    size_t entryCount() const { 
        std::shared_lock lock(mutex_);
        return entries_.size(); 
    }
    
    size_t subscriberCount() const { 
        std::shared_lock lock(mutex_);
        return subscribers_.size(); 
    }

private:
    void notifySubscribers(const BlackboardEntry& entry) {
        std::shared_lock lock(mutex_);
        for (const auto& [id, callback] : subscribers_) {
            try {
                callback(entry);
            } catch (const std::exception& e) {
                std::cerr << "[Blackboard] Subscriber " << id << " error: " << e.what() << std::endl;
            }
        }
    }

    mutable std::shared_mutex mutex_;
    std::unordered_map<uint64_t, BlackboardEntry> entries_;
    std::unordered_map<uint64_t, SubscriberCallback> subscribers_;
    uint64_t next_subscriber_id_ = 1;
    std::atomic<size_t> entry_count_{0};
};

} // namespace RawrXD::Agentic
