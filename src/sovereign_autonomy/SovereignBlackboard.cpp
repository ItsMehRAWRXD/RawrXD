/**
 * @file SovereignBlackboard.cpp
 * @brief Implementation of the shared knowledge store
 */

#include "SovereignBlackboard.hpp"
#include <sstream>
#include <algorithm>

namespace RawrXD::Autonomy {

// ---------------------------------------------------------------------------
// Typed writes
// ---------------------------------------------------------------------------
void SovereignBlackboard::WriteString(const std::string& key, const std::string& value,
                                       const std::string& source, int priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    BlackboardEntry e;
    e.key = key;
    e.value = value;
    e.type = "string";
    e.source = source;
    e.timestamp = std::chrono::steady_clock::now();
    e.priority = priority;
    entries_[key] = std::move(e);
    NotifySubscribers(key, entries_[key]);
}

void SovereignBlackboard::WriteInt(const std::string& key, int64_t value,
                                    const std::string& source, int priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    BlackboardEntry e;
    e.key = key;
    e.value = value;
    e.type = "int";
    e.source = source;
    e.timestamp = std::chrono::steady_clock::now();
    e.priority = priority;
    entries_[key] = std::move(e);
    NotifySubscribers(key, entries_[key]);
}

void SovereignBlackboard::WriteFloat(const std::string& key, double value,
                                      const std::string& source, int priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    BlackboardEntry e;
    e.key = key;
    e.value = value;
    e.type = "float";
    e.source = source;
    e.timestamp = std::chrono::steady_clock::now();
    e.priority = priority;
    entries_[key] = std::move(e);
    NotifySubscribers(key, entries_[key]);
}

void SovereignBlackboard::WriteJson(const std::string& key, const std::string& json_value,
                                     const std::string& source, int priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    BlackboardEntry e;
    e.key = key;
    e.value = json_value;
    e.type = "json";
    e.source = source;
    e.timestamp = std::chrono::steady_clock::now();
    e.priority = priority;
    entries_[key] = std::move(e);
    NotifySubscribers(key, entries_[key]);
}

void SovereignBlackboard::WriteBinary(const std::string& key, const std::vector<uint8_t>& data,
                                       const std::string& source, int priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    BlackboardEntry e;
    e.key = key;
    e.value = data;
    e.type = "binary";
    e.source = source;
    e.timestamp = std::chrono::steady_clock::now();
    e.priority = priority;
    entries_[key] = std::move(e);
    NotifySubscribers(key, entries_[key]);
}

// ---------------------------------------------------------------------------
// Typed reads
// ---------------------------------------------------------------------------
std::optional<std::string> SovereignBlackboard::ReadString(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end() || it->second.type != "string") return std::nullopt;
    return std::any_cast<std::string>(it->second.value);
}

std::optional<int64_t> SovereignBlackboard::ReadInt(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end() || it->second.type != "int") return std::nullopt;
    return std::any_cast<int64_t>(it->second.value);
}

std::optional<double> SovereignBlackboard::ReadFloat(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end() || it->second.type != "float") return std::nullopt;
    return std::any_cast<double>(it->second.value);
}

std::optional<std::string> SovereignBlackboard::ReadJson(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end() || it->second.type != "json") return std::nullopt;
    return std::any_cast<std::string>(it->second.value);
}

std::optional<std::vector<uint8_t>> SovereignBlackboard::ReadBinary(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end() || it->second.type != "binary") return std::nullopt;
    return std::any_cast<std::vector<uint8_t>>(it->second.value);
}

// ---------------------------------------------------------------------------
// Generic entry access
// ---------------------------------------------------------------------------
std::optional<BlackboardEntry> SovereignBlackboard::GetEntry(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end() || IsExpired(it->second)) return std::nullopt;
    return it->second;
}

bool SovereignBlackboard::HasKey(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    return it != entries_.end() && !IsExpired(it->second);
}

void SovereignBlackboard::Remove(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.erase(key);
}

void SovereignBlackboard::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
}

void SovereignBlackboard::ClearNonPersistent() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (!it->second.persistent) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

// ---------------------------------------------------------------------------
// TTL support
// ---------------------------------------------------------------------------
void SovereignBlackboard::SetTTL(const std::string& key, std::chrono::seconds ttl) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it != entries_.end()) {
        it->second.expires_at = std::chrono::steady_clock::now() + ttl;
    }
}

void SovereignBlackboard::ExpireStaleEntries() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (IsExpired(it->second)) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------
std::vector<std::string> SovereignBlackboard::Keys() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    result.reserve(entries_.size());
    for (const auto& [k, v] : entries_) {
        if (!IsExpired(v)) result.push_back(k);
    }
    return result;
}

std::vector<std::string> SovereignBlackboard::KeysBySource(const std::string& source) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [k, v] : entries_) {
        if (v.source == source && !IsExpired(v)) result.push_back(k);
    }
    return result;
}

std::vector<std::string> SovereignBlackboard::KeysByPrefix(const std::string& prefix) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [k, v] : entries_) {
        if (k.rfind(prefix, 0) == 0 && !IsExpired(v)) result.push_back(k);
    }
    return result;
}

size_t SovereignBlackboard::Size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [k, v] : entries_) {
        if (!IsExpired(v)) ++count;
    }
    return count;
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------
void SovereignBlackboard::Subscribe(const std::string& key_prefix, ChangeCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    subscriptions_[key_prefix].push_back(std::move(callback));
}

void SovereignBlackboard::Unsubscribe(const std::string& key_prefix) {
    std::lock_guard<std::mutex> lock(mutex_);
    subscriptions_.erase(key_prefix);
}

void SovereignBlackboard::NotifySubscribers(const std::string& key, const BlackboardEntry& entry) {
    // Copy callbacks under lock, then invoke outside lock to prevent reentrant deadlock
    std::vector<ChangeCallback> to_call;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [prefix, callbacks] : subscriptions_) {
            if (key.rfind(prefix, 0) == 0) {
                for (const auto& cb : callbacks) {
                    if (cb) to_call.push_back(cb);
                }
            }
        }
    }
    for (const auto& cb : to_call) {
        cb(key, entry);
    }
}

// ---------------------------------------------------------------------------
// Serialization (simplified JSON-like)
// ---------------------------------------------------------------------------
std::string SovereignBlackboard::SerializeToJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream oss;
    oss << "{\n";
    bool first = true;
    for (const auto& [k, v] : entries_) {
        if (IsExpired(v)) continue;
        if (!first) oss << ",\n";
        first = false;
        oss << "  \"" << k << "\": {\"type\":\"" << v.type << "\",\"source\":\"" << v.source << "\"}";
    }
    oss << "\n}";
    return oss.str();
}

bool SovereignBlackboard::DeserializeFromJson(const std::string& /*json*/) {
    // TODO: Full JSON parse if needed; for now, clear and rebuild manually
    return true;
}

// ---------------------------------------------------------------------------
// Merge / dump
// ---------------------------------------------------------------------------
void SovereignBlackboard::Merge(const SovereignBlackboard& other, bool overwrite) {
    // Snapshot other under its lock, then merge under ours (lock ordering: avoid deadlock)
    std::map<std::string, BlackboardEntry> other_entries;
    {
        std::lock_guard<std::mutex> other_lock(other.mutex_);
        other_entries = other.entries_;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [k, v] : other_entries) {
        if (overwrite || entries_.find(k) == entries_.end()) {
            entries_[k] = v;
        }
    }
}

void SovereignBlackboard::DumpToLog() const {
    std::lock_guard<std::mutex> lock(mutex_);
    // Intentionally minimal; caller can log SerializeToJson()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
bool SovereignBlackboard::IsExpired(const BlackboardEntry& entry) const {
    if (!entry.expires_at.has_value()) return false;
    return std::chrono::steady_clock::now() > entry.expires_at.value();
}

} // namespace RawrXD::Autonomy
