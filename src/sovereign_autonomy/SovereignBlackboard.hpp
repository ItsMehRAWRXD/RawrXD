/**
 * @file SovereignBlackboard.hpp
 * @brief Shared knowledge store for the sovereign agent swarm
 *
 * Thread-safe blackboard supporting typed entries, TTL expiration,
 * and subscription-based change notifications.
 */

#pragma once

#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <chrono>
#include <memory>
#include <functional>
#include <any>
#include <optional>

namespace RawrXD::Autonomy {

struct BlackboardEntry {
    std::string key;
    std::any value;
    std::string type;           // "string", "int", "float", "json", "binary"
    std::string source;         // Agent ID or "system"
    std::chrono::steady_clock::time_point timestamp;
    std::optional<std::chrono::steady_clock::time_point> expires_at;
    int priority = 0;           // Higher = more important
    bool persistent = false;    // Survives mission end?
};

class SovereignBlackboard {
public:
    using ChangeCallback = std::function<void(const std::string& key, const BlackboardEntry& entry)>;

    SovereignBlackboard() = default;
    ~SovereignBlackboard() = default;

    // Typed writes
    void WriteString(const std::string& key, const std::string& value,
                     const std::string& source = "system", int priority = 0);
    void WriteInt(const std::string& key, int64_t value,
                  const std::string& source = "system", int priority = 0);
    void WriteFloat(const std::string& key, double value,
                    const std::string& source = "system", int priority = 0);
    void WriteJson(const std::string& key, const std::string& json_value,
                   const std::string& source = "system", int priority = 0);
    void WriteBinary(const std::string& key, const std::vector<uint8_t>& data,
                     const std::string& source = "system", int priority = 0);

    // Typed reads
    std::optional<std::string> ReadString(const std::string& key) const;
    std::optional<int64_t> ReadInt(const std::string& key) const;
    std::optional<double> ReadFloat(const std::string& key) const;
    std::optional<std::string> ReadJson(const std::string& key) const;
    std::optional<std::vector<uint8_t>> ReadBinary(const std::string& key) const;

    // Generic entry access
    std::optional<BlackboardEntry> GetEntry(const std::string& key) const;
    bool HasKey(const std::string& key) const;
    void Remove(const std::string& key);
    void Clear();
    void ClearNonPersistent();

    // TTL support
    void SetTTL(const std::string& key, std::chrono::seconds ttl);
    void ExpireStaleEntries();

    // Query
    std::vector<std::string> Keys() const;
    std::vector<std::string> KeysBySource(const std::string& source) const;
    std::vector<std::string> KeysByPrefix(const std::string& prefix) const;
    size_t Size() const;

    // Subscriptions
    void Subscribe(const std::string& key_prefix, ChangeCallback callback);
    void Unsubscribe(const std::string& key_prefix);

    // Snapshot / restore
    std::string SerializeToJson() const;
    bool DeserializeFromJson(const std::string& json);

    // High-level helpers
    void Merge(const SovereignBlackboard& other, bool overwrite = false);
    void DumpToLog() const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, BlackboardEntry> entries_;
    std::map<std::string, std::vector<ChangeCallback>> subscriptions_;

    void NotifySubscribers(const std::string& key, const BlackboardEntry& entry);
    bool IsExpired(const BlackboardEntry& entry) const;
};

} // namespace RawrXD::Autonomy
