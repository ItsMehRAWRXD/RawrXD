/**
 * StateSync.cpp
 *
 * Phase D.3 Batch 2/5: State Synchronization Protocol
 *
 * Implementation of distributed state synchronization with CRDT-based
 * conflict resolution and delta encoding.
 */

#include "StateSync.hpp"
#include "../core/Logger.hpp"
#include "../core/ErrorCodes.hpp"
#include <chrono>
#include <algorithm>
#include <zlib.h>

namespace Distributed {

// ============================================================================
// State Type Helpers
// ============================================================================

std::string StateTypeToString(StateType type) {
    switch (type) {
        case StateType::AGENT_STATE:   return "agent";
        case StateType::MODEL_STATE:   return "model";
        case StateType::CONFIG_STATE:  return "config";
        case StateType::METRICS_STATE: return "metrics";
        case StateType::SESSION_STATE: return "session";
        case StateType::CUSTOM_STATE:  return "custom";
        default: return "unknown";
    }
}

StateType StateTypeFromString(const std::string& str) {
    if (str == "agent")   return StateType::AGENT_STATE;
    if (str == "model")   return StateType::MODEL_STATE;
    if (str == "config")  return StateType::CONFIG_STATE;
    if (str == "metrics") return StateType::METRICS_STATE;
    if (str == "session") return StateType::SESSION_STATE;
    return StateType::CUSTOM_STATE;
}

// ============================================================================
// StateKey Implementation
// ============================================================================

std::string StateKey::ToString() const {
    return StateTypeToString(type) + ":" + scope + ":" + name;
}

StateKey StateKey::FromString(const std::string& str) {
    StateKey key;
    size_t firstColon = str.find(':');
    size_t secondColon = str.find(':', firstColon + 1);
    
    if (firstColon != std::string::npos && secondColon != std::string::npos) {
        key.type = StateTypeFromString(str.substr(0, firstColon));
        key.scope = str.substr(firstColon + 1, secondColon - firstColon - 1);
        key.name = str.substr(secondColon + 1);
    }
    
    return key;
}

bool StateKey::operator==(const StateKey& other) const {
    return type == other.type && scope == other.scope && name == other.name;
}

bool StateKey::operator<(const StateKey& other) const {
    if (type != other.type) return type < other.type;
    if (scope != other.scope) return scope < other.scope;
    return name < other.name;
}

// ============================================================================
// StateEntry Implementation
// ============================================================================

uint32_t StateEntry::CalculateChecksum() const {
    uint32_t crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, reinterpret_cast<const Bytef*>(data.data()), data.size());
    crc = crc32(crc, reinterpret_cast<const Bytef*>(&timestamp), sizeof(timestamp));
    return crc;
}

bool StateEntry::VerifyChecksum() const {
    return checksum == CalculateChecksum();
}

std::vector<uint8_t> StateEntry::Serialize() const {
    std::vector<uint8_t> result;
    
    // Key
    std::string keyStr = key.ToString();
    uint32_t keyLen = keyStr.length();
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&keyLen),
                  reinterpret_cast<const uint8_t*>(&keyLen) + sizeof(keyLen));
    result.insert(result.end(), keyStr.begin(), keyStr.end());
    
    // Data
    uint32_t dataLen = data.size();
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&dataLen),
                  reinterpret_cast<const uint8_t*>(&dataLen) + sizeof(dataLen));
    result.insert(result.end(), data.begin(), data.end());
    
    // Version
    std::string verJson = version.ToJson();
    uint32_t verLen = verJson.length();
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&verLen),
                  reinterpret_cast<const uint8_t*>(&verLen) + sizeof(verLen));
    result.insert(result.end(), verJson.begin(), verJson.end());
    
    // Timestamp
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&timestamp),
                  reinterpret_cast<const uint8_t*>(&timestamp) + sizeof(timestamp));
    
    // Node ID
    uint32_t nodeLen = nodeId.length();
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&nodeLen),
                  reinterpret_cast<const uint8_t*>(&nodeLen) + sizeof(nodeLen));
    result.insert(result.end(), nodeId.begin(), nodeId.end());
    
    // Checksum
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&checksum),
                  reinterpret_cast<const uint8_t*>(&checksum) + sizeof(checksum));
    
    return result;
}

StateEntry StateEntry::Deserialize(const std::vector<uint8_t>& data) {
    StateEntry entry;
    size_t offset = 0;
    
    auto readUint32 = [&]() -> uint32_t {
        uint32_t val;
        memcpy(&val, data.data() + offset, sizeof(val));
        offset += sizeof(val);
        return val;
    };
    
    auto readString = [&](uint32_t len) -> std::string {
        std::string str(data.begin() + offset, data.begin() + offset + len);
        offset += len;
        return str;
    };
    
    auto readUint64 = [&]() -> uint64_t {
        uint64_t val;
        memcpy(&val, data.data() + offset, sizeof(val));
        offset += sizeof(val);
        return val;
    };
    
    // Key
    uint32_t keyLen = readUint32();
    entry.key = StateKey::FromString(readString(keyLen));
    
    // Data
    uint32_t dataLen = readUint32();
    entry.data = std::vector<uint8_t>(data.begin() + offset, data.begin() + offset + dataLen);
    offset += dataLen;
    
    // Version
    uint32_t verLen = readUint32();
    entry.version = VersionVector::FromJson(readString(verLen));
    
    // Timestamp
    entry.timestamp = readUint64();
    
    // Node ID
    uint32_t nodeLen = readUint32();
    entry.nodeId = readString(nodeLen);
    
    // Checksum
    memcpy(&entry.checksum, data.data() + offset, sizeof(entry.checksum));
    
    return entry;
}

// ============================================================================
// StateSnapshot Implementation
// ============================================================================

StateSnapshot::StateSnapshot() = default;

StateSnapshot::StateSnapshot(const VersionVector& version) : version_(version) {}

void StateSnapshot::AddEntry(const StateEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_[entry.key] = entry;
}

void StateSnapshot::AddEntries(const std::vector<StateEntry>& entries) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : entries) {
        entries_[entry.key] = entry;
    }
}

std::optional<StateEntry> StateSnapshot::GetEntry(const StateKey& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it != entries_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<StateEntry> StateSnapshot::GetEntriesByType(StateType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<StateEntry> result;
    for (const auto& [key, entry] : entries_) {
        if (key.type == type) {
            result.push_back(entry);
        }
    }
    return result;
}

std::vector<StateEntry> StateSnapshot::GetAllEntries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<StateEntry> result;
    for (const auto& [key, entry] : entries_) {
        result.push_back(entry);
    }
    return result;
}

size_t StateSnapshot::Size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

bool StateSnapshot::IsEmpty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.empty();
}

VersionVector StateSnapshot::GetVersion() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return version_;
}

void StateSnapshot::SetVersion(const VersionVector& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    version_ = version;
}

std::vector<uint8_t> StateSnapshot::Serialize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<uint8_t> result;
    
    // Version
    std::string verJson = version_.ToJson();
    uint32_t verLen = verJson.length();
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&verLen),
                  reinterpret_cast<const uint8_t*>(&verLen) + sizeof(verLen));
    result.insert(result.end(), verJson.begin(), verJson.end());
    
    // Entry count
    uint32_t count = entries_.size();
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&count),
                  reinterpret_cast<const uint8_t*>(&count) + sizeof(count));
    
    // Entries
    for (const auto& [key, entry] : entries_) {
        auto entryData = entry.Serialize();
        uint32_t entryLen = entryData.size();
        result.insert(result.end(), reinterpret_cast<const uint8_t*>(&entryLen),
                      reinterpret_cast<const uint8_t*>(&entryLen) + sizeof(entryLen));
        result.insert(result.end(), entryData.begin(), entryData.end());
    }
    
    return result;
}

StateSnapshot StateSnapshot::Deserialize(const std::vector<uint8_t>& data) {
    StateSnapshot snapshot;
    size_t offset = 0;
    
    auto readUint32 = [&]() -> uint32_t {
        uint32_t val;
        memcpy(&val, data.data() + offset, sizeof(val));
        offset += sizeof(val);
        return val;
    };
    
    auto readString = [&](uint32_t len) -> std::string {
        std::string str(data.begin() + offset, data.begin() + offset + len);
        offset += len;
        return str;
    };
    
    // Version
    uint32_t verLen = readUint32();
    snapshot.version_ = VersionVector::FromJson(readString(verLen));
    
    // Entry count
    uint32_t count = readUint32();
    
    // Entries
    for (uint32_t i = 0; i < count; i++) {
        uint32_t entryLen = readUint32();
        std::vector<uint8_t> entryData(data.begin() + offset, data.begin() + offset + entryLen);
        offset += entryLen;
        
        StateEntry entry = StateEntry::Deserialize(entryData);
        snapshot.entries_[entry.key] = entry;
    }
    
    return snapshot;
}

std::vector<uint8_t> StateSnapshot::Compress() const {
    auto serialized = Serialize();
    
    uLongf compressedSize = compressBound(serialized.size());
    std::vector<uint8_t> compressed(compressedSize);
    
    if (compress2(compressed.data(), &compressedSize,
                  serialized.data(), serialized.size(), Z_BEST_SPEED) == Z_OK) {
        compressed.resize(compressedSize);
        return compressed;
    }
    
    return serialized;  // Fallback to uncompressed
}

StateSnapshot StateSnapshot::Decompress(const std::vector<uint8_t>& data) {
    // Try to decompress
    uLongf uncompressedSize = data.size() * 10;  // Estimate
    std::vector<uint8_t> uncompressed(uncompressedSize);
    
    int result = uncompress(uncompressed.data(), &uncompressedSize,
                           data.data(), data.size());
    
    if (result == Z_OK) {
        uncompressed.resize(uncompressedSize);
        return Deserialize(uncompressed);
    }
    
    // Fallback: assume uncompressed
    return Deserialize(data);
}

// ============================================================================
// DeltaSync Implementation
// ============================================================================

DeltaSync::DeltaSync(const SyncConfig& config) : config_(config) {}

DeltaSync::~DeltaSync() {
    Shutdown();
}

bool DeltaSync::Initialize() {
    running_ = true;
    return true;
}

void DeltaSync::Shutdown() {
    running_ = false;
}

std::optional<Delta> DeltaSync::GenerateDelta(
    const VersionVector& fromVersion,
    const VersionVector& toVersion
) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<StateChange> changes;
    for (const auto& tracked : changes_) {
        // Include changes that happened after fromVersion
        if (tracked.change.version.HappensAfter(fromVersion) ||
            tracked.change.version.IsConcurrentWith(fromVersion)) {
            changes.push_back(tracked.change);
        }
    }
    
    if (changes.empty()) {
        return std::nullopt;
    }
    
    Delta delta;
    delta.fromVersion = fromVersion;
    delta.toVersion = toVersion;
    delta.changes = EncodeChanges(
        std::vector<TrackedChange>(changes.begin(), changes.end())
    );
    delta.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    return delta;
}

std::optional<Delta> DeltaSync::GenerateDeltaForPeer(
    const std::string& peerNodeId,
    const VersionVector& peerVersion
) {
    return GenerateDelta(peerVersion, currentVersion_);
}

bool DeltaSync::ApplyDelta(const Delta& delta) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto changes = DecodeChanges(delta.changes);
    for (const auto& change : changes) {
        TrackChange(change);
    }
    
    currentVersion_.Merge(delta.toVersion);
    return true;
}

bool DeltaSync::ApplyDeltas(const std::vector<Delta>& deltas) {
    for (const auto& delta : deltas) {
        if (!ApplyDelta(delta)) {
            return false;
        }
    }
    return true;
}

void DeltaSync::TrackChange(const StateChange& change) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    TrackedChange tracked;
    tracked.change = change;
    tracked.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    changes_.push_back(tracked);
    
    // Update version vector
    currentVersion_.Merge(change.version);
    
    // Handle tombstones
    if (change.type == StateChange::Type::DELETE && config_.enableTombstones) {
        tombstones_[change.key] = change;
    }
}

void DeltaSync::TrackChanges(const std::vector<StateChange>& changes) {
    for (const auto& change : changes) {
        TrackChange(change);
    }
}

std::vector<StateChange> DeltaSync::GetChangesSince(
    const VersionVector& version,
    size_t maxChanges
) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<StateChange> result;
    for (const auto& tracked : changes_) {
        if (tracked.change.version.HappensAfter(version)) {
            result.push_back(tracked.change);
            if (maxChanges > 0 && result.size() >= maxChanges) {
                break;
            }
        }
    }
    
    return result;
}

void DeltaSync::PruneOldChanges(uint64_t olderThanMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    changes_.erase(
        std::remove_if(changes_.begin(), changes_.end(),
            [now, olderThanMs](const TrackedChange& tc) {
                return (now - tc.timestamp) > olderThanMs;
            }),
        changes_.end()
    );
}

void DeltaSync::PruneTombstones() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!config_.enableTombstones) return;
    
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    for (auto it = tombstones_.begin(); it != tombstones_.end();) {
        if ((now - it->second.timestamp) > config_.tombstoneRetentionMs) {
            it = tombstones_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t DeltaSync::GetPendingChangeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return changes_.size();
}

size_t DeltaSync::GetTombstoneCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return tombstones_.size();
}

std::vector<uint8_t> DeltaSync::EncodeChanges(
    const std::vector<TrackedChange>& changes
) {
    // Simple JSON encoding for now
    std::string json = "[";
    for (size_t i = 0; i < changes.size(); i++) {
        if (i > 0) json += ",";
        // Add change encoding
        json += "{}";  // Placeholder
    }
    json += "]";
    
    return std::vector<uint8_t>(json.begin(), json.end());
}

std::vector<StateChange> DeltaSync::DecodeChanges(const std::vector<uint8_t>& data) {
    // Placeholder implementation
    return {};
}

// ============================================================================
// StateReplicator Implementation
// ============================================================================

StateReplicator::StateReplicator(
    std::shared_ptr<CommunicationManager> commManager,
    const SyncConfig& config
) : commManager_(commManager), config_(config) {}

StateReplicator::~StateReplicator() {
    Shutdown();
}

bool StateReplicator::Initialize() {
    running_ = true;
    
    deltaSync_ = std::make_unique<DeltaSync>(config_);
    deltaSync_->Initialize();
    
    crdtManager_ = std::make_unique<CRDTManager>();
    
    // Start background threads
    syncThread_ = std::thread(&StateReplicator::SyncLoop, this);
    snapshotThread_ = std::thread(&StateReplicator::SnapshotLoop, this);
    
    return true;
}

void StateReplicator::Shutdown() {
    running_ = false;
    
    if (syncThread_.joinable()) {
        syncThread_.join();
    }
    if (snapshotThread_.joinable()) {
        snapshotThread_.join();
    }
    
    if (deltaSync_) {
        deltaSync_->Shutdown();
    }
}

bool StateReplicator::SetState(const StateKey& key, const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    StateEntry entry;
    entry.key = key;
    entry.data = data;
    entry.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    entry.checksum = entry.CalculateChecksum();
    
    localState_[key] = entry;
    
    // Track change
    StateChange change;
    change.type = StateChange::Type::SET;
    change.key = key;
    change.data = data;
    change.timestamp = entry.timestamp;
    
    deltaSync_->TrackChange(change);
    NotifyStateChange(change);
    
    return true;
}

bool StateReplicator::SetState(const StateKey& key, const std::string& data) {
    return SetState(key, std::vector<uint8_t>(data.begin(), data.end()));
}

bool StateReplicator::SetStateJson(const StateKey& key, const std::string& json) {
    return SetState(key, json);
}

std::optional<std::vector<uint8_t>> StateReplicator::GetState(const StateKey& key) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    auto it = localState_.find(key);
    if (it != localState_.end()) {
        return it->second.data;
    }
    
    return std::nullopt;
}

std::optional<std::string> StateReplicator::GetStateString(const StateKey& key) {
    auto data = GetState(key);
    if (data) {
        return std::string(data->begin(), data->end());
    }
    return std::nullopt;
}

std::optional<std::string> StateReplicator::GetStateJson(const StateKey& key) {
    return GetStateString(key);
}

bool StateReplicator::DeleteState(const StateKey& key) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    localState_.erase(key);
    
    StateChange change;
    change.type = StateChange::Type::DELETE;
    change.key = key;
    change.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    deltaSync_->TrackChange(change);
    NotifyStateChange(change);
    
    return true;
}

bool StateReplicator::HasState(const StateKey& key) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    return localState_.find(key) != localState_.end();
}

bool StateReplicator::SetMultiple(
    const std::map<StateKey, std::vector<uint8_t>>& states
) {
    for (const auto& [key, data] : states) {
        SetState(key, data);
    }
    return true;
}

std::map<StateKey, std::vector<uint8_t>> StateReplicator::GetMultiple(
    const std::vector<StateKey>& keys
) {
    std::map<StateKey, std::vector<uint8_t>> result;
    for (const auto& key : keys) {
        auto data = GetState(key);
        if (data) {
            result[key] = *data;
        }
    }
    return result;
}

std::map<StateKey, std::vector<uint8_t>> StateReplicator::GetAllByType(StateType type) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    std::map<StateKey, std::vector<uint8_t>> result;
    for (const auto& [key, entry] : localState_) {
        if (key.type == type) {
            result[key] = entry.data;
        }
    }
    return result;
}

bool StateReplicator::RequestSync(const std::string& peerNodeId) {
    // Send sync request message
    Message msg;
    msg.header.type = MessageType::STATE_SYNC_REQUEST;
    msg.header.destinationNode = peerNodeId;
    
    // Add current version
    auto version = deltaSync_->GenerateDelta(VersionVector{}, VersionVector{});
    if (version) {
        msg.payload = version->ToJson();
    }
    
    return commManager_->SendMessage(peerNodeId, msg);
}

bool StateReplicator::RequestSyncAll() {
    auto nodes = commManager_->GetConnectedNodes();
    bool success = true;
    for (const auto& node : nodes) {
        if (!RequestSync(node.nodeId)) {
            success = false;
        }
    }
    return success;
}

bool StateReplicator::IsSyncing(const std::string& peerNodeId) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    auto it = peerStatus_.find(peerNodeId);
    if (it != peerStatus_.end()) {
        return it->second.isSyncing;
    }
    return false;
}

StateSnapshot StateReplicator::CreateSnapshot() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    StateSnapshot snapshot;
    for (const auto& [key, entry] : localState_) {
        snapshot.AddEntry(entry);
    }
    
    return snapshot;
}

bool StateReplicator::RestoreSnapshot(const StateSnapshot& snapshot) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    localState_.clear();
    for (const auto& entry : snapshot.GetAllEntries()) {
        localState_[entry.key] = entry;
    }
    
    return true;
}

bool StateReplicator::RequestSnapshot(const std::string& peerNodeId) {
    Message msg;
    msg.header.type = MessageType::STATE_SYNC_REQUEST;
    msg.header.destinationNode = peerNodeId;
    msg.header.flags = 0x02;  // Snapshot request flag
    
    return commManager_->SendMessage(peerNodeId, msg);
}

void StateReplicator::OnStateChange(StateChangeCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    changeCallback_ = callback;
}

void StateReplicator::OnSyncComplete(SyncCompleteCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    syncCompleteCallback_ = callback;
}

SyncStatus StateReplicator::GetSyncStatus(const std::string& peerNodeId) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    auto it = peerStatus_.find(peerNodeId);
    if (it != peerStatus_.end()) {
        return it->second;
    }
    
    return SyncStatus{};
}

std::vector<SyncStatus> StateReplicator::GetAllSyncStatus() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    std::vector<SyncStatus> result;
    for (const auto& [nodeId, status] : peerStatus_) {
        result.push_back(status);
    }
    return result;
}

bool StateReplicator::IsFullySynced() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    for (const auto& [nodeId, status] : peerStatus_) {
        if (status.lagMs > config_.maxSyncLagMs) {
            return false;
        }
    }
    return true;
}

uint64_t StateReplicator::GetMaxLagMs() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    uint64_t maxLag = 0;
    for (const auto& [nodeId, status] : peerStatus_) {
        maxLag = std::max(maxLag, status.lagMs);
    }
    return maxLag;
}

CRDTManager* StateReplicator::GetCRDTManager() {
    return crdtManager_.get();
}

StateEntry StateReplicator::ResolveConflict(
    const StateEntry& local,
    const StateEntry& remote
) {
    if (!config_.enableCRDT) {
        // Last-write-wins
        if (local.timestamp > remote.timestamp) {
            return local;
        } else if (remote.timestamp > local.timestamp) {
            return remote;
        }
        // Tie-breaker: lexicographic node ID
        return local.nodeId < remote.nodeId ? local : remote;
    }
    
    // CRDT-based resolution
    if (local.version.IsConcurrentWith(remote.version)) {
        // Concurrent updates - merge using CRDT semantics
        // For now, use LWW as fallback
        return local.timestamp > remote.timestamp ? local : remote;
    }
    
    if (local.version.HappensAfter(remote.version)) {
        return local;
    }
    
    return remote;
}

void StateReplicator::NotifyStateChange(const StateChange& change) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (changeCallback_) {
        changeCallback_(change);
    }
}

void StateReplicator::NotifySyncComplete(const std::string& peerNodeId, bool success) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (syncCompleteCallback_) {
        syncCompleteCallback_(peerNodeId, success);
    }
}

void StateReplicator::UpdatePeerVersion(
    const std::string& peerNodeId,
    const VersionVector& version
) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    peerStatus_[peerNodeId].peerVersion = version;
    peerStatus_[peerNodeId].lastSyncTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void StateReplicator::SyncLoop() {
    while (running_) {
        // Periodic sync with all peers
        auto nodes = commManager_->GetConnectedNodes();
        for (const auto& node : nodes) {
            auto delta = deltaSync_->GenerateDeltaForPeer(
                node.nodeId,
                GetSyncStatus(node.nodeId).peerVersion
            );
            
            if (delta) {
                Message msg;
                msg.header.type = MessageType::STATE_DELTA;
                msg.header.destinationNode = node.nodeId;
                msg.payload = delta->ToJson();
                
                commManager_->SendMessage(node.nodeId, msg);
            }
        }
        
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.deltaSyncIntervalMs));
    }
}

void StateReplicator::SnapshotLoop() {
    while (running_) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.snapshotIntervalMs));
        
        if (!running_) break;
        
        // Prune old changes
        deltaSync_->PruneOldChanges(config_.tombstoneRetentionMs);
        deltaSync_->PruneTombstones();
    }
}

// ============================================================================
// SyncScheduler Implementation
// ============================================================================

SyncScheduler::SyncScheduler(const SyncConfig& config) : config_(config) {}

SyncScheduler::~SyncScheduler() {
    Shutdown();
}

bool SyncScheduler::Initialize() {
    running_ = true;
    return true;
}

void SyncScheduler::Shutdown() {
    running_ = false;
    cv_.notify_all();
}

void SyncScheduler::ScheduleSync(const std::string& peerNodeId, Task::Priority priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Task task;
    task.priority = priority;
    task.peerNodeId = peerNodeId;
    task.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    tasks_.push(task);
    cv_.notify_one();
}

void SyncScheduler::ScheduleDeltaSync(
    const std::string& peerNodeId,
    const VersionVector& from
) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Task task;
    task.priority = Task::Priority::NORMAL;
    task.peerNodeId = peerNodeId;
    task.targetVersion = from;
    task.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    tasks_.push(task);
    cv_.notify_one();
}

void SyncScheduler::ScheduleSnapshot(const std::string& peerNodeId) {
    ScheduleSync(peerNodeId, Task::Priority::SNAPSHOT);
}

void SyncScheduler::ScheduleFullSync() {
    std::lock_guard<std::mutex> lock(mutex_);
    // Schedule sync for all known peers
    // This would need access to node registry
}

std::optional<Task> SyncScheduler::GetNextTask() {
    std::unique_lock<std::mutex> lock(mutex_);
    
    cv_.wait(lock, [this] { return !tasks_.empty() || !running_; });
    
    if (!running_ || tasks_.empty()) {
        return std::nullopt;
    }
    
    Task task = tasks_.top();
    tasks_.pop();
    activeSyncs_.insert(task.peerNodeId);
    
    return task;
}

void SyncScheduler::CancelTasksForPeer(const std::string& peerNodeId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Remove from active syncs
    activeSyncs_.erase(peerNodeId);
    
    // Rebuild queue without this peer's tasks
    std::priority_queue<Task> newQueue;
    while (!tasks_.empty()) {
        Task task = tasks_.top();
        tasks_.pop();
        if (task.peerNodeId != peerNodeId) {
            newQueue.push(task);
        }
    }
    tasks_ = std::move(newQueue);
}

void SyncScheduler::CancelAllTasks() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    while (!tasks_.empty()) {
        tasks_.pop();
    }
    activeSyncs_.clear();
}

size_t SyncScheduler::GetPendingTaskCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return tasks_.size();
}

size_t SyncScheduler::GetTaskCountByPriority(Task::Priority priority) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t count = 0;
    auto tempQueue = tasks_;
    while (!tempQueue.empty()) {
        if (tempQueue.top().priority == priority) {
            count++;
        }
        tempQueue.pop();
    }
    return count;
}

bool SyncScheduler::Task::operator<(const Task& other) const {
    // Higher priority comes first
    return priority > other.priority;
}

// ============================================================================
// StateSynchronizer Implementation
// ============================================================================

StateSynchronizer::StateSynchronizer(
    std::shared_ptr<CommunicationManager> commManager,
    const SyncConfig& config
) {
    replicator_ = std::make_unique<StateReplicator>(commManager, config);
    scheduler_ = std::make_unique<SyncScheduler>(config);
}

StateSynchronizer::~StateSynchronizer() {
    Shutdown();
}

bool StateSynchronizer::Initialize() {
    if (!replicator_->Initialize()) {
        return false;
    }
    if (!scheduler_->Initialize()) {
        return false;
    }
    return true;
}

void StateSynchronizer::Shutdown() {
    if (replicator_) {
        replicator_->Shutdown();
    }
    if (scheduler_) {
        scheduler_->Shutdown();
    }
}

bool StateSynchronizer::Set(const std::string& key, const std::string& value) {
    StateKey stateKey = StateKey::FromString(key);
    return replicator_->SetState(stateKey, value);
}

bool StateSynchronizer::SetJson(const std::string& key, const std::string& json) {
    return Set(key, json);
}

std::optional<std::string> StateSynchronizer::Get(const std::string& key) {
    StateKey stateKey = StateKey::FromString(key);
    return replicator_->GetStateString(stateKey);
}

std::optional<std::string> StateSynchronizer::GetJson(const std::string& key) {
    return Get(key);
}

bool StateSynchronizer::Delete(const std::string& key) {
    StateKey stateKey = StateKey::FromString(key);
    return replicator_->DeleteState(stateKey);
}

bool StateSynchronizer::Exists(const std::string& key) {
    StateKey stateKey = StateKey::FromString(key);
    return replicator_->HasState(stateKey);
}

bool StateSynchronizer::SyncNow(const std::string& peerNodeId) {
    return replicator_->RequestSync(peerNodeId);
}

bool StateSynchronizer::SyncAllNow() {
    return replicator_->RequestSyncAll();
}

bool StateSynchronizer::IsSyncComplete() {
    return replicator_->IsFullySynced();
}

void StateSynchronizer::WaitForSync() {
    while (!IsSyncComplete()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

bool StateSynchronizer::IsHealthy() {
    return replicator_->GetMaxLagMs() < replicator_->GetSyncStatus("").lagMs;
}

std::string StateSynchronizer::GetStatusJson() {
    auto statuses = replicator_->GetAllSyncStatus();
    
    std::string json = "{\"peers\":[";
    for (size_t i = 0; i < statuses.size(); i++) {
        if (i > 0) json += ",";
        json += statuses[i].ToJson();
    }
    json += "],\"maxLagMs\":" + std::to_string(replicator_->GetMaxLagMs());
    json += ",\"healthy\":" + std::string(IsHealthy() ? "true" : "false") + "}";
    
    return json;
}

StateReplicator* StateSynchronizer::GetReplicator() {
    return replicator_.get();
}

} // namespace Distributed
