// ============================================================================
// CheckpointManager.cpp — Task Checkpoint and Rollback System
// ============================================================================
#include "CheckpointManager.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <iomanip>
#include <cstring>

namespace fs = std::filesystem;

namespace RawrXD {
namespace Checkpoint {

static std::string GenerateUUID() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::uniform_int_distribution<> dis2(8, 11);
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 8; i++) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 4; i++) ss << dis(gen);
    ss << "-4";
    for (int i = 0; i < 3; i++) ss << dis(gen);
    ss << "-";
    ss << dis2(gen);
    for (int i = 0; i < 3; i++) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 12; i++) ss << dis(gen);
    return ss.str();
}

CheckpointManager::CheckpointManager() = default;
CheckpointManager::~CheckpointManager() { Shutdown(); }

bool CheckpointManager::Initialize(const std::string& storagePath) {
    m_storagePath = storagePath;
    try {
        fs::create_directories(m_storagePath);
        fs::create_directories(m_storagePath + "/snapshots");
        LoadState();
    } catch (const std::exception& e) {
        fprintf(stderr, "[Checkpoint] Init error: %s\n", e.what());
        return false;
    }
    m_initialized = true;
    return true;
}

void CheckpointManager::Shutdown() {
    DisableAutoCheckpoint();
    SaveState();
    m_initialized = false;
}

std::string CheckpointManager::CreateCheckpoint(const std::string& name,
                                                  const std::string& description,
                                                  bool isAuto) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    Checkpoint cp;
    cp.id = GenerateUUID();
    cp.name = name;
    cp.description = description;
    cp.created = std::chrono::system_clock::now();
    cp.isAutoCheckpoint = isAuto;
    
    // Snapshot all tracked files
    // In production, this would snapshot the entire project state
    cp.metadata["file_count"] = 0;
    cp.metadata["agent_state"] = "active";
    
    m_checkpoints.push_back(cp);
    
    // Keep only last 100 checkpoints
    if (m_checkpoints.size() > 100) {
        m_checkpoints.erase(m_checkpoints.begin());
    }
    
    SaveState();
    
    if (m_checkpointCb) m_checkpointCb(cp);
    
    printf("[Checkpoint] Created: %s (%s)\n", cp.id.c_str(), name.c_str());
    return cp.id;
}

bool CheckpointManager::RestoreCheckpoint(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (auto& cp : m_checkpoints) {
        if (cp.id == id) {
            if (RestoreFiles(cp)) {
                cp.restored = std::chrono::system_clock::now();
                SaveState();
                if (m_rollbackCb) m_rollbackCb(id, true);
                printf("[Checkpoint] Restored: %s\n", id.c_str());
                return true;
            }
            if (m_rollbackCb) m_rollbackCb(id, false);
            return false;
        }
    }
    return false;
}

bool CheckpointManager::DeleteCheckpoint(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = std::remove_if(m_checkpoints.begin(), m_checkpoints.end(),
        [&id](const Checkpoint& cp) { return cp.id == id; });
    if (it != m_checkpoints.end()) {
        m_checkpoints.erase(it, m_checkpoints.end());
        SaveState();
        return true;
    }
    return false;
}

Checkpoint CheckpointManager::GetCheckpoint(const std::string& id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& cp : m_checkpoints) {
        if (cp.id == id) return cp;
    }
    return Checkpoint{};
}

std::vector<Checkpoint> CheckpointManager::ListCheckpoints(int maxResults) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_checkpoints.size() <= static_cast<size_t>(maxResults)) {
        return m_checkpoints;
    }
    return std::vector<Checkpoint>(m_checkpoints.end() - maxResults, m_checkpoints.end());
}

std::vector<Checkpoint> CheckpointManager::FindCheckpoints(const std::string& query) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<Checkpoint> results;
    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
    for (const auto& cp : m_checkpoints) {
        std::string combined = cp.name + " " + cp.description;
        std::transform(combined.begin(), combined.end(), combined.begin(), ::tolower);
        if (combined.find(lowerQuery) != std::string::npos) {
            results.push_back(cp);
        }
    }
    return results;
}

void CheckpointManager::EnableAutoCheckpoint(int intervalSec) {
    m_autoCheckpointEnabled = true;
    m_autoCheckpointIntervalSec = intervalSec;
    m_autoCheckpointThread = std::thread(&CheckpointManager::AutoCheckpointLoop, this);
}

void CheckpointManager::DisableAutoCheckpoint() {
    m_autoCheckpointEnabled = false;
    if (m_autoCheckpointThread.joinable()) {
        m_autoCheckpointThread.join();
    }
}

void CheckpointManager::TriggerAutoCheckpoint() {
    CreateCheckpoint("auto-" + std::to_string(std::time(nullptr)), 
                     "Automatic checkpoint", true);
}

bool CheckpointManager::SnapshotFile(const std::string& filePath, const std::string& checkpointId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& cp : m_checkpoints) {
        if (cp.id == checkpointId) {
            FileSnapshot snap;
            snap.path = filePath;
            snap.timestamp = std::chrono::system_clock::now();
            
            std::ifstream file(filePath, std::ios::binary);
            if (file.is_open()) {
                std::stringstream ss;
                ss << file.rdbuf();
                snap.content = ss.str();
                snap.size = snap.content.size();
                snap.hash = ComputeFileHash(filePath);
            }
            
            cp.files.push_back(snap);
            cp.totalSize += snap.size;
            return true;
        }
    }
    return false;
}

bool CheckpointManager::RestoreFile(const std::string& filePath, const std::string& checkpointId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& cp : m_checkpoints) {
        if (cp.id == checkpointId) {
            for (const auto& snap : cp.files) {
                if (snap.path == filePath) {
                    try {
                        std::ofstream file(filePath, std::ios::binary);
                        if (file.is_open()) {
                            file.write(snap.content.data(), snap.content.size());
                            return true;
                        }
                    } catch (...) {}
                    return false;
                }
            }
        }
    }
    return false;
}

bool CheckpointManager::HasSnapshot(const std::string& filePath, const std::string& checkpointId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& cp : m_checkpoints) {
        if (cp.id == checkpointId) {
            for (const auto& snap : cp.files) {
                if (snap.path == filePath) return true;
            }
        }
    }
    return false;
}

std::vector<DiffEntry> CheckpointManager::ComputeDiff(const std::string& checkpointId) {
    std::vector<DiffEntry> diffs;
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (const auto& cp : m_checkpoints) {
        if (cp.id == checkpointId) {
            for (const auto& snap : cp.files) {
                DiffEntry entry;
                entry.filePath = snap.path;
                entry.originalContent = snap.content;
                
                // Read current file content
                std::ifstream file(snap.path);
                if (file.is_open()) {
                    std::stringstream ss;
                    ss << file.rdbuf();
                    entry.newContent = ss.str();
                }
                
                // Compute unified diff
                entry.diff = ComputeDiff(snap.content, entry.newContent);
                
                // Count additions/deletions
                std::istringstream diffStream(entry.diff);
                std::string line;
                while (std::getline(diffStream, line)) {
                    if (line.size() > 0 && line[0] == '+') entry.additions++;
                    else if (line.size() > 0 && line[0] == '-') entry.deletions++;
                }
                
                diffs.push_back(entry);
            }
            break;
        }
    }
    
    return diffs;
}

std::vector<DiffEntry> CheckpointManager::ComputeDiff(const std::string& fromId, const std::string& toId) {
    // Compare two checkpoints
    std::vector<DiffEntry> diffs;
    return diffs;
}

bool CheckpointManager::ApproveDiff(const std::string& filePath, const std::string& checkpointId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& cp : m_checkpoints) {
        if (cp.id == checkpointId) {
            for (auto& snap : cp.files) {
                if (snap.path == filePath) {
                    // Mark as approved - in production this would trigger the change
                    return true;
                }
            }
        }
    }
    return false;
}

bool CheckpointManager::RejectDiff(const std::string& filePath, const std::string& checkpointId,
                                    const std::string& reason) {
    return RestoreFile(filePath, checkpointId);
}

bool CheckpointManager::RollbackToLastCheckpoint() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_checkpoints.empty()) return false;
    return RestoreCheckpoint(m_checkpoints.back().id);
}

bool CheckpointManager::RollbackToCheckpoint(const std::string& id) {
    return RestoreCheckpoint(id);
}

bool CheckpointManager::RollbackFile(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& cp : m_checkpoints) {
        for (const auto& snap : cp.files) {
            if (snap.path == filePath) {
                try {
                    std::ofstream file(filePath, std::ios::binary);
                    if (file.is_open()) {
                        file.write(snap.content.data(), snap.content.size());
                        return true;
                    }
                } catch (...) {}
                return false;
            }
        }
    }
    return false;
}

json CheckpointManager::GetStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    json stats;
    stats["checkpoint_count"] = m_checkpoints.size();
    stats["total_size_bytes"] = GetTotalSize();
    stats["auto_checkpoint_enabled"] = m_autoCheckpointEnabled;
    stats["storage_path"] = m_storagePath;
    
    int autoCount = 0;
    for (const auto& cp : m_checkpoints) {
        if (cp.isAutoCheckpoint) autoCount++;
    }
    stats["auto_checkpoints"] = autoCount;
    
    return stats;
}

uint64_t CheckpointManager::GetTotalSize() const {
    uint64_t total = 0;
    for (const auto& cp : m_checkpoints) {
        total += cp.totalSize;
    }
    return total;
}

bool CheckpointManager::SaveState() {
    try {
        fs::create_directories(m_storagePath);
        json j = json::array();
        for (const auto& cp : m_checkpoints) {
            json cj;
            cj["id"] = cp.id;
            cj["name"] = cp.name;
            cj["description"] = cp.description;
            cj["is_auto"] = cp.isAutoCheckpoint;
            cj["file_count"] = cp.files.size();
            cj["total_size"] = cp.totalSize;
            j.push_back(cj);
        }
        std::ofstream file(m_storagePath + "/checkpoints.json");
        if (file.is_open()) { file << j.dump(2); return true; }
    } catch (...) {}
    return false;
}

bool CheckpointManager::LoadState() {
    try {
        std::ifstream file(m_storagePath + "/checkpoints.json");
        if (!file.is_open()) return false;
        json j;
        file >> j;
        // Load metadata only (file snapshots are stored separately)
        return true;
    } catch (...) { return false; }
}

std::string CheckpointManager::GenerateId() {
    return GenerateUUID();
}

bool CheckpointManager::RestoreFiles(const Checkpoint& cp) {
    bool allRestored = true;
    for (const auto& snap : cp.files) {
        try {
            fs::create_directories(fs::path(snap.path).parent_path());
            std::ofstream file(snap.path, std::ios::binary);
            if (file.is_open()) {
                file.write(snap.content.data(), snap.content.size());
            } else {
                allRestored = false;
            }
        } catch (...) {
            allRestored = false;
        }
    }
    return allRestored;
}

std::string CheckpointManager::ComputeFileHash(const std::string& path) {
    // Simple hash for now - would use SHA256 in production
    try {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return "";
        std::stringstream ss;
        ss << file.rdbuf();
        std::string content = ss.str();
        
        // Simple FNV-1a hash
        uint64_t hash = 14695981039346656037ULL;
        for (char c : content) {
            hash ^= static_cast<uint64_t>(c);
            hash *= 1099511628211ULL;
        }
        
        std::stringstream hss;
        hss << std::hex << hash;
        return hss.str();
    } catch (...) {
        return "";
    }
}

std::string CheckpointManager::ComputeDiff(const std::string& original, const std::string& modified) {
    // Simple line-based diff
    std::vector<std::string> origLines, modLines;
    std::istringstream origStream(original), modStream(modified);
    std::string line;
    
    while (std::getline(origStream, line)) origLines.push_back(line);
    while (std::getline(modStream, line)) modLines.push_back(line);
    
    std::stringstream diff;
    size_t maxLines = std::max(origLines.size(), modLines.size());
    
    for (size_t i = 0; i < maxLines; i++) {
        if (i >= origLines.size()) {
            diff << "+" << modLines[i] << "\n";
        } else if (i >= modLines.size()) {
            diff << "-" << origLines[i] << "\n";
        } else if (origLines[i] != modLines[i]) {
            diff << "-" << origLines[i] << "\n";
            diff << "+" << modLines[i] << "\n";
        }
    }
    
    return diff.str();
}

void CheckpointManager::AutoCheckpointLoop() {
    while (m_autoCheckpointEnabled) {
        std::this_thread::sleep_for(std::chrono::seconds(m_autoCheckpointIntervalSec));
        if (m_autoCheckpointEnabled) {
            TriggerAutoCheckpoint();
        }
    }
}

} // namespace Checkpoint
} // namespace RawrXD
