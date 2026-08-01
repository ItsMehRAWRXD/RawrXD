// ============================================================================
// StateManager.cpp — Native State Manager Implementation
// ============================================================================

#include "StateManager.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>

namespace rawr {

StateManager& StateManager::Get() {
    static StateManager instance;
    return instance;
}

void StateManager::Initialize() {
    RawrRuntime::Get().Log(LogLevel::Info, "StateManager initialized");
}

void StateManager::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.clear();
    m_history.clear();
}

void StateManager::Set(const char* key, const char* value) {
    if (!key) return;
    std::lock_guard<std::mutex> lock(m_mutex);

    StateEntry entry;
    entry.key = key;
    entry.value = value ? value : "";
    entry.version = ++m_version;

    m_state[key] = entry;
}

const char* StateManager::Get(const char* key, const char* defaultValue) {
    if (!key) return defaultValue;
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_state.find(key);
    if (it != m_state.end()) {
        return it->second.value.c_str();
    }
    return defaultValue;
}

bool StateManager::Has(const char* key) const {
    if (!key) return false;
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_state.find(key) != m_state.end();
}

void StateManager::Remove(const char* key) {
    if (!key) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.erase(key);
}

void StateManager::Clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.clear();
}

uint64_t StateManager::BeginTransaction(const char* action) {
    std::lock_guard<std::mutex> lock(m_mutex);

    Transaction tx;
    tx.id = m_nextTxId++;
    tx.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    tx.action = action ? action : "unknown";

    m_history.push_back(tx);
    return tx.id;
}

void StateManager::CommitTransaction(uint64_t txId) {
    // Transaction is already recorded; mark as committed
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& tx : m_history) {
        if (tx.id == txId) {
            break;
        }
    }
}

void StateManager::RollbackTransaction(uint64_t txId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = std::find_if(m_history.begin(), m_history.end(),
        [txId](const Transaction& tx) { return tx.id == txId; });

    if (it != m_history.end()) {
        // Reverse changes
        for (const auto& change : it->changes) {
            m_state[change.key] = change;
        }
        m_history.erase(it);
    }
}

std::vector<StateEntry> StateManager::Snapshot() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<StateEntry> result;
    for (const auto& [key, entry] : m_state) {
        result.push_back(entry);
    }
    return result;
}

bool StateManager::Restore(const std::vector<StateEntry>& snapshot) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.clear();
    for (const auto& entry : snapshot) {
        m_state[entry.key] = entry;
    }
    return true;
}

bool StateManager::Rollback() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_history.empty()) return false;

    // Remove last transaction
    m_history.pop_back();
    if (m_history.empty()) return false;

    // Restore to previous state
    const auto& prev = m_history.back();
    for (const auto& change : prev.changes) {
        m_state[change.key] = change;
    }

    return true;
}

bool StateManager::Save(const char* path) {
    if (!path) return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    std::ofstream file(path);
    if (!file.is_open()) return false;

    for (const auto& [key, entry] : m_state) {
        file << entry.key << "=" << entry.value << "\n";
    }

    return true;
}

bool StateManager::Load(const char* path) {
    if (!path) return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    std::ifstream file(path);
    if (!file.is_open()) return false;

    m_state.clear();
    std::string line;
    while (std::getline(file, line)) {
        auto pos = line.find('=');
        if (pos != std::string::npos) {
            StateEntry entry;
            entry.key = line.substr(0, pos);
            entry.value = line.substr(pos + 1);
            entry.version = ++m_version;
            m_state[entry.key] = entry;
        }
    }

    return true;
}

} // namespace rawr
