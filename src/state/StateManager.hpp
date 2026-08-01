// ============================================================================
// StateManager.hpp — Native State Manager
// Dispatch, snapshot, rollback, restore
// ============================================================================

#ifndef STATE_MANAGER_HPP
#define STATE_MANAGER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <mutex>

namespace rawr {

// ============================================================================
// State Entry
// ============================================================================
struct StateEntry {
    std::string key;
    std::string value;
    uint64_t version;
};

// ============================================================================
// Transaction
// ============================================================================
struct Transaction {
    uint64_t id;
    uint64_t timestamp;
    std::string action;
    std::vector<StateEntry> changes;
};

// ============================================================================
// StateManager — Atomic state with rollback
// ============================================================================
class StateManager {
public:
    static StateManager& Get();

    void Initialize();
    void Shutdown();

    // State operations
    void Set(const char* key, const char* value);
    const char* Get(const char* key, const char* defaultValue = nullptr);
    bool Has(const char* key) const;
    void Remove(const char* key);
    void Clear();

    // Transactions
    uint64_t BeginTransaction(const char* action);
    void CommitTransaction(uint64_t txId);
    void RollbackTransaction(uint64_t txId);

    // Snapshot
    std::vector<StateEntry> Snapshot() const;
    bool Restore(const std::vector<StateEntry>& snapshot);

    // Rollback to last known good state
    bool Rollback();

    // Persistence
    bool Save(const char* path);
    bool Load(const char* path);

    uint64_t GetVersion() const { return m_version; }

private:
    StateManager() = default;
    ~StateManager() = default;
    StateManager(const StateManager&) = delete;
    StateManager& operator=(const StateManager&) = delete;

    std::unordered_map<std::string, StateEntry> m_state;
    std::vector<Transaction> m_history;
    uint64_t m_version = 0;
    uint64_t m_nextTxId = 1;
    mutable std::mutex m_mutex;
};

} // namespace rawr

#endif // STATE_MANAGER_HPP
