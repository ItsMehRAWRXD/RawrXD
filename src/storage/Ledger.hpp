// ============================================================================
// Ledger.hpp — Transaction Ledger
// Persistent journal of state changes
// ============================================================================

#ifndef LEDGER_HPP
#define LEDGER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <mutex>

namespace rawr {

// ============================================================================
// Ledger Entry
// ============================================================================
struct LedgerEntry {
    uint64_t id;
    uint64_t timestamp;
    std::string action;
    std::string key;
    std::string oldValue;
    std::string newValue;
};

// ============================================================================
// Ledger — Append-only transaction journal
// ============================================================================
class Ledger {
public:
    static Ledger& Get();

    bool Initialize(const char* path = nullptr);
    void Shutdown();

    void Record(const char* action, const char* key,
                const char* oldValue, const char* newValue);
    void RecordState(const char* action, const char* stateJson);

    std::vector<LedgerEntry> Query(uint64_t sinceId = 0, uint32_t limit = 100) const;
    uint64_t GetEntryCount() const { return m_entryCount; }
    bool Flush();

private:
    Ledger() = default;
    ~Ledger() { Shutdown(); }
    Ledger(const Ledger&) = delete;
    Ledger& operator=(const Ledger&) = delete;

    std::vector<LedgerEntry> m_entries;
    uint64_t m_entryCount = 0;
    uint64_t m_nextId = 1;
    std::string m_path;
    mutable std::mutex m_mutex;
};

} // namespace rawr

#endif // LEDGER_HPP
