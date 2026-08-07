// ============================================================================
// Ledger.cpp — Transaction Ledger Implementation
// ============================================================================

#include "Ledger.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <fstream>
#include <chrono>

namespace rawr {

Ledger& Ledger::Get() {
    static Ledger instance;
    return instance;
}

bool Ledger::Initialize(const char* path) {
    m_path = path ? path : "rawrxd.ledger";
    RawrRuntime::Get().Log(LogLevel::Info, "Ledger initialized");
    return true;
}

void Ledger::Shutdown() {
    Flush();
    m_entries.clear();
}

void Ledger::Record(const char* action, const char* key,
                    const char* oldValue, const char* newValue) {
    std::lock_guard<std::mutex> lock(m_mutex);

    LedgerEntry entry;
    entry.id = m_nextId++;
    entry.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    entry.action = action ? action : "";
    entry.key = key ? key : "";
    entry.oldValue = oldValue ? oldValue : "";
    entry.newValue = newValue ? newValue : "";

    m_entries.push_back(entry);
    m_entryCount++;
}

void Ledger::RecordState(const char* action, const char* stateJson) {
    Record(action, "_state", "", stateJson ? stateJson : "");
}

std::vector<LedgerEntry> Ledger::Query(uint64_t sinceId, uint32_t limit) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<LedgerEntry> result;
    for (const auto& entry : m_entries) {
        if (entry.id > sinceId) {
            result.push_back(entry);
            if (result.size() >= limit) break;
        }
    }
    return result;
}

bool Ledger::Flush() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_path.empty() || m_entries.empty()) return true;

    std::ofstream file(m_path, std::ios::app);
    if (!file.is_open()) return false;

    for (const auto& entry : m_entries) {
        file << entry.id << "|"
             << entry.timestamp << "|"
             << entry.action << "|"
             << entry.key << "|"
             << entry.oldValue << "|"
             << entry.newValue << "\n";
    }

    file.close();
    m_entries.clear();
    return true;
}

} // namespace rawr
