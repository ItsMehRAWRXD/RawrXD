// ============================================================================
// Migration.hpp — Schema Migration Engine
// Versioned state migration with rollback support
// ============================================================================

#ifndef MIGRATION_HPP
#define MIGRATION_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <mutex>

namespace rawr {

// ============================================================================
// Migration Function
// ============================================================================
using MigrationFn = std::function<bool(const char* currentState, char** newState, size_t* newSize)>;

// ============================================================================
// Migration Entry
// ============================================================================
struct MigrationEntry {
    uint32_t targetVersion;
    MigrationFn migrate;
    const char* description;
};

// ============================================================================
// MigrationEngine — Versioned state migration
// ============================================================================
class MigrationEngine {
public:
    static MigrationEngine& Get();

    void Initialize(uint32_t currentVersion = 0);
    void Shutdown();

    void RegisterMigration(uint32_t targetVersion, MigrationFn fn, const char* description = nullptr);
    uint32_t GetCurrentVersion() const { return m_currentVersion; }
    uint32_t GetLatestVersion() const { return m_latestVersion; }

    // Run all pending migrations
    bool RunPending(const char* stateData, size_t stateSize,
                    char** outData, size_t* outSize);

    // Check if migration is needed
    bool NeedsMigration() const { return m_currentVersion < m_latestVersion; }

private:
    MigrationEngine() = default;
    ~MigrationEngine() = default;
    MigrationEngine(const MigrationEngine&) = delete;
    MigrationEngine& operator=(const MigrationEngine&) = delete;

    std::vector<MigrationEntry> m_migrations;
    uint32_t m_currentVersion = 0;
    uint32_t m_latestVersion = 0;
    mutable std::mutex m_mutex;
};

} // namespace rawr

#endif // MIGRATION_HPP
