// ============================================================================
// Migration.cpp — Schema Migration Engine Implementation
// ============================================================================

#include "Migration.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <cstdlib>
#include <cstring>

namespace rawr {

MigrationEngine& MigrationEngine::Get() {
    static MigrationEngine instance;
    return instance;
}

void MigrationEngine::Initialize(uint32_t currentVersion) {
    m_currentVersion = currentVersion;
    RawrRuntime::Get().Log(LogLevel::Info, "MigrationEngine initialized");
}

void MigrationEngine::Shutdown() {
    m_migrations.clear();
}

void MigrationEngine::RegisterMigration(uint32_t targetVersion, MigrationFn fn, const char* description) {
    std::lock_guard<std::mutex> lock(m_mutex);

    MigrationEntry entry;
    entry.targetVersion = targetVersion;
    entry.migrate = std::move(fn);
    entry.description = description ? description : "";

    m_migrations.push_back(entry);
    if (targetVersion > m_latestVersion) {
        m_latestVersion = targetVersion;
    }
}

bool MigrationEngine::RunPending(const char* stateData, size_t stateSize,
                                  char** outData, size_t* outSize) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!NeedsMigration()) {
        if (outData) *outData = nullptr;
        if (outSize) *outSize = 0;
        return true;
    }

    const char* currentState = stateData;
    size_t currentSize = stateSize;

    for (auto& migration : m_migrations) {
        if (migration.targetVersion > m_currentVersion) {
            char* newState = nullptr;
            size_t newSize = 0;

            if (!migration.migrate(currentState, &newState, &newSize)) {
                RawrRuntime::Get().Log(LogLevel::Error, "Migration failed");
                return false;
            }

            if (newState) {
                if (currentState != stateData) {
                    free(const_cast<char*>(currentState));
                }
                currentState = newState;
                currentSize = newSize;
            }

            m_currentVersion = migration.targetVersion;
            RawrRuntime::Get().Log(LogLevel::Info, "Migration applied");
        }
    }

    if (outData) {
        *outData = const_cast<char*>(currentState);
    }
    if (outSize) {
        *outSize = currentSize;
    }

    return true;
}

} // namespace rawr
