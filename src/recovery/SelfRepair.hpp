// ============================================================================
// SelfRepair.hpp — Native Self-Healing Manager
// Detects issues and auto-repairs
// ============================================================================

#ifndef SELF_REPAIR_HPP
#define SELF_REPAIR_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <mutex>

namespace rawr {

// ============================================================================
// Repair Action
// ============================================================================
struct RepairAction {
    std::string description;
    bool (*repair)();
    uint32_t priority;
};

// ============================================================================
// SelfRepair — Autonomous repair manager
// ============================================================================
class SelfRepair {
public:
    static SelfRepair& Get();

    void Initialize();
    void Shutdown();

    void RegisterRepair(const char* description, bool (*repair)(), uint32_t priority = 0);

    // Run all registered repairs
    uint32_t RunAll();

    // Run repairs matching a category
    uint32_t RunCategory(const char* category);

    // Check system health
    bool HealthCheck();

    // Statistics
    uint32_t GetRepairCount() const { return static_cast<uint32_t>(m_repairs.size()); }
    uint32_t GetSuccessfulRepairs() const { return m_successful; }
    uint32_t GetFailedRepairs() const { return m_failed; }

private:
    SelfRepair() = default;
    ~SelfRepair() = default;
    SelfRepair(const SelfRepair&) = delete;
    SelfRepair& operator=(const SelfRepair&) = delete;

    std::vector<RepairAction> m_repairs;
    uint32_t m_successful = 0;
    uint32_t m_failed = 0;
    mutable std::mutex m_mutex;
};

} // namespace rawr

#endif // SELF_REPAIR_HPP
