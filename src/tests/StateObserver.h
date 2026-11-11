#pragma once

#include <atomic>
#include <string>
#include <vector>
#include <mutex>

namespace RawrXD::E2E {

/**
 * @brief Monitors atomic adapter swaps for race conditions
 * 
 * Phase 19: Validates integrity of shadow buffer pattern
 */
class StateObserver {
public:
    /**
     * @brief Called when adapter swap occurs
     * @param old_id Previous adapter ID
     * @param new_id New adapter ID
     */
    static void OnAdapterSwap(const std::string& old_id, const std::string& new_id);
    
    /**
     * @brief Verify no race conditions occurred
     * @return true if integrity maintained
     */
    static bool VerifyAtomicIntegrity();
    
    /**
     * @brief Get total swap count
     */
    static uint64_t GetSwapCount() { return m_swap_count.load(); }
    
    /**
     * @brief Reset observer state
     */
    static void Reset();

private:
    static std::atomic<uint64_t> m_swap_count;
    static std::vector<std::pair<std::string, std::string>> m_swap_history;
    static std::mutex m_history_mutex;
    static std::atomic<bool> m_integrity_violation;
};

} // namespace RawrXD::E2E
