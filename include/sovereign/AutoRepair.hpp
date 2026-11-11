#pragma once
#include "HealthReport.hpp"

namespace Sovereign {
namespace AutoRepair {

/**
 * @brief Attempt automatic repair based on health state
 * @param health Current sovereign health snapshot
 */
void TryRepair(const SovereignHealth& health);

/**
 * @brief Check if repair is needed
 * @param health Current health snapshot
 * @return true if any subsystem is not Ok
 */
bool NeedsRepair(const SovereignHealth& health);

/**
 * @brief Get last repair result message
 */
const char* GetLastRepairMessage();

/**
 * @brief Get repair attempt count
 */
uint32_t GetRepairCount();

} // namespace AutoRepair
} // namespace Sovereign
