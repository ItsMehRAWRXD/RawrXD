#pragma once

namespace Sovereign {
namespace CrashRecovery {

/**
 * @brief Save runtime state for crash recovery
 */
void SaveState();

/**
 * @brief Load runtime state after crash
 */
void LoadState();

/**
 * @brief Check if saved state exists
 */
bool HasSavedState();

/**
 * @brief Clear saved state
 */
void ClearState();

} // namespace CrashRecovery
} // namespace Sovereign
