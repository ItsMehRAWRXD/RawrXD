#pragma once
#include <cstdint>

namespace Sovereign {
namespace StressTester {

/**
 * @brief Run synthetic long-context stress test
 * @param tokens Number of tokens to generate (1M-8M)
 */
void RunSyntheticSequence(uint64_t tokens);

/**
 * @brief Run full long-context test suite
 */
void RunFullLongContextTest();

/**
 * @brief Validate KV tiering under load
 */
bool ValidateKVTiering();

/**
 * @brief Validate MoE routing under load
 */
bool ValidateMoERouting();

/**
 * @brief Validate NVMe async paging
 */
bool ValidateNVMePaging();

} // namespace StressTester
} // namespace Sovereign
