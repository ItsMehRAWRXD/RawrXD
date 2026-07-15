#pragma once
#include <string>

namespace Sovereign {
namespace IntegrityChecker {

/**
 * @brief Validate model file integrity
 * @param path Path to model file
 * @return true if valid
 */
bool ValidateModel(const std::wstring& path);

/**
 * @brief Validate executable sections
 * @param exePath Path to executable
 * @return true if valid
 */
bool ValidateSections(const std::wstring& exePath);

/**
 * @brief Compute simple hash of file
 * @param path File path
 * @return 64-bit hash
 */
uint64_t ComputeFileHash(const std::wstring& path);

} // namespace IntegrityChecker
} // namespace Sovereign
