// ContextCrystallizationAuthority.h — RAWRXD_CONTEXT_CRYSTALLIZATION_AUTHORITY_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace context {
void crystallize(const std::string& contextId);
bool reuseCrystallizedSlice(const std::string& contextId);
void writeCrystallizationReceipt(const std::string& path);
}} // namespace rawrxd::context