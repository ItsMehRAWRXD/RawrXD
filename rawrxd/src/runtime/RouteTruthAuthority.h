// RouteTruthAuthority.h — RAWRXD_ROUTE_TRUTH_AUTHORITY_001
// Proves whether CPU/GPU/scalar/AVX/Vulkan path actually ran.
#pragma once
#include <string>
#include <cstdint>

namespace rawrxd { namespace route {

void recordRequested(const std::string& route);
void recordActual(const std::string& route);
void recordFallback(const std::string& fromRoute, const std::string& toRoute);
int getFallbackCount();
int getUnplannedFallbackCount();
void writeRouteTruthReceipt(const std::string& path);

}} // namespace rawrxd::route