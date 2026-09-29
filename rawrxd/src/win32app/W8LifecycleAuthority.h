// W8LifecycleAuthority.h — RAWRXD_W8_LIFECYCLE_AUTHORITY_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace lifecycle {
void beginStayAliveCert(uint32_t durationSec);
void recordShutdownRequest(const char* reason);
void allowShutdown();
void writeW8Receipt(const std::string& path);
}} // namespace rawrxd::lifecycle