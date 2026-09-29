// StrictCertificationAuthority.h — RAWRXD_STRICT_CERTIFICATION_AUTHORITY_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace cert {
bool checkSourceGraphTruth();
bool checkRealLink();
bool checkW8();
bool checkChatE2E();
bool checkGpuCorrectness();
void writeStrictCertReceipt(const std::string& path);
}} // namespace rawrxd::cert