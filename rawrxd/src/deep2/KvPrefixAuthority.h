// KvPrefixAuthority.h — RAWRXD_KV_PREFIX_AUTHORITY_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace kv {
std::string fingerprintPrefix(const std::string& prefix);
bool savePrefix(const std::string& key, const std::string& fingerprint);
bool restorePrefix(const std::string& key);
bool validatePrefix(const std::string& key, const std::string& expectedFingerprint);
void writeKvPrefixReceipt(const std::string& path);
}} // namespace rawrxd::kv