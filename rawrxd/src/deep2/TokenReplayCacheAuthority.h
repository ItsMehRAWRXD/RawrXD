// TokenReplayCacheAuthority.h — RAWRXD_TOKEN_REPLAY_CACHE_AUTHORITY_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace cache {
bool lookupPromptPrefix(const std::string& prompt);
bool lookupKvPrefix(const std::string& kvKey);
bool lookupDeterministicOutput(const std::string& prompt);
void recordReplayHit(uint32_t count);
void writeReplayReceipt(const std::string& path);
}} // namespace rawrxd::cache