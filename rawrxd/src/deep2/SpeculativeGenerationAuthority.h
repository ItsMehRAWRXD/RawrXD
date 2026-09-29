// SpeculativeGenerationAuthority.h — RAWRXD_SPECULATIVE_GENERATION_AUTHORITY_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace spec {
void buildDraft();
void verifyDraft();
void acceptTokens(uint32_t count);
void rejectTokens(uint32_t count);
void writeSpecReceipt(const std::string& path);
}} // namespace rawrxd::spec