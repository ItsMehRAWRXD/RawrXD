#pragma once
#include <cstdint>

namespace rawrxd { namespace masm {

bool MASMCathedral_ApplySignature(const uint8_t* data, size_t len, uint32_t flags);
bool MASMCathedral_Verify(const uint8_t* data, size_t len);

}} // namespace rawrxd::masm
