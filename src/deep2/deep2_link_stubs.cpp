// ============================================================================
// deep2_link_stubs.cpp — Honest stubs for symbols NOT provided by real TUs
//
// Philosophy: Only define what is genuinely missing. If a real TU exists in
// the target, do NOT redefine its symbols here — that causes LNK2005.
// ============================================================================

#include <cstring>
#include <vector>
#include <functional>
#include <memory>
#include <unordered_map>
#include <filesystem>
#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>

namespace Deep2 {

// All GEMV kernels now have real ASM implementations in src/deep2/sovereign_*.asm.
// This file intentionally left empty to avoid LNK2005 duplicate symbol errors.

} // namespace Deep2
