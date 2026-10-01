// ============================================================================
// flash_attention.cpp — FlashAttentionEngine implementation
// ============================================================================
// Wraps the AVX-512 ASM kernel with license gating, alignment checks,
// and diagnostic reporting.
//
// ASM Source:  src/asm/FlashAttention_AVX512.asm
// Header:     src/core/flash_attention.h
// License:    FEATURE_FLASH_ATTENTION (0x40) — Pro tier minimum
// ============================================================================

#include "flash_attention.h"
#include "enterprise_license.h"
#include <iostream>
#include <sstream>
#include <cstdint>

namespace RawrXD {

// ============================================================================
// FlashAttentionEngine::Initialize
// ============================================================================
bool FlashAttentionEngine::Initialize() {
    // Step 1: License gate — FEATURE_FLASH_ATTENTION (0x40)
    m_licensed = EnterpriseLicense::Instance().HasFeature(
        EnterpriseFeature::FlashAttention);

    if (!m_licensed) {
        std::cout << "[FlashAttention] License check FAILED — "
                  << "FEATURE_FLASH_ATTENTION (0x40) not enabled.\n"
                  << "[FlashAttention] Upgrade to Pro tier for Flash Attention.\n"
                  << "[FlashAttention] Current edition: "
                  << EnterpriseLicense::Instance().GetEditionName() << std::endl;
        m_ready = false;
        return false;
    }

    // Step 2: AVX-512 capability check (calls CPUID)
    //
    // FlashAttention_Init() performs a real CPUID/XGETBV probe (it used to
    // `return 1` unconditionally, which meant this branch was unreachable and
    // the engine claimed an AVX-512 kernel on hosts that had none).
    //
    // Note: the forward path is scalar C++ and does not require AVX-512. This
    // flag currently gates readiness reporting only; it is not a correctness
    // precondition for the math.
    int32_t avxResult = FlashAttention_Init();
    m_hasAVX512 = (avxResult == 1);

    if (!m_hasAVX512) {
        std::cout << "[FlashAttention] Host lacks AVX-512F+DQ+BW+VL (or the OS "
                     "is not preserving ZMM state).\n"
                  << "[FlashAttention] Running the portable scalar reference "
                     "path; AVX-512 kernel is unavailable.\n";
        m_ready = true;
        m_scalarFallback = true;
    }

    // Step 3: Report tile configuration (loop-tile parameters, not a
    // measurement of a compiled AVX-512 kernel -- see the definition).
    FlashAttentionTileConfig tileCfg = GetTileConfig();
    if (m_hasAVX512) {
        std::cout << "[FlashAttention] AVX-512 host detected (F+DQ+BW+VL, ZMM "
                     "state enabled).\n";
    } else {
        std::cout << "[FlashAttention] Scalar reference path.\n";
    }
    std::cout << "  Tile M:         " << tileCfg.tileM << "\n"
              << "  Tile N:         " << tileCfg.tileN << "\n"
              << "  Head Dim:       " << tileCfg.headDim << "\n"
              << "  Scratch bytes:  " << tileCfg.scratchBytes << "\n"
              << "  License:        Pro tier (0x40)" << std::endl;

    m_ready = true;
    return true;
}

// ============================================================================
// FlashAttentionEngine::Forward
// ============================================================================
int32_t FlashAttentionEngine::Forward(FlashAttentionConfig& cfg) {
    if (!m_ready) {
        std::cerr << "[FlashAttention] Forward called but engine not ready. "
                  << "Call Initialize() first." << std::endl;
        return -2;
    }

// Validate pointer alignment.
    // The original check demanded 64 bytes and justified it with "ZMM requires
    // 64-byte alignment". The forward path is scalar C++ reading floats, so the
    // real requirement is natural float alignment; demanding 64 rejected
    // otherwise-valid configs for no reason.
    if (!ValidateAlignment(cfg)) {
        std::cerr << "[FlashAttention] ERROR: Q/K/V/O pointers are not "
                     "naturally aligned. Use an aligned allocator." << std::endl;
        return -3;
    }

    // Validate dimensions
    if (cfg.seqLenM <= 0 || cfg.seqLenN <= 0 || cfg.headDim <= 0 ||
        cfg.numHeads <= 0 || cfg.numKVHeads <= 0 || cfg.batchSize <= 0) {
        std::cerr << "[FlashAttention] ERROR: Invalid dimensions in config."
                  << std::endl;
        return -4;
    }

    // No headDim % 16 constraint: the scalar dot-product loop walks headDim
    // elements at unit stride. That rejection existed only to satisfy a ZMM
    // kernel this code does not contain.

    // Validate GQA: numHeads must be divisible by numKVHeads
    if (cfg.numHeads % cfg.numKVHeads != 0) {
        std::cerr << "[FlashAttention] ERROR: numHeads (" << cfg.numHeads
                  << ") must be divisible by numKVHeads (" << cfg.numKVHeads
                  << ") for GQA." << std::endl;
        return -6;
    }

    // Auto-compute scale if not set
    if (cfg.scale <= 0.0f || cfg.scale > 1.0f) {
        cfg.ComputeScale();
    }

    // Dispatch to ASM kernel
    return FlashAttention_Forward(&cfg);
}

// ============================================================================
// FlashAttentionEngine::GetTileConfig
// ============================================================================
FlashAttentionTileConfig FlashAttentionEngine::GetTileConfig() const {
    FlashAttentionTileConfig out = {};
    FlashAttention_GetTileConfig(&out);
    return out;
}

// ============================================================================
// FlashAttentionEngine::GetStatusString
// ============================================================================
std::string FlashAttentionEngine::GetStatusString() const {
    std::ostringstream ss;
    ss << "FlashAttention AVX-512 Engine Status:\n"
       << "  Ready:     " << (m_ready     ? "YES" : "NO") << "\n"
       << "  AVX-512:   " << (m_hasAVX512 ? "YES" : "NO") << "\n"
       << "  Licensed:  " << (m_licensed  ? "YES" : "NO") << "\n"
       << "  Calls:     " << g_FlashAttnCalls << "\n"
       << "  Tiles:     " << g_FlashAttnTiles;

    if (m_ready) {
        FlashAttentionTileConfig tc = {};
        FlashAttention_GetTileConfig(&tc);
        ss << "\n  TileM:     " << tc.tileM
           << "\n  TileN:     " << tc.tileN
           << "\n  HeadDim:   " << tc.headDim
           << "\n  Scratch:   " << tc.scratchBytes << " bytes";
    }

    return ss.str();
}

// ============================================================================
// FlashAttentionEngine::ValidateAlignment
// ============================================================================
bool FlashAttentionEngine::ValidateAlignment(const FlashAttentionConfig& cfg) {
    // Natural alignment for float. This was 63 (64-byte) with the rationale
    // "ZMM requires 64-byte alignment", but the forward pass contains no ZMM
    // operands -- it is scalar C++ reading floats -- so the 64-byte demand
    // rejected valid configs without cause. If an AVX-512 kernel is ever added
    // this should become a tiered check: 64 bytes only on that path.
    constexpr uintptr_t ALIGN_MASK = sizeof(float) - 1;
    if (reinterpret_cast<uintptr_t>(cfg.Q) & ALIGN_MASK) return false;
    if (reinterpret_cast<uintptr_t>(cfg.K) & ALIGN_MASK) return false;
    if (reinterpret_cast<uintptr_t>(cfg.V) & ALIGN_MASK) return false;
    if (reinterpret_cast<uintptr_t>(cfg.O) & ALIGN_MASK) return false;
    return true;
}

} // namespace RawrXD
