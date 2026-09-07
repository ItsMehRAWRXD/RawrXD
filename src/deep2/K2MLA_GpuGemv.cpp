// K2MLA_GpuGemv.cpp — GPU Q4_K+Q8_0, then GetGEMV (shared CPU/GPU authority)
// LOCK: live callers MUST use MLA_Gemv — never MLA_TryGpuGemv (parity drift).
// Q4 path: MLA_Gemv → (FUSED_Q4KT|DispatchGEMVPacked) → GetGEMV fallback.
#include "K2MLA_GpuGemv.hpp"
#include "K2BraidExecutionPolicy.hpp"
#include "K2MLA_FusedQ4KT.hpp"
#include "K2MLA_QaCritical.hpp"
#include "K2MlaQBranchTiming.hpp"
#include "K2GpuStreamCopy.hpp"
#include "QuantKernelRegistry.hpp"
#include "vulkan_compute.h"
#include <atomic>
#include <cstring>
#include <cstdlib>
#include <mutex>

namespace Deep2 {
namespace {
std::mutex g_mu;
uint64_t g_ops = 0, g_fail = 0, g_skip = 0, g_attempts = 0;
uint64_t g_gemvEntry = 0, g_tryEntry = 0;
uint64_t g_upQ = 0, g_upK = 0, g_upV = 0, g_upO = 0;
uint64_t g_hitQ = 0, g_hitK = 0, g_hitV = 0, g_hitO = 0;
uint64_t g_keyNew = 0, g_keyReuse = 0;
uint64_t g_slotEvict = 0, g_metaUp = 0, g_weightUp = 0, g_pinKeyZero = 0;
std::atomic<uint64_t> g_pinKey{0}; // process-wide — no TLS (static-lib TLS drift)

size_t PackedNeed(int ty, uint32_t rows, uint32_t cols) {
    if (!rows || !cols) return 0;
    if (ty == 12) {
        if ((cols % 256u) != 0) return 0;
        return (size_t)rows * ((size_t)cols / 256u) * 144u;
    }
    if (ty == 8) {
        if ((cols % 32u) != 0) return 0;
        return (size_t)rows * ((size_t)cols / 32u) * 34u;
    }
    return 0;
}

void NoteFamily(uint8_t tag, bool uploaded, bool hit) {
    auto add = [&](uint64_t& u, uint64_t& h) {
        if (uploaded) ++u;
        if (hit) ++h;
    };
    switch (tag) {
    case 1: case 2: add(g_upQ, g_hitQ); break;
    case 3: case 4: add(g_upK, g_hitK); break;
    case 5:         add(g_upV, g_hitV); break;
    case 6:         add(g_upO, g_hitO); break;
    default: break;
    }
    if (uploaded) ++g_keyNew;
    if (hit) ++g_keyReuse;
}
} // namespace

bool MLA_GpuGemvWanted() {
    const char* e = std::getenv("DEEP2_K2_GPU_MLA");
    return e && e[0] == '1';
}

void MLA_GpuGemv_SetPinKey(uint64_t key) {
    g_pinKey.store(key, std::memory_order_relaxed);
}
void MLA_GpuGemv_Reset() {
    g_ops = g_fail = g_skip = g_attempts = 0;
    g_gemvEntry = g_tryEntry = 0;
    g_upQ = g_upK = g_upV = g_upO = 0;
    g_hitQ = g_hitK = g_hitV = g_hitO = 0;
    g_keyNew = g_keyReuse = 0;
    g_slotEvict = g_metaUp = g_weightUp = g_pinKeyZero = 0;
    MLA_FusedQ4KT_Reset();
    MLA_QaCrit_Reset();
}
uint64_t MLA_GpuGemvOps() { return g_ops; }
uint64_t MLA_GpuGemvFail() { return g_fail; }
uint64_t MLA_GpuGemvSkip() { return g_skip; }
uint64_t MLA_GemvEntries() { return g_gemvEntry; }
uint64_t MLA_TryGpuGemvEntries() { return g_tryEntry; }
uint64_t MLA_UploadQ() { return g_upQ; }
uint64_t MLA_UploadK() { return g_upK; }
uint64_t MLA_UploadV() { return g_upV; }
uint64_t MLA_UploadO() { return g_upO; }
uint64_t MLA_HitQ() { return g_hitQ; }
uint64_t MLA_HitK() { return g_hitK; }
uint64_t MLA_HitV() { return g_hitV; }
uint64_t MLA_HitO() { return g_hitO; }
uint64_t MLA_CacheKeyNew() { return g_keyNew; }
uint64_t MLA_CacheKeyReuse() { return g_keyReuse; }
uint64_t MLA_SlotEvict() { return g_slotEvict; }
uint64_t MLA_MetaUpload() { return g_metaUp; }
uint64_t MLA_WeightUpload() { return g_weightUp; }
uint64_t MLA_PinKeyZero() { return g_pinKeyZero; }

void MLA_GpuGemv_Emit(FILE* f) {
    if (!f) return;
    fprintf(f,
            "MLA_GPU_GEMV_OPS=%llu FAIL=%llu ATTEMPTS=%llu SKIP=%llu "
            "GEMV_ENTRY=%llu TRYGPU_ENTRY=%llu\n",
            (unsigned long long)g_ops, (unsigned long long)g_fail,
            (unsigned long long)g_attempts, (unsigned long long)g_skip,
            (unsigned long long)g_gemvEntry, (unsigned long long)g_tryEntry);
    fprintf(f,
            "MLA_UPLOAD_Q=%llu K=%llu V=%llu O=%llu "
            "MLA_HIT_Q=%llu K=%llu V=%llu O=%llu "
            "MLA_CACHEKEY_NEW=%llu REUSE=%llu "
            "MLA_SLOT_EVICT=%llu META_UP=%llu WEIGHT_UP=%llu PINKEY0=%llu\n",
            (unsigned long long)g_upQ, (unsigned long long)g_upK,
            (unsigned long long)g_upV, (unsigned long long)g_upO,
            (unsigned long long)g_hitQ, (unsigned long long)g_hitK,
            (unsigned long long)g_hitV, (unsigned long long)g_hitO,
            (unsigned long long)g_keyNew, (unsigned long long)g_keyReuse,
            (unsigned long long)g_slotEvict, (unsigned long long)g_metaUp,
            (unsigned long long)g_weightUp, (unsigned long long)g_pinKeyZero);
    MLA_FusedQ4KT_Emit(f);
    MLA_QaCrit_Emit(f);
}

static bool TryGpu(int ty, const void* packed, size_t bytes,
                   const float* input, float* output,
                   uint32_t rows, uint32_t cols,
                   const BraidExecutionPlan* braidPlan) {
    if (!MLA_GpuGemvWanted() || !packed || !input || !output) return false;
    if (ty != 12 && ty != 8) { ++g_skip; return false; }
    if (ty == 8) {
        const char* q4 = std::getenv("DEEP2_MLA_GPU_Q4_ONLY");
        if (q4 && q4[0] == '1') { ++g_skip; return false; }
    }
    ++g_attempts;
    const size_t need = PackedNeed(ty, rows, cols);
    if (!need) { ++g_skip; return false; }
    if (!bytes) bytes = need;
    if (bytes < need) { ++g_skip; return false; }
    auto* vc = K2GpuStreamCopy_Vc();
    if (!vc) { ++g_skip; return false; }
    const uint64_t tWait0 = MLA_FusedQ4KT_NowUs();
    std::lock_guard<std::mutex> lock(g_mu);
    const uint64_t waitUs = MLA_FusedQ4KT_NowUs() - tWait0;
    const uint64_t rej0 = vc->WeightPinRejects();
    const uint64_t up0 = vc->GemvWeightUploads();
    const uint64_t hit0 = vc->WeightContentHits();
    const uint64_t ev0 = vc->WeightPinEvicts();
    const uint64_t pk = g_pinKey.load(std::memory_order_relaxed);
    if (!pk) ++g_pinKeyZero;
    const uint8_t tag = (uint8_t)(pk & 0xffu);
    const bool isQa = (tag == 1);
    const uint64_t tCall0 = isQa ? MLA_FusedQ4KT_NowUs() : 0;
    if (isQa) {
        MLA_QaCrit_Begin();
        MLA_QaCrit_NoteSetup(waitUs);
    }

    bool ok = false;
    const bool braidFused = !braidPlan || braidPlan->preferFusedQ4KT;
    const bool allowFused =
        isQa ? MLA_QaAllowFused(braidFused) : braidFused;
    const bool wantFused =
        isQa ? MLA_QaWantFused() : MLA_FusedQ4KT_Wanted();

    const uint64_t tBody0 = MLA_FusedQ4KT_NowUs();
    if (ty == 12 && allowFused && wantFused) {
        const uint64_t t0 = MLA_FusedQ4KT_NowUs();
        ok = MLA_FusedQ4KT(packed, bytes, input, output, rows, cols, pk);
        if (isQa) MLA_QaCrit_NoteFused(MLA_FusedQ4KT_NowUs() - t0, ok);
    }
    if (!ok && ty == 12) {
        const uint64_t t0 = MLA_FusedQ4KT_NowUs();
        ok = vc->DispatchGEMVPacked(packed, bytes, input, output, rows, cols, pk);
        if (ok) MLA_NoteGemvCompatUs(t0);
        if (isQa) MLA_QaCrit_NoteCompat(MLA_FusedQ4KT_NowUs() - t0, ok);
    } else if (!ok) {
        ok = vc->DispatchGEMVQuant(ty, packed, bytes, input, output, rows, cols,
                                   pk);
    }
    const uint64_t bodyUs = MLA_FusedQ4KT_NowUs() - tBody0;
    if (!ok) {
        if (isQa) {
            MLA_QaCrit_NoteFallback();
            MLA_QaCrit_End(MLA_FusedQ4KT_NowUs() - tCall0);
        }
        if (vc->WeightPinRejects() > rej0) ++g_skip;
        else ++g_fail;
        return false;
    }
    const bool uploaded = vc->GemvWeightUploads() > up0;
    const bool hit = vc->WeightContentHits() > hit0;
    g_slotEvict += vc->WeightPinEvicts() - ev0;
    if (uploaded) ++g_weightUp;
    if (isQa && uploaded) MLA_QaCrit_NoteUpload();
    NoteFamily(tag, uploaded, hit);
    QBr_NoteLane(tag, waitUs, uploaded ? bodyUs : 0ull,
                 uploaded ? 0ull : bodyUs);
    if (isQa) MLA_QaCrit_End(MLA_FusedQ4KT_NowUs() - tCall0);
    ++g_ops;
    return true;
}

bool MLA_TryGpuGemv(int ggmlType, const void* packed, size_t bytes,
                    const float* input, float* output,
                    uint32_t rows, uint32_t cols) {
    ++g_tryEntry;
    return TryGpu(ggmlType, packed, bytes, input, output, rows, cols, nullptr);
}

// Map pinKey low byte to KernelRole for braid policy attribution.
static KernelRole PinKeyToRole(uint64_t pk) {
    switch (pk & 0xffu) {
        case 1: case 2: return KernelRole::Q_PROJ;
        case 3: case 4: return KernelRole::K_PROJ;
        case 5:         return KernelRole::V_PROJ;
        case 6:         return KernelRole::O_PROJ;
        default:        return KernelRole::UNKNOWN;
    }
}

bool MLA_Gemv(int ggmlType, const void* packed, size_t bytes,
              const float* input, float* output,
              uint32_t rows, uint32_t cols) {
    ++g_gemvEntry;
    (void)bytes;

    // -- Braid execution policy: plan + note for every GEMV call --
    // Authority sequence: MLA_Gemv entry -> Plan -> (packed exec | fallback).
    // PLAN != EXECUTED != PACKED_EXECUTED — a policy call cannot masquerade
    // as braid actually owning packed execution.
    K2Braid_NoteMlaGemvEntry();

    BraidExecutionPlan plan;
    BraidGGMLType braidType = BraidGGMLType::Q4_K;
    if (ggmlType == 8)  braidType = BraidGGMLType::Q8_0;
    else if (ggmlType == 14) braidType = BraidGGMLType::Q6_K;
    else if (ggmlType == 12) braidType = BraidGGMLType::Q4_K;
    else if (ggmlType == 0)  braidType = BraidGGMLType::F32;
    else if (ggmlType == 1)  braidType = BraidGGMLType::F16;
    const uint64_t pk = g_pinKey.load(std::memory_order_relaxed);
    const KernelRole role = PinKeyToRole(pk);
    const uint8_t laneTag = static_cast<uint8_t>(pk & 0xffu);
    K2Braid_PlanTagged(role, braidType, laneTag, plan);
    K2Braid_NotePlan(role);
    // If the format is not directly packable, flag it (should not happen
    // in the MLA hot path — Q4_K/Q8_0 are always direct packable).
    if (!K2Braid_IsDirectPackable(braidType) &&
        braidType != BraidGGMLType::F32 &&
        braidType != BraidGGMLType::F16) {
        K2Braid_NoteUnsupportedReinterpret();
    }

    if (TryGpu(ggmlType, packed, bytes, input, output, rows, cols, &plan)) {
        // Packed GPU GEMV succeeded — braid owns packed execution.
        K2Braid_NotePackedExec(role);
        K2Braid_NoteExecuted(role);
        return true;
    }
    if (!MLA_GpuGemvWanted()) return false;
    if (!packed || !input || !output || !rows || !cols) return false;
    auto gemv = QuantKernelRegistry::Instance().GetGEMV(ggmlType);
    if (!gemv) return false;
    // Only Q4_K GetGEMV implies decompressed-weight authority loss for #04.
    if (ggmlType == 12) {
        const uint64_t expandedBytes = (uint64_t)rows * (uint64_t)cols * 4ull;
        MLA_NoteF32WeightExpand(expandedBytes);
        // Braid invariant violation: GetGEMV fallback decompresses to F32.
        K2Braid_NoteF32Warehouse(expandedBytes);
    }
    std::memset(output, 0, (size_t)rows * sizeof(float));
    gemv(reinterpret_cast<const uint8_t*>(packed), input, output, rows, cols);
    if (laneTag == 1) MLA_QaCrit_NoteFallback();
    // Fallback executed (not packed) — preserve execution truth.
    K2Braid_NoteExecuted(role);
    return true;
}

bool MLA_GemvQ4K(const void* packed, size_t bytes,
                 const float* input, float* output,
                 uint32_t rows, uint32_t cols) {
    return MLA_Gemv(12, packed, bytes, input, output, rows, cols);
}

} // namespace Deep2
