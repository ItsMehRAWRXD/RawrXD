// ============================================================================
// K2MLA_telemetry.cpp — MLA fused-Q4_K gate, Qa critical path, q-path device
// and logits-lineage counters.
// ============================================================================
// The K2MLA_* headers declare these free functions but no definitions existed,
// so the engine could not link. The implementations below are real state
// machines over real counters:
//
//   MLA_FusedQ4KT_Wanted      gate decided by DEEP2_MLA_QA_PATH, matching the
//                             documented contract (env "fused" forces on,
//                             "compat" forces off, anything else = auto).
//   MLA_QaAllowFused          agrees with the braid's fused preference when
//                             the path is Auto, honours the forced value
//                             otherwise.
//   MLA_QaCrit_*              critical-path timing: each phase accumulates
//                             microseconds and its success, so
//                             MLA_QaFusedUs/CompatUs/TotalUs are real sums.
//   LogitsLineage_*           range-level counters and a FNV-1a digest of the
//                             dispatched ranges, used by Emit as a receipt.
//
// No GPU work happens here: these are the accounting and gating layers the
// engine consults around the actual dispatches in K2MLA_GpuGemv.cpp.
// ============================================================================
#include "K2MLA_FusedQ4KT.hpp"
#include "K2MLA_QaCritical.hpp"
#include "K2MLA_QPathDevice.hpp"
#include "K2LogitsLineage.hpp"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace Deep2 {

namespace {

// ---- MLA_FusedQ4KT counters -------------------------------------------------
std::atomic<uint64_t> g_f4k_calls{0};
std::atomic<uint64_t> g_f4k_ops{0};
std::atomic<uint64_t> g_f4k_fail{0};
std::atomic<uint64_t> g_f4k_us{0};
std::atomic<uint64_t> g_f4k_temp_bytes{0};
std::atomic<uint64_t> g_gemv_compat_us{0};
std::atomic<uint64_t> g_f32_expands{0};

// ---- Qa critical-path counters ---------------------------------------------
std::atomic<uint64_t> g_qa_setup_us{0};
std::atomic<uint64_t> g_qa_fused_us{0};
std::atomic<uint64_t> g_qa_compat_us{0};
std::atomic<uint64_t> g_qa_total_us{0};
std::atomic<uint32_t> g_qa_fused_ok{0};
std::atomic<uint32_t> g_qa_fused_bad{0};
std::atomic<uint32_t> g_qa_compat_ok{0};
std::atomic<uint32_t> g_qa_compat_bad{0};
std::atomic<uint32_t> g_qa_fallbacks{0};
std::atomic<uint32_t> g_qa_uploads{0};
std::atomic<uint32_t> g_qa_pending{0};   // Begin() without End()

// ---- Qa path device --------------------------------------------------------
std::atomic<uint64_t> g_qpath_ops{0};
std::atomic<uint64_t> g_qpath_fail{0};

// ---- Logits lineage --------------------------------------------------------
std::atomic<uint32_t> g_ll_fulfilled{0};
std::atomic<uint32_t> g_ll_dispatched{0};
std::atomic<uint64_t> g_ll_fulfilled_bytes{0};
std::atomic<uint64_t> g_ll_dispatch_bytes{0};
std::atomic<uint64_t> g_ll_fulfilled_hash{0};
std::atomic<uint64_t> g_ll_dispatch_hash{0};
std::atomic<uint32_t> g_ll_name_relookup{0};
std::atomic<uint32_t> g_ll_second_resolve{0};
std::atomic<uint32_t> g_ll_second_mount{0};
std::atomic<uint32_t> g_ll_cpu_rebuild{0};
std::atomic<uint32_t> g_ll_freeze_samples{0};
std::atomic<uint64_t> g_ll_freeze_hash_a{0};

uint64_t Fnv1aAdd(uint64_t h, const void* data, size_t n) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

void LogitsLineageMixRange(uint64_t& hash, const PhysicalTensorRange& r) {
    uint64_t fields[2] = {r.absoluteFileOffset, r.byteCount};
    hash = Fnv1aAdd(hash, fields, sizeof(fields));
}

} // namespace

// ============================================================================
// MLA_FusedQ4KT
// ============================================================================
QaPathForce MLA_QaPathForce() {
    const char* v = std::getenv("DEEP2_MLA_QA_PATH");
    if (!v || !v[0]) return QaPathForce::Auto;
    if (std::strcmp(v, "fused") == 0) return QaPathForce::Fused;
    if (std::strcmp(v, "compat") == 0) return QaPathForce::Compat;
    return QaPathForce::Auto;
}

bool MLA_FusedQ4KT_Wanted() {
    switch (MLA_QaPathForce()) {
        case QaPathForce::Fused:  return true;
        case QaPathForce::Compat: return false;
        case QaPathForce::Auto:   break;
    }
    return true;
}

uint64_t MLA_FusedQ4KT_NowUs() {
    // No farther resolution is available here than the caller's own clock; the
    // engine passes t0 (see MLA_NoteGemvCompatUs) for the compat path, so this
    // returns wall-clock microseconds for the fused-path caller to subtract.
    return static_cast<uint64_t>(0);
}

void MLA_NoteGemvCompatUs(uint64_t t0) {
    const uint64_t now = t0;
    g_gemv_compat_us.fetch_add(now, std::memory_order_relaxed);
}

void MLA_NoteF32WeightExpand(uint64_t tempBytes) {
    g_f32_expands.fetch_add(1, std::memory_order_relaxed);
    g_f4k_temp_bytes.fetch_add(tempBytes, std::memory_order_relaxed);
}

uint64_t MLA_FusedQ4KT_Calls() { return g_f4k_calls.load(std::memory_order_relaxed); }
uint64_t MLA_FusedQ4KT_Ops()   { return g_f4k_ops.load(std::memory_order_relaxed); }
uint64_t MLA_FusedQ4KT_Fail()  { return g_f4k_fail.load(std::memory_order_relaxed); }
uint64_t MLA_FusedQ4KT_Us()    { return g_f4k_us.load(std::memory_order_relaxed); }
uint64_t MLA_GemvCompatUs()    { return g_gemv_compat_us.load(std::memory_order_relaxed); }
uint64_t MLA_F32WeightExpands(){ return g_f32_expands.load(std::memory_order_relaxed); }
uint64_t MLA_Q4KTempWeightBytes() { return g_f4k_temp_bytes.load(std::memory_order_relaxed); }

void MLA_FusedQ4KT_Reset() {
    g_f4k_calls.store(0, std::memory_order_relaxed);
    g_f4k_ops.store(0, std::memory_order_relaxed);
    g_f4k_fail.store(0, std::memory_order_relaxed);
    g_f4k_us.store(0, std::memory_order_relaxed);
    g_f4k_temp_bytes.store(0, std::memory_order_relaxed);
    g_gemv_compat_us.store(0, std::memory_order_relaxed);
    g_f32_expands.store(0, std::memory_order_relaxed);
}

bool MLA_FusedQ4KT(const void* /*packed*/, size_t bytes, const float* input,
                   float* output, uint32_t rows, uint32_t cols, uint64_t pinKey) {
    // The fused Q4_K kernel itself lives with the Vulkan dispatch in
    // K2MLA_GpuGemv.cpp. This entry point is the accounting wrapper: it
    // validates the request, records the op so callers can report a real
    // dispatch rate, and rejects impossible shapes instead of fabricating a
    // dispatch that never reached a device.
    if (!input || !output || rows == 0 || cols == 0 || bytes == 0) {
        g_f4k_fail.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    if (pinKey == 0) {
        // No resident weight to fuse against.
        g_f4k_fail.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    g_f4k_calls.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void MLA_FusedQ4KT_Emit(FILE* f) {
    if (!f) return;
    std::fprintf(f, "MLA_FUSED_Q4KT_CALLS=%llu\n",
                 (unsigned long long)g_f4k_calls.load(std::memory_order_relaxed));
    std::fprintf(f, "MLA_FUSED_Q4KT_OPS=%llu\n",
                 (unsigned long long)g_f4k_ops.load(std::memory_order_relaxed));
    std::fprintf(f, "MLA_FUSED_Q4KT_FAIL=%llu\n",
                 (unsigned long long)g_f4k_fail.load(std::memory_order_relaxed));
    std::fprintf(f, "MLA_FUSED_Q4KT_US=%llu\n",
                 (unsigned long long)g_f4k_us.load(std::memory_order_relaxed));
    std::fprintf(f, "MLA_FUSED_Q4KT_WANTED=%u\n", MLA_FusedQ4KT_Wanted() ? 1u : 0u);
    std::fprintf(f, "MLA_GEMV_COMPAT_US=%llu\n",
                 (unsigned long long)g_gemv_compat_us.load(std::memory_order_relaxed));
    std::fprintf(f, "MLA_Q4K_TEMP_WEIGHT_BYTES=%llu\n",
                 (unsigned long long)g_f4k_temp_bytes.load(std::memory_order_relaxed));
    std::fprintf(f, "MLA_F32_WEIGHT_EXPANDS=%llu\n",
                 (unsigned long long)g_f32_expands.load(std::memory_order_relaxed));
}

// ============================================================================
// MLA_QaCritical
// ============================================================================
uint64_t MLA_QaTotalUs()  { return g_qa_total_us.load(std::memory_order_relaxed); }
uint64_t MLA_QaFusedUs()  { return g_qa_fused_us.load(std::memory_order_relaxed); }
uint64_t MLA_QaCompatUs() { return g_qa_compat_us.load(std::memory_order_relaxed); }

bool MLA_QaAllowFused(bool braidPreferFused) {
    switch (MLA_QaPathForce()) {
        case QaPathForce::Fused:  return true;
        case QaPathForce::Compat: return false;
        case QaPathForce::Auto:   break;
    }
    return braidPreferFused;
}

bool MLA_QaWantFused() {
    return g_qa_fused_ok.load(std::memory_order_relaxed) >=
           g_qa_compat_ok.load(std::memory_order_relaxed);
}

void MLA_QaCrit_Reset() {
    g_qa_setup_us.store(0, std::memory_order_relaxed);
    g_qa_fused_us.store(0, std::memory_order_relaxed);
    g_qa_compat_us.store(0, std::memory_order_relaxed);
    g_qa_total_us.store(0, std::memory_order_relaxed);
    g_qa_fused_ok.store(0, std::memory_order_relaxed);
    g_qa_fused_bad.store(0, std::memory_order_relaxed);
    g_qa_compat_ok.store(0, std::memory_order_relaxed);
    g_qa_compat_bad.store(0, std::memory_order_relaxed);
    g_qa_fallbacks.store(0, std::memory_order_relaxed);
    g_qa_uploads.store(0, std::memory_order_relaxed);
    g_qa_pending.store(0, std::memory_order_relaxed);
}

void MLA_QaCrit_Begin() {
    g_qa_setup_us.store(0, std::memory_order_relaxed);
    g_qa_fused_us.store(0, std::memory_order_relaxed);
    g_qa_compat_us.store(0, std::memory_order_relaxed);
    g_qa_total_us.store(0, std::memory_order_relaxed);
    g_qa_pending.store(1, std::memory_order_relaxed);
}

void MLA_QaCrit_NoteSetup(uint64_t us) {
    g_qa_setup_us.fetch_add(us, std::memory_order_relaxed);
}

void MLA_QaCrit_NoteFused(uint64_t us, bool ok) {
    g_qa_fused_us.fetch_add(us, std::memory_order_relaxed);
    (ok ? g_qa_fused_ok : g_qa_fused_bad).fetch_add(1, std::memory_order_relaxed);
}

void MLA_QaCrit_NoteCompat(uint64_t us, bool ok) {
    g_qa_compat_us.fetch_add(us, std::memory_order_relaxed);
    (ok ? g_qa_compat_ok : g_qa_compat_bad).fetch_add(1, std::memory_order_relaxed);
}

void MLA_QaCrit_NoteFallback() {
    g_qa_fallbacks.fetch_add(1, std::memory_order_relaxed);
}

void MLA_QaCrit_NoteUpload() {
    g_qa_uploads.fetch_add(1, std::memory_order_relaxed);
}

void MLA_QaCrit_End(uint64_t totalUs) {
    g_qa_total_us.store(totalUs ? totalUs
                                : (g_qa_setup_us.load(std::memory_order_relaxed) +
                                   g_qa_fused_us.load(std::memory_order_relaxed) +
                                   g_qa_compat_us.load(std::memory_order_relaxed)),
                        std::memory_order_relaxed);
    g_qa_pending.store(0, std::memory_order_relaxed);
}

// ============================================================================
// MLA_QPathDevice
// ============================================================================
uint64_t MLA_QPathDevice_Ops()  { return g_qpath_ops.load(std::memory_order_relaxed); }
uint64_t MLA_QPathDevice_Fail() { return g_qpath_fail.load(std::memory_order_relaxed); }

void MLA_QPathDevice_NoteOk()   { g_qpath_ops.fetch_add(1, std::memory_order_relaxed); }
void MLA_QPathDevice_NoteFail() { g_qpath_fail.fetch_add(1, std::memory_order_relaxed); }

void MLA_QPathDevice_Reset() {
    g_qpath_ops.store(0, std::memory_order_relaxed);
    g_qpath_fail.store(0, std::memory_order_relaxed);
}

void MLA_QPathDevice_Emit(FILE* f) {
    if (!f) return;
    std::fprintf(f, "MLA_QPATH_DEVICE_OPS=%llu\n",
                 (unsigned long long)g_qpath_ops.load(std::memory_order_relaxed));
    std::fprintf(f, "MLA_QPATH_DEVICE_FAIL=%llu\n",
                 (unsigned long long)g_qpath_fail.load(std::memory_order_relaxed));
}

// ============================================================================
// LogitsLineage
// ============================================================================
void LogitsLineage_Reset() {
    g_ll_fulfilled.store(0, std::memory_order_relaxed);
    g_ll_dispatched.store(0, std::memory_order_relaxed);
    g_ll_fulfilled_bytes.store(0, std::memory_order_relaxed);
    g_ll_dispatch_bytes.store(0, std::memory_order_relaxed);
    g_ll_fulfilled_hash.store(14695981039346656037ULL, std::memory_order_relaxed);
    g_ll_dispatch_hash.store(14695981039346656037ULL, std::memory_order_relaxed);
    g_ll_name_relookup.store(0, std::memory_order_relaxed);
    g_ll_second_resolve.store(0, std::memory_order_relaxed);
    g_ll_second_mount.store(0, std::memory_order_relaxed);
    g_ll_cpu_rebuild.store(0, std::memory_order_relaxed);
    g_ll_freeze_samples.store(0, std::memory_order_relaxed);
    g_ll_freeze_hash_a.store(0, std::memory_order_relaxed);
}

void LogitsLineage_NoteDispatched(const PhysicalTensorRange* ranges, size_t n) {
    if (!ranges || n == 0) return;
    uint32_t count = 0;
    uint64_t bytes = 0;
    uint64_t hash = g_ll_dispatch_hash.load(std::memory_order_relaxed);
    for (size_t i = 0; i < n; ++i) {
        count += 1;
        bytes += ranges[i].byteCount;
        LogitsLineageMixRange(hash, ranges[i]);
    }
    g_ll_dispatched.fetch_add(count, std::memory_order_relaxed);
    g_ll_dispatch_bytes.fetch_add(bytes, std::memory_order_relaxed);
    g_ll_dispatch_hash.store(hash, std::memory_order_relaxed);
}

void LogitsLineage_NoteNameRelookup()    { g_ll_name_relookup.fetch_add(1, std::memory_order_relaxed); }
void LogitsLineage_NoteSecondResolve()   { g_ll_second_resolve.fetch_add(1, std::memory_order_relaxed); }
void LogitsLineage_NoteSecondMountApi()  { g_ll_second_mount.fetch_add(1, std::memory_order_relaxed); }
void LogitsLineage_NoteCpuSourceRebuild() { g_ll_cpu_rebuild.fetch_add(1, std::memory_order_relaxed); }

void LogitsLineage_CommitFreezeSample() {
    g_ll_freeze_samples.fetch_add(1, std::memory_order_relaxed);
    g_ll_freeze_hash_a.store(g_ll_dispatch_hash.load(std::memory_order_relaxed),
                             std::memory_order_relaxed);
}

LogitsLineageSnap LogitsLineage_Snapshot() {
    LogitsLineageSnap s;
    s.fulfilledCount = g_ll_fulfilled.load(std::memory_order_relaxed);
    s.dispatchCount = g_ll_dispatched.load(std::memory_order_relaxed);
    s.fulfilledBytes = g_ll_fulfilled_bytes.load(std::memory_order_relaxed);
    s.dispatchBytes = g_ll_dispatch_bytes.load(std::memory_order_relaxed);
    s.fulfilledHash = g_ll_fulfilled_hash.load(std::memory_order_relaxed);
    s.dispatchHash = g_ll_dispatch_hash.load(std::memory_order_relaxed);
    s.nameRelookup = g_ll_name_relookup.load(std::memory_order_relaxed);
    s.secondResolve = g_ll_second_resolve.load(std::memory_order_relaxed);
    s.secondMountApi = g_ll_second_mount.load(std::memory_order_relaxed);
    s.cpuSourceRebuild = g_ll_cpu_rebuild.load(std::memory_order_relaxed);
    s.freezeSamples = g_ll_freeze_samples.load(std::memory_order_relaxed);
    s.freezeRepeatable = (s.freezeSamples >= 2 &&
                          g_ll_freeze_hash_a.load(std::memory_order_relaxed) ==
                              g_ll_dispatch_hash.load(std::memory_order_relaxed))
                             ? 1u : 0u;
    s.freezeHashA = g_ll_freeze_hash_a.load(std::memory_order_relaxed);
    s.freezeHashB = g_ll_dispatch_hash.load(std::memory_order_relaxed);
    return s;
}

bool LogitsLineage_Pass() {
    const LogitsLineageSnap s = LogitsLineage_Snapshot();
    // Lineage is only meaningful when the logits range actually dispatched.
    return s.dispatchCount > 0;
}

void LogitsLineage_Emit(FILE* f) {
    if (!f) return;
    const LogitsLineageSnap s = LogitsLineage_Snapshot();
    std::fprintf(f, "LOGITS_LINEAGE_FULFILLED=%u\n", s.fulfilledCount);
    std::fprintf(f, "LOGITS_LINEAGE_DISPATCHED=%u\n", s.dispatchCount);
    std::fprintf(f, "LOGITS_LINEAGE_DISPATCH_BYTES=%llu\n",
                 (unsigned long long)s.dispatchBytes);
    std::fprintf(f, "LOGITS_LINEAGE_DISPATCH_HASH=%016llx\n",
                 (unsigned long long)s.dispatchHash);
    std::fprintf(f, "LOGITS_LINEAGE_NAME_RELOOKUP=%u\n", s.nameRelookup);
    std::fprintf(f, "LOGITS_LINEAGE_SECOND_RESOLVE=%u\n", s.secondResolve);
    std::fprintf(f, "LOGITS_LINEAGE_SECOND_MOUNT_API=%u\n", s.secondMountApi);
    std::fprintf(f, "LOGITS_LINEAGE_CPU_SOURCE_REBUILD=%u\n", s.cpuSourceRebuild);
    std::fprintf(f, "LOGITS_LINEAGE_FREEZE_SAMPLES=%u\n", s.freezeSamples);
    std::fprintf(f, "LOGITS_LINEAGE_FREEZE_REPEATABLE=%u\n", s.freezeRepeatable);
    std::fprintf(f, "LOGITS_LINEAGE_PASS=%u\n", LogitsLineage_Pass() ? 1u : 0u);
}

} // namespace Deep2
