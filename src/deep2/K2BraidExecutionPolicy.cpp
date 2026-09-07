// K2BraidExecutionPolicy.cpp — transient braid policy implementation
#include "K2BraidExecutionPolicy.hpp"
#include <atomic>
#include <cstddef>
#include <cstring>
#include <mutex>

namespace Deep2 {
namespace {

std::mutex g_mu;
BraidCounters g_counters{};
std::atomic<uint64_t> g_sourceRewriteBytes{0};
std::atomic<uint64_t> g_f32WarehouseBytes{0};

// ---------------------------------------------------------------------------
// Tightened witness chain — one process-global state so the cert links the
// same atomics as the live MLA_Gemv route.
// ---------------------------------------------------------------------------
struct BraidWitnessState {
    std::atomic<uint64_t> mlaGemvEntries{0};
    std::atomic<uint64_t> planCount{0};
    std::atomic<uint64_t> execCount{0};
    std::atomic<uint64_t> packedExecCount{0};

    std::atomic<uint64_t> sourceRewriteBytes{0};
    std::atomic<uint64_t> f32WarehouseBytes{0};
    std::atomic<uint64_t> unsupportedReinterpret{0};
    std::atomic<uint64_t> persistedBraidBytes{0};

    std::atomic<uint64_t> rolePlans[K2_BRAID_ROLE_SLOTS]{};
    std::atomic<uint64_t> roleExecs[K2_BRAID_ROLE_SLOTS]{};
    std::atomic<uint64_t> rolePackedExecs[K2_BRAID_ROLE_SLOTS]{};
};

BraidWitnessState g_braidWitness;

static size_t RoleSlot(KernelRole role) noexcept {
    const size_t i = static_cast<size_t>(role);
    return i < K2_BRAID_ROLE_SLOTS ? i : (K2_BRAID_ROLE_SLOTS - 1);
}

static uint64_t Load(const std::atomic<uint64_t>& v) noexcept {
    return v.load(std::memory_order_relaxed);
}

} // namespace

void K2Braid_ResetWitnesses() {
    g_braidWitness.mlaGemvEntries.store(0, std::memory_order_relaxed);
    g_braidWitness.planCount.store(0, std::memory_order_relaxed);
    g_braidWitness.execCount.store(0, std::memory_order_relaxed);
    g_braidWitness.packedExecCount.store(0, std::memory_order_relaxed);

    g_braidWitness.sourceRewriteBytes.store(0, std::memory_order_relaxed);
    g_braidWitness.f32WarehouseBytes.store(0, std::memory_order_relaxed);
    g_braidWitness.unsupportedReinterpret.store(0, std::memory_order_relaxed);
    g_braidWitness.persistedBraidBytes.store(0, std::memory_order_relaxed);

    for (size_t i = 0; i < K2_BRAID_ROLE_SLOTS; ++i) {
        g_braidWitness.rolePlans[i].store(0, std::memory_order_relaxed);
        g_braidWitness.roleExecs[i].store(0, std::memory_order_relaxed);
        g_braidWitness.rolePackedExecs[i].store(0, std::memory_order_relaxed);
    }
}

void K2Braid_NoteMlaGemvEntry() {
    g_braidWitness.mlaGemvEntries.fetch_add(1, std::memory_order_relaxed);
}

void K2Braid_NotePlan(KernelRole role) {
    g_braidWitness.planCount.fetch_add(1, std::memory_order_relaxed);
    g_braidWitness.rolePlans[RoleSlot(role)].fetch_add(1, std::memory_order_relaxed);
}

void K2Braid_NoteExecuted(KernelRole role) {
    g_braidWitness.execCount.fetch_add(1, std::memory_order_relaxed);
    g_braidWitness.roleExecs[RoleSlot(role)].fetch_add(1, std::memory_order_relaxed);
}

void K2Braid_NotePackedExec(KernelRole role) {
    g_braidWitness.packedExecCount.fetch_add(1, std::memory_order_relaxed);
    g_braidWitness.rolePackedExecs[RoleSlot(role)].fetch_add(1, std::memory_order_relaxed);
}

void K2Braid_NoteSourceRewrite(uint64_t bytes) {
    g_braidWitness.sourceRewriteBytes.fetch_add(bytes, std::memory_order_relaxed);
}

void K2Braid_NoteF32Warehouse(uint64_t bytes) {
    g_braidWitness.f32WarehouseBytes.fetch_add(bytes, std::memory_order_relaxed);
}

void K2Braid_NoteUnsupportedReinterpret() {
    g_braidWitness.unsupportedReinterpret.fetch_add(1, std::memory_order_relaxed);
}

void K2Braid_NotePersistedBytes(uint64_t bytes) {
    g_braidWitness.persistedBraidBytes.fetch_add(bytes, std::memory_order_relaxed);
}

K2BraidWitnessSnapshot K2Braid_GetWitnessSnapshot() {
    K2BraidWitnessSnapshot s{};
    s.mlaGemvEntries = Load(g_braidWitness.mlaGemvEntries);
    s.planCount = Load(g_braidWitness.planCount);
    s.execCount = Load(g_braidWitness.execCount);
    s.packedExecCount = Load(g_braidWitness.packedExecCount);
    s.sourceRewriteBytes = Load(g_braidWitness.sourceRewriteBytes);
    s.f32WarehouseBytes = Load(g_braidWitness.f32WarehouseBytes);
    s.unsupportedReinterpret = Load(g_braidWitness.unsupportedReinterpret);
    s.persistedBraidBytes = Load(g_braidWitness.persistedBraidBytes);
    for (size_t i = 0; i < K2_BRAID_ROLE_SLOTS; ++i) {
        s.rolePlans[i] = Load(g_braidWitness.rolePlans[i]);
        s.roleExecs[i] = Load(g_braidWitness.roleExecs[i]);
        s.rolePackedExecs[i] = Load(g_braidWitness.rolePackedExecs[i]);
    }
    return s;
}

void K2Braid_Plan(KernelRole role, BraidGGMLType sourceFormat,
                  BraidExecutionPlan& out) {
    out.sourceFormat = sourceFormat;
    out.role = role;
    out.precision = BraidPrecision::BP8;  // native packed by default
    out.directPacked = true;
    out.f32Warehouse = false;
    // Correction lane only for aggressive approximation modes
    out.correctionEnabled = false;
    // BP1/BP2 would enable correction; BP8 = native, no correction needed
}

void K2Braid_NoteExecuted(const BraidExecutionPlan& plan) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_counters.plansIssued++;
    if (plan.directPacked) g_counters.directPacked++;
    if (plan.f32Warehouse) g_counters.f32Warehouse++;
    if (plan.correctionEnabled) g_counters.correctionLane++;
    switch (plan.role) {
        case KernelRole::Q_PROJ:  g_counters.roleQ++; break;
        case KernelRole::K_PROJ:  g_counters.roleK++; break;
        case KernelRole::V_PROJ:  g_counters.roleV++; break;
        case KernelRole::O_PROJ:  g_counters.roleO++; break;
        case KernelRole::FFN:     g_counters.roleFFN++; break;
        case KernelRole::EXPERT:  g_counters.roleExpert++; break;
        case KernelRole::LOGITS:  g_counters.roleLogits++; break;
        case KernelRole::EMBED:   g_counters.roleEmbed++; break;
        default: break;
    }
}

void K2Braid_ResetCounters() {
    std::lock_guard<std::mutex> lock(g_mu);
    g_counters = BraidCounters{};
    K2Braid_ResetWitnesses();
}

BraidCounters K2Braid_GetCounters() {
    std::lock_guard<std::mutex> lock(g_mu);
    BraidCounters c = g_counters;
    // Atomic bytes are read outside the counter struct
    return c;
}

void K2Braid_EmitCounters(FILE* f) {
    if (!f) f = stdout;
    std::lock_guard<std::mutex> lock(g_mu);
    fprintf(f,
        "BRAID_PLANS=%llu DIRECT_PACKED=%llu F32_WAREHOUSE=%llu\n"
        "BRAID_SOURCE_REWRITES=%llu SOURCE_REWRITE_BYTES=%llu\n"
        "BRAID_CORRECTION_LANE=%llu UNSUPPORTED_REINTERPRET=%llu\n"
        "BRAID_ROLE_Q=%llu K=%llu V=%llu O=%llu FFN=%llu EXPERT=%llu "
        "LOGITS=%llu EMBED=%llu\n"
        "BRAID_F32_WAREHOUSE_BYTES=%llu\n",
        (unsigned long long)g_counters.plansIssued,
        (unsigned long long)g_counters.directPacked,
        (unsigned long long)g_counters.f32Warehouse,
        (unsigned long long)g_counters.sourceRewrites,
        (unsigned long long)g_sourceRewriteBytes.load(std::memory_order_acquire),
        (unsigned long long)g_counters.correctionLane,
        (unsigned long long)g_counters.unsupportedReinterpret,
        (unsigned long long)g_counters.roleQ,
        (unsigned long long)g_counters.roleK,
        (unsigned long long)g_counters.roleV,
        (unsigned long long)g_counters.roleO,
        (unsigned long long)g_counters.roleFFN,
        (unsigned long long)g_counters.roleExpert,
        (unsigned long long)g_counters.roleLogits,
        (unsigned long long)g_counters.roleEmbed,
        (unsigned long long)g_f32WarehouseBytes.load(std::memory_order_acquire));
    fflush(f);
}

const char* K2Braid_PrecisionName(BraidPrecision p) {
    switch (p) {
        case BraidPrecision::BP1: return "BP1";
        case BraidPrecision::BP2: return "BP2";
        case BraidPrecision::BP4: return "BP4";
        case BraidPrecision::BP6: return "BP6";
        case BraidPrecision::BP8: return "BP8";
    }
    return "UNKNOWN";
}

const char* K2Braid_RoleName(KernelRole r) {
    switch (r) {
        case KernelRole::Q_PROJ:  return "Q_PROJ";
        case KernelRole::K_PROJ:  return "K_PROJ";
        case KernelRole::V_PROJ:  return "V_PROJ";
        case KernelRole::O_PROJ:  return "O_PROJ";
        case KernelRole::FFN:     return "FFN";
        case KernelRole::EXPERT:  return "EXPERT";
        case KernelRole::LOGITS:  return "LOGITS";
        case KernelRole::EMBED:   return "EMBED";
        case KernelRole::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

const char* K2Braid_FormatName(BraidGGMLType t) {
    switch (t) {
        case BraidGGMLType::F32:    return "F32";
        case BraidGGMLType::F16:    return "F16";
        case BraidGGMLType::Q4_0:   return "Q4_0";
        case BraidGGMLType::Q4_1:   return "Q4_1";
        case BraidGGMLType::Q8_0:   return "Q8_0";
        case BraidGGMLType::Q2_K:   return "Q2_K";
        case BraidGGMLType::Q3_K:   return "Q3_K";
        case BraidGGMLType::Q4_K:   return "Q4_K";
        case BraidGGMLType::Q5_K:   return "Q5_K";
        case BraidGGMLType::Q6_K:   return "Q6_K";
        case BraidGGMLType::IQ4_NL: return "IQ4_NL";
        case BraidGGMLType::IQ4_XS: return "IQ4_XS";
    }
    return "UNKNOWN";
}

bool K2Braid_IsDirectPackable(BraidGGMLType t) {
    switch (t) {
        case BraidGGMLType::Q4_0:
        case BraidGGMLType::Q4_1:
        case BraidGGMLType::Q8_0:
        case BraidGGMLType::Q2_K:
        case BraidGGMLType::Q3_K:
        case BraidGGMLType::Q4_K:
        case BraidGGMLType::Q5_K:
        case BraidGGMLType::Q6_K:
        case BraidGGMLType::IQ4_NL:
        case BraidGGMLType::IQ4_XS:
            return true;
        case BraidGGMLType::F32:
        case BraidGGMLType::F16:
            return false;  // not packed — direct float path
        default:
            return false;
    }
}

} // namespace Deep2