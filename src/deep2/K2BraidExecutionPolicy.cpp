// K2BraidExecutionPolicy.cpp — transient braid policy implementation
#include "K2BraidExecutionPolicy.hpp"
#include "K2RainbowFoldTable.hpp"
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <mutex>
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdlib>
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

// ===========================================================================
// Adaptive QKV topology controller
// REDUCE  = GPU Q || host KV_A when KV_A owns QKV wall
// UNREDUCE = serial GPU + hidden reuse when ownership collapses
// HOLD    = keep sticky mode
// Lane preferFused: A/B fused vs compat for GPU lanes still on device.
// ===========================================================================
namespace {

struct QkvLaneCtrl {
    float emaPct = 0.f;
    bool emaValid = false;
    bool preferFused = true;
    uint32_t hot = 0, cold = 0, cooldown = 0;
};

struct QkvAdapt {
    QkvLaneCtrl lane[3];
    uint64_t windows = 0;
    uint64_t qaUs = 0, qbUs = 0, kvaUs = 0;
    float pct[3] = {};
    BraidQkvMode mode = BraidQkvMode::SplitKv;
    BraidAdaptiveAction lastAction = BraidAdaptiveAction::HOLD;
    int owner = -1;
    uint32_t modeHot = 0, modeCold = 0;
};

std::mutex g_adaptMu;
QkvAdapt g_adapt{};

constexpr float kEmaA = 0.25f;
constexpr float kEnter = 0.40f;
constexpr float kExit = 0.24f;
constexpr float kDom = 1.50f;
// Observe is per-layer (~1ms); absolute floor must match layer scale.
constexpr uint64_t kMinUs = 400ull;
constexpr uint32_t kHotN = 2, kColdN = 8, kCd = 8;

static int TagLane(uint8_t tag) {
    if (tag == 1) return 0;
    if (tag == 2) return 1;
    if (tag == 3) return 2;
    return -1;
}

} // namespace (adaptive continues in Deep2)

void K2Braid_PlanTagged(KernelRole role, BraidGGMLType sourceFormat,
                        uint8_t pinTag, BraidExecutionPlan& out) {
    out = BraidExecutionPlan{};
    out.sourceFormat = sourceFormat;
    out.role = role;
    out.laneTag = pinTag;
    out.precision = BraidPrecision::BP8;
    out.directPacked = K2Braid_IsDirectPackable(sourceFormat);
    out.f32Warehouse = false;
    out.correctionEnabled = false;
    out.preferFusedQ4KT = true;
    const int lane = TagLane(pinTag);
    if (lane >= 0) {
        std::lock_guard<std::mutex> lock(g_adaptMu);
        out.preferFusedQ4KT = g_adapt.lane[lane].preferFused;
    }
}

void K2Braid_ObserveQkvWindow(uint64_t qaUs, uint64_t qbUs, uint64_t kvaUs,
                              bool parityOk) {
    std::lock_guard<std::mutex> lock(g_adaptMu);
    ++g_adapt.windows;
    g_adapt.qaUs = qaUs;
    g_adapt.qbUs = qbUs;
    g_adapt.kvaUs = kvaUs;
    g_adapt.lastAction = BraidAdaptiveAction::HOLD;

    if (!parityOk) {
        g_adapt.mode = BraidQkvMode::SerialReuse;
        g_adapt.lastAction = BraidAdaptiveAction::UNREDUCE;
        for (int i = 0; i < 3; ++i) {
            g_adapt.lane[i].preferFused = true;
            g_adapt.lane[i].hot = g_adapt.lane[i].cold = 0;
            g_adapt.lane[i].cooldown = kCd;
        }
        return;
    }

    const uint64_t total = qaUs + qbUs + kvaUs;
    if (!total) return;

    const uint64_t raw[3] = {qaUs, qbUs, kvaUs};
    g_adapt.pct[0] = (float)qaUs / (float)total;
    g_adapt.pct[1] = (float)qbUs / (float)total;
    g_adapt.pct[2] = (float)kvaUs / (float)total;

    for (int i = 0; i < 3; ++i) {
        auto& l = g_adapt.lane[i];
        if (!l.emaValid) { l.emaPct = g_adapt.pct[i]; l.emaValid = true; }
        else l.emaPct += kEmaA * (g_adapt.pct[i] - l.emaPct);
        if (l.cooldown) --l.cooldown;
    }

    const float qPct = g_adapt.lane[0].emaPct + g_adapt.lane[1].emaPct;
    const float kvaPct = g_adapt.lane[2].emaPct;
    const float second = (std::max)(g_adapt.lane[0].emaPct, g_adapt.lane[1].emaPct);
    g_adapt.owner = (kvaPct >= qPct) ? 2 : (g_adapt.lane[0].emaPct >= g_adapt.lane[1].emaPct ? 0 : 1);

    const bool kvDom =
        kvaPct >= kEnter && kvaPct >= qPct * kDom && raw[2] >= kMinUs;
    const bool qDom =
        qPct >= kEnter && qPct >= kvaPct * kDom &&
        (raw[0] + raw[1]) >= kMinUs;

    BraidQkvMode want = g_adapt.mode;
    if (g_adapt.mode == BraidQkvMode::SplitKv ||
        g_adapt.mode == BraidQkvMode::SplitQ) {
        // Sticky split: component % under parallel Q||KV looks Q-heavy and must
        // not auto-flip SplitKv↔SplitQ. Soft-cold → Serial only (below).
        want = g_adapt.mode;
    } else {
        if (kvDom) want = BraidQkvMode::SplitKv;
        else if (qDom) want = BraidQkvMode::SplitQ;
    }
    // Do NOT demote Split→Serial on weak absolute samples. Only soft-cold below.

    if (want != g_adapt.mode) {
        ++g_adapt.modeHot;
        g_adapt.modeCold = 0;
        if (g_adapt.modeHot >= kHotN) {
            const bool reducing =
                (want == BraidQkvMode::SplitKv || want == BraidQkvMode::SplitQ) &&
                g_adapt.mode == BraidQkvMode::SerialReuse;
            const bool unreducing =
                want == BraidQkvMode::SerialReuse &&
                g_adapt.mode != BraidQkvMode::SerialReuse;
            g_adapt.mode = want;
            g_adapt.modeHot = 0;
            g_adapt.lastAction = reducing ? BraidAdaptiveAction::REDUCE
                                : unreducing ? BraidAdaptiveAction::UNREDUCE
                                             : BraidAdaptiveAction::HOLD;
            // Secondary: when reducing onto SplitKv, try compat path on KVA
            // lane if still GPU (serial); for SplitKv host path fused N/A.
            if (reducing && want == BraidQkvMode::SplitKv) {
                // Keep GPU Q lanes fused; mark KVA preferFused for when
                // UNREDUCE returns it to GPU.
                g_adapt.lane[2].preferFused = false;
            }
            if (unreducing) {
                for (int i = 0; i < 3; ++i)
                    g_adapt.lane[i].preferFused = true;
            }
        }
    } else {
        g_adapt.modeHot = 0;
        // Soft unreduce sticky: split mode loses ownership → SerialReuse.
        const bool coldSplit =
            (g_adapt.mode == BraidQkvMode::SplitKv && kvaPct <= kExit) ||
            (g_adapt.mode == BraidQkvMode::SplitQ && qPct <= kExit);
        if (coldSplit) {
            if (++g_adapt.modeCold >= kColdN) {
                g_adapt.mode = BraidQkvMode::SerialReuse;
                g_adapt.modeCold = 0;
                g_adapt.lastAction = BraidAdaptiveAction::UNREDUCE;
                for (int i = 0; i < 3; ++i)
                    g_adapt.lane[i].preferFused = true;
            }
        } else {
            g_adapt.modeCold = 0;
        }
        (void)second;
    }
}

void K2Braid_ReportParity(bool parityOk) {
    if (parityOk) return;
    K2RainbowFold_ParityFallback();
    K2Braid_ObserveQkvWindow(0, 0, 0, false);
}

BraidQkvMode K2Braid_GetQkvMode() {
    // Env wins for certs / A/B. Empty string = unset (CRT leaves var present).
    if (const char* e = std::getenv("DEEP2_MLA_QKV_SPLIT")) {
        if (e[0] == '0') return BraidQkvMode::SerialReuse;
        if (e[0] == 'q' || e[0] == 'Q') return BraidQkvMode::SplitQ;
        if (e[0] == '1' || e[0] == 'k' || e[0] == 'K')
            return BraidQkvMode::SplitKv;
    }
    // DEEP2_MLA_SERIAL=1 is GPU Q+KV serial reuse, not host-KV SplitKv.
    if (const char* ser = std::getenv("DEEP2_MLA_SERIAL")) {
        if (ser[0] == '1') return BraidQkvMode::SerialReuse;
    }
    // )ter*N: frozen ROUTING fold steers topology; EMA cannot flip it.
    if (K2RainbowFold_IsFrozenRouting(RainbowFoldId::QKV_SPLIT_KV))
        return BraidQkvMode::SplitKv;
    if (K2RainbowFold_IsFrozenRouting(RainbowFoldId::QKV_SERIAL_REUSE))
        return BraidQkvMode::SerialReuse;
    std::lock_guard<std::mutex> lock(g_adaptMu);
    return g_adapt.mode;
}

BraidAdaptiveSnapshot K2Braid_GetAdaptiveSnapshot() {
    std::lock_guard<std::mutex> lock(g_adaptMu);
    BraidAdaptiveSnapshot s{};
    s.windows = g_adapt.windows;
    s.qaUs = g_adapt.qaUs;
    s.qbUs = g_adapt.qbUs;
    s.kvaUs = g_adapt.kvaUs;
    s.qaPct = g_adapt.pct[0];
    s.qbPct = g_adapt.pct[1];
    s.kvaPct = g_adapt.pct[2];
    s.qaEmaPct = g_adapt.lane[0].emaPct;
    s.qbEmaPct = g_adapt.lane[1].emaPct;
    s.kvaEmaPct = g_adapt.lane[2].emaPct;
    s.owner = g_adapt.owner == 0   ? BraidQkvLane::QA
              : g_adapt.owner == 1 ? BraidQkvLane::QB
              : g_adapt.owner == 2 ? BraidQkvLane::KVA
                                   : BraidQkvLane::NONE;
    s.lastAction = g_adapt.lastAction;
    s.mode = g_adapt.mode;
    s.qaFused = g_adapt.lane[0].preferFused;
    s.qbFused = g_adapt.lane[1].preferFused;
    s.kvaFused = g_adapt.lane[2].preferFused;
    return s;
}

const char* K2Braid_ActionName(BraidAdaptiveAction a) {
    switch (a) {
    case BraidAdaptiveAction::REDUCE: return "REDUCE";
    case BraidAdaptiveAction::UNREDUCE: return "UNREDUCE";
    default: return "HOLD";
    }
}
const char* K2Braid_QkvLaneName(BraidQkvLane lane) {
    switch (lane) {
    case BraidQkvLane::QA: return "Q_A";
    case BraidQkvLane::QB: return "Q_B";
    case BraidQkvLane::KVA: return "KV_A";
    default: return "NONE";
    }
}
const char* K2Braid_QkvModeName(BraidQkvMode m) {
    switch (m) {
    case BraidQkvMode::SerialReuse: return "SERIAL_REUSE";
    case BraidQkvMode::SplitKv: return "SPLIT_KV";
    case BraidQkvMode::SplitQ: return "SPLIT_Q";
    }
    return "SERIAL_REUSE";
}

void K2Braid_EmitAdaptive(FILE* f) {
    if (!f) f = stdout;
    const auto s = K2Braid_GetAdaptiveSnapshot();
    const BraidQkvMode live = K2Braid_GetQkvMode();
    fprintf(f,
            "BRAID_QKV_US QA=%llu QB=%llu KVA=%llu\n"
            "BRAID_QKV_PCT QA=%.2f QB=%.2f KVA=%.2f "
            "EMA_QA=%.2f EMA_QB=%.2f EMA_KVA=%.2f\n"
            "BRAID_QKV_OWNER=%s ACTION=%s LIVE_MODE=%s POLICY_MODE=%s\n"
            "BRAID_QKV_PATH QA=%s QB=%s KVA=%s WINDOWS=%llu\n",
            (unsigned long long)s.qaUs, (unsigned long long)s.qbUs,
            (unsigned long long)s.kvaUs, s.qaPct * 100.f, s.qbPct * 100.f,
            s.kvaPct * 100.f, s.qaEmaPct * 100.f, s.qbEmaPct * 100.f,
            s.kvaEmaPct * 100.f, K2Braid_QkvLaneName(s.owner),
            K2Braid_ActionName(s.lastAction), K2Braid_QkvModeName(live),
            K2Braid_QkvModeName(s.mode),
            s.qaFused ? "FUSED" : "COMPAT", s.qbFused ? "FUSED" : "COMPAT",
            s.kvaFused ? "FUSED" : "COMPAT",
            (unsigned long long)s.windows);
    K2RainbowFold_Emit(f);
    fflush(f);
}

void K2Braid_Plan(KernelRole role, BraidGGMLType sourceFormat,
                  BraidExecutionPlan& out) {
    K2Braid_PlanTagged(role, sourceFormat, 0, out);
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
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_counters = BraidCounters{};
    }
    K2Braid_ResetWitnesses();
    {
        std::lock_guard<std::mutex> lock(g_adaptMu);
        g_adapt = QkvAdapt{};
        g_adapt.mode = BraidQkvMode::SplitKv;
    }
}

BraidCounters K2Braid_GetCounters() {
    std::lock_guard<std::mutex> lock(g_mu);
    BraidCounters c = g_counters;
    // Atomic bytes are read outside the counter struct
    return c;
}

void K2Braid_EmitCounters(FILE* f) {
    if (!f) f = stdout;
    {
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
    K2Braid_EmitAdaptive(f);
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