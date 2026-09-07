// K2BraidExecutionPolicy.hpp — transient braid policy above packed GEMV
// NOT a storage format. BP1..BP8 describe how much information from the
// authoritative packed representation is consumed/reconstructed per invocation.
#pragma once
#include <cstdint>
#include <cstdio>
#include <string>

namespace Deep2 {

enum class BraidPrecision : uint8_t {
    BP1 = 1, BP2 = 2, BP4 = 4, BP6 = 6, BP8 = 8,
};

enum class KernelRole : uint8_t {
    UNKNOWN = 0, Q_PROJ = 1, K_PROJ = 2, V_PROJ = 3, O_PROJ = 4,
    FFN = 5, EXPERT = 6, LOGITS = 7, EMBED = 8,
};

enum class BraidGGMLType : int {
    F32 = 0, F16 = 1, Q4_0 = 2, Q4_1 = 3, Q8_0 = 8,
    Q2_K = 10, Q3_K = 11, Q4_K = 12, Q5_K = 13, Q6_K = 14,
    IQ4_NL = 20, IQ4_XS = 23,
};

struct BraidExecutionPlan {
    BraidGGMLType sourceFormat = BraidGGMLType::Q4_K;
    BraidPrecision precision = BraidPrecision::BP8;
    KernelRole role = KernelRole::UNKNOWN;
    bool correctionEnabled = false;
    bool directPacked = true;
    bool f32Warehouse = false;
    uint8_t laneTag = 0;
    bool preferFusedQ4KT = true; // false → DispatchGEMVPacked for this lane
};

enum class BraidAdaptiveAction : uint8_t { HOLD = 0, REDUCE = 1, UNREDUCE = 2 };
enum class BraidQkvLane : uint8_t { NONE = 0, QA = 1, QB = 2, KVA = 3 };
enum class BraidQkvMode : uint8_t {
    SerialReuse = 0, // GPU Q_A → reuse → KV_A → Q_B
    SplitKv = 1,     // GPU Q || host KV_A (champion)
    SplitQ = 2,      // host Q || GPU KV_A
};

struct BraidAdaptiveSnapshot {
    uint64_t windows = 0;
    uint64_t qaUs = 0, qbUs = 0, kvaUs = 0;
    float qaPct = 0, qbPct = 0, kvaPct = 0;
    float qaEmaPct = 0, qbEmaPct = 0, kvaEmaPct = 0;
    BraidQkvLane owner = BraidQkvLane::NONE;
    BraidAdaptiveAction lastAction = BraidAdaptiveAction::HOLD;
    BraidQkvMode mode = BraidQkvMode::SplitKv;
    bool qaFused = true, qbFused = true, kvaFused = true;
};

struct BraidCounters {
    uint64_t plansIssued = 0, directPacked = 0, f32Warehouse = 0;
    uint64_t sourceRewrites = 0, correctionLane = 0, unsupportedReinterpret = 0;
    uint64_t roleQ = 0, roleK = 0, roleV = 0, roleO = 0;
    uint64_t roleFFN = 0, roleExpert = 0, roleLogits = 0, roleEmbed = 0;
};

static constexpr uint32_t K2_BRAID_ROLE_SLOTS = 8;

struct K2BraidWitnessSnapshot {
    uint64_t mlaGemvEntries = 0, planCount = 0, execCount = 0, packedExecCount = 0;
    uint64_t sourceRewriteBytes = 0, f32WarehouseBytes = 0;
    uint64_t unsupportedReinterpret = 0, persistedBraidBytes = 0;
    uint64_t rolePlans[K2_BRAID_ROLE_SLOTS]{};
    uint64_t roleExecs[K2_BRAID_ROLE_SLOTS]{};
    uint64_t rolePackedExecs[K2_BRAID_ROLE_SLOTS]{};
};

void K2Braid_ResetWitnesses();
void K2Braid_NoteMlaGemvEntry();
void K2Braid_NotePlan(KernelRole role);
void K2Braid_NoteExecuted(KernelRole role);
void K2Braid_NotePackedExec(KernelRole role);
void K2Braid_NoteSourceRewrite(uint64_t bytes);
void K2Braid_NoteF32Warehouse(uint64_t bytes);
void K2Braid_NoteUnsupportedReinterpret();
void K2Braid_NotePersistedBytes(uint64_t bytes);
K2BraidWitnessSnapshot K2Braid_GetWitnessSnapshot();

void K2Braid_PlanTagged(KernelRole role, BraidGGMLType sourceFormat,
                        uint8_t pinTag, BraidExecutionPlan& out);
void K2Braid_Plan(KernelRole role, BraidGGMLType sourceFormat,
                  BraidExecutionPlan& out);
void K2Braid_ObserveQkvWindow(uint64_t qaUs, uint64_t qbUs, uint64_t kvaUs,
                              bool parityOk = true);
void K2Braid_ReportParity(bool parityOk);
BraidQkvMode K2Braid_GetQkvMode();
BraidAdaptiveSnapshot K2Braid_GetAdaptiveSnapshot();
void K2Braid_EmitAdaptive(FILE* f);
const char* K2Braid_ActionName(BraidAdaptiveAction a);
const char* K2Braid_QkvLaneName(BraidQkvLane lane);
const char* K2Braid_QkvModeName(BraidQkvMode m);

void K2Braid_NoteExecuted(const BraidExecutionPlan& plan);
void K2Braid_ResetCounters();
BraidCounters K2Braid_GetCounters();
void K2Braid_EmitCounters(FILE* f);
const char* K2Braid_PrecisionName(BraidPrecision p);
const char* K2Braid_RoleName(KernelRole r);
const char* K2Braid_FormatName(BraidGGMLType t);
bool K2Braid_IsDirectPackable(BraidGGMLType t);

} // namespace Deep2
