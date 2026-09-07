// K2BraidExecutionPolicy.hpp — transient braid policy above packed GEMV
// NOT a storage format. BP1..BP8 describe how much information from the
// authoritative packed representation is consumed/reconstructed per invocation.
//
// Architecture:
//   GGUF packed weights → ResolveWeight → residency → BraidExecutionPolicy
//     → packed kernel → FP32 accumulator
#pragma once
#include <cstdint>
#include <cstdio>
#include <string>

namespace Deep2 {

// ---------------------------------------------------------------------------
// BraidPrecision — transient compute policy (NOT a storage format)
//   BP8 = full native packed (no approximation)
//   BP6 = native packed with selective component skip
//   BP4 = reduced precision reconstruction
//   BP2 = aggressive approximation + correction lane
//   BP1 = minimal information + correction lane
// ---------------------------------------------------------------------------
enum class BraidPrecision : uint8_t {
    BP1 = 1,
    BP2 = 2,
    BP4 = 4,
    BP6 = 6,
    BP8 = 8,  // native packed — no approximation
};

// ---------------------------------------------------------------------------
// KernelRole — semantic role of the tensor being executed
// ---------------------------------------------------------------------------
enum class KernelRole : uint8_t {
    UNKNOWN = 0,
    Q_PROJ  = 1,
    K_PROJ  = 2,
    V_PROJ  = 3,
    O_PROJ  = 4,
    FFN     = 5,
    EXPERT  = 6,
    LOGITS  = 7,
    EMBED   = 8,
};

// ---------------------------------------------------------------------------
// GGMLType — canonical ggml type IDs (matches QuantKernelRegistry)
// ---------------------------------------------------------------------------
enum class BraidGGMLType : int {
    F32  = 0,
    F16  = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q8_0 = 8,
    Q2_K = 10,
    Q3_K = 11,
    Q4_K = 12,
    Q5_K = 13,
    Q6_K = 14,
    IQ4_NL = 20,
    IQ4_XS = 23,
};

// ---------------------------------------------------------------------------
// BraidExecutionPlan — describes how a transient weight lane is executed
// ---------------------------------------------------------------------------
struct BraidExecutionPlan {
    BraidGGMLType sourceFormat = BraidGGMLType::Q4_K;
    BraidPrecision precision    = BraidPrecision::BP8;
    KernelRole     role         = KernelRole::UNKNOWN;
    bool           correctionEnabled = false;
    bool           directPacked = true;  // feed packed block directly to kernel
    bool           f32Warehouse = false; // false = no permanent FP32 expansion
};

// ---------------------------------------------------------------------------
// BraidCounters — certification witnesses
// ---------------------------------------------------------------------------
struct BraidCounters {
    uint64_t plansIssued    = 0;
    uint64_t directPacked   = 0;  // plans that used direct packed kernel
    uint64_t f32Warehouse   = 0;  // plans that materialized FP32 (should be 0)
    uint64_t sourceRewrites = 0;  // plans that rewrote source tensor (should be 0)
    uint64_t correctionLane = 0;  // plans using correction stream
    uint64_t unsupportedReinterpret = 0;  // unsupported format reinterpret (should be 0)
    // Per-role
    uint64_t roleQ = 0, roleK = 0, roleV = 0, roleO = 0;
    uint64_t roleFFN = 0, roleExpert = 0, roleLogits = 0, roleEmbed = 0;
};

// Keep Count as the final enum member in KernelRole.
static constexpr uint32_t K2_BRAID_ROLE_SLOTS = 8;

// ---------------------------------------------------------------------------
// K2BraidWitnessSnapshot — tightened witness chain proving real execution.
// Distinguishes PLAN != EXECUTED != PACKED_EXECUTED so a policy call cannot
// masquerade as braid actually owning packed execution.
// ---------------------------------------------------------------------------
struct K2BraidWitnessSnapshot {
    uint64_t mlaGemvEntries = 0;
    uint64_t planCount = 0;
    uint64_t execCount = 0;
    uint64_t packedExecCount = 0;

    uint64_t sourceRewriteBytes = 0;
    uint64_t f32WarehouseBytes = 0;
    uint64_t unsupportedReinterpret = 0;
    uint64_t persistedBraidBytes = 0;

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

// ---------------------------------------------------------------------------
// BraidController — policy layer between weight resolution and packed GEMV
// ---------------------------------------------------------------------------
// Usage from MLA_Gemv / LinearW:
//   BraidExecutionPlan plan;
//   K2Braid_Plan(role, sourceFormat, plan);
//   if (plan.directPacked) {
//       // feed packed block directly to GPU/CPU GEMV kernel
//   }
//   K2Braid_NoteExecuted(plan);

// Plan an execution for a given role + source format.
// Returns a plan with directPacked=true, f32Warehouse=false, precision=BP8
// (native) by default. Correction lane enabled for BP1/BP2.
void K2Braid_Plan(KernelRole role, BraidGGMLType sourceFormat,
                  BraidExecutionPlan& out);

// Note that a plan was executed. Updates counters.
void K2Braid_NoteExecuted(const BraidExecutionPlan& plan);

// Note a source rewrite violation (should be 0 for certification).
void K2Braid_NoteSourceRewrite(size_t bytes);

// Note an FP32 warehouse violation (should be 0 for certification).
void K2Braid_NoteF32Warehouse(size_t bytes);

// Note unsupported format reinterpret (should be 0 for certification).
void K2Braid_NoteUnsupportedReinterpret();

// Reset all counters.
void K2Braid_ResetCounters();

// Get current counters.
BraidCounters K2Braid_GetCounters();

// Emit counters to FILE* (or stdout if f==nullptr).
void K2Braid_EmitCounters(FILE* f);

// Convert enum to string for logging.
const char* K2Braid_PrecisionName(BraidPrecision p);
const char* K2Braid_RoleName(KernelRole r);
const char* K2Braid_FormatName(BraidGGMLType t);

// Check if a format is directly packable (no FP32 expansion needed).
bool K2Braid_IsDirectPackable(BraidGGMLType t);

} // namespace Deep2