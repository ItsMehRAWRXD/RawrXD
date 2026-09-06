// retained_proof_masm_smoke.cpp — MASM FACTROOT gate (does NOT replace k2_runtime_validation)
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#ifdef _WIN32
extern "C" {
uint32_t SerializeRetainedProofTable(const void* rawTable, void* destBuffer, uint64_t limitSize);
uint64_t ExecuteDeterminismSmokeTest(const void* generatorCtx, void* tempWorkspace, void* patchSlots);
}
#endif

static constexpr uint64_t FACTROOT = 0x544F4F5246414354ULL;
static constexpr uint64_t P0 = 1ULL << 0;
static constexpr uint64_t P1 = 1ULL << 1;
static constexpr uint64_t P2 = 1ULL << 2;
static constexpr uint64_t P3 = 1ULL << 3;
static constexpr uint64_t P4 = 1ULL << 4;
static constexpr uint64_t P5 = 1ULL << 5;
static constexpr uint64_t P6 = 1ULL << 6;
static constexpr uint64_t ALL = P0|P1|P2|P3|P4|P5|P6;

#pragma pack(push, 8)
struct EnvelopeFacts {
    uint64_t GpuIdentifier;
    uint64_t K2TopologyHash;
    uint64_t KernelAbiSignature;
    uint64_t PhysicalBudgetCeiling;
};
struct ProofEntry {
    uint32_t RuleIdentifier;
    uint32_t ReservedPadding;
    uint64_t MeasuredTimeDelta;
    EnvelopeFacts HardwareEnvelope;
};
struct ProofTableHeader {
    uint64_t MagicSignature;
    uint64_t GenerationIndex;
    uint64_t ActiveProofCount;
    uint64_t PayloadCombinedSize;
    uint64_t TableSelfHash[4];
};
struct GenCtx {
    const void* AuthorityRecord;
    const void* HardwareFacts;
    const void* WorkloadFacts;
    uint64_t BudgetCeiling;
    const void* RetainedProofsTable;
};
#pragma pack(pop)

static void logp(const char* n, bool ok) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", n);
}

int main() {
#ifndef _WIN32
    std::printf("MASM retained_proof smoke is Windows/MSVC only\n");
    return 0;
#else
    std::printf("P1_RETAINED_PROOF_TABLE_001 MASM FACTROOT smoke\n");

    std::vector<uint8_t> raw(sizeof(ProofTableHeader) + 2 * sizeof(ProofEntry), 0);
    auto* hdr = reinterpret_cast<ProofTableHeader*>(raw.data());
    hdr->MagicSignature = FACTROOT;
    hdr->GenerationIndex = 1;
    hdr->ActiveProofCount = 2;
    hdr->PayloadCombinedSize = 2 * sizeof(ProofEntry);

    auto* e0 = reinterpret_cast<ProofEntry*>(raw.data() + sizeof(ProofTableHeader));
    e0[0].RuleIdentifier = 20;
    e0[0].MeasuredTimeDelta = 1350;
    e0[0].HardwareEnvelope = {1, 2, 3, 2000};
    e0[1].RuleIdentifier = 10; // sorts before 20
    e0[1].MeasuredTimeDelta = 2150;
    e0[1].HardwareEnvelope = {1, 2, 3, 2000};

    std::vector<uint8_t> canonical(raw.size(), 0);
    const uint32_t st = SerializeRetainedProofTable(raw.data(), canonical.data(), canonical.size());
    if (st != 0) {
        std::printf("Serialize failed status=0x%X\n", st);
        return 1;
    }
    // Copy hash back into "active" table for smoke hash-match step
    std::memcpy(raw.data(), canonical.data(), canonical.size());

    GenCtx ctx{};
    ctx.RetainedProofsTable = raw.data();
    ctx.BudgetCeiling = 2000;
    uint8_t slots[64];
    std::memset(slots, 0xFF, sizeof(slots));
    std::vector<uint8_t> ws(4096, 0);

    const uint64_t mask = ExecuteDeterminismSmokeTest(&ctx, ws.data(), slots);
    logp("PROOF_TABLE_CANONICAL_ENCODING", (mask & P0) != 0);
    logp("PROOF_TABLE_HASH_MATCH", (mask & P1) != 0);
    logp("PROOF_FACT_ENVELOPE_MATCH", (mask & P2) != 0);
    logp("PATCH_HISTORY_INPUT_ABSENT", (mask & P3) != 0);
    logp("PATCH_HISTORY_PERTURBATION_HASH_SAME", (mask & P4) != 0);
    logp("GENERATED_IMAGE_HASH_REPRODUCIBLE", (mask & P5) != 0);
    logp("PATCH_SLOTS_ZERO_AFTER_COMMIT", (mask & P6) != 0);

    bool slotsZero = true;
    for (uint8_t b : slots) if (b) slotsZero = false;
    if (!slotsZero) {
        std::printf("FAIL slots not zeroed\n");
        return 2;
    }
    if ((mask & ALL) != ALL) {
        std::printf("FAIL mask=0x%llX\n", (unsigned long long)mask);
        return 3;
    }
    std::printf("P1_RETAINED_PROOF_TABLE_001 MASM PASS\n");
    std::printf("NOTE: k2_runtime_validation remains certified G10/G11 path; wire authority next.\n");
    return 0;
#endif
}
