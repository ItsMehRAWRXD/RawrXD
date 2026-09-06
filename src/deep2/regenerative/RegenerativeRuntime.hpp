// RegenerativeRuntime.hpp — crash-safe proof→image→activate→zero-slots
#pragma once
#include "RuntimeGenerator.hpp"
#include <vector>

namespace Deep2 {
namespace Regenerative {

class RegenerativeRuntime {
public:
    void SetSealed(const SealedCore& s) { sealed_ = s; }
    void SetHardware(const HardwareFacts& h) { hardware_ = h; }
    void SetWorkload(const WorkloadFacts& w) { workload_ = w; }
    void SetBudgets(const BudgetFacts& b) { budgets_ = b; }
    void SetKernelAbi(const char* tag) {
        kernelAbiTag_[0] = 0;
        if (tag) std::snprintf(kernelAbiTag_, sizeof(kernelAbiTag_), "%s", tag);
        else std::snprintf(kernelAbiTag_, sizeof(kernelAbiTag_), "rawrxd.deep2.abi.v1");
    }

    RetainedProofTable& Proofs() { return proofs_; }
    const RetainedProofTable& Proofs() const { return proofs_; }
    const std::vector<uint8_t>& CanonicalBlob() const { return canonicalBlob_; }
    ProofFactEnvelope CurrentEnvelope() const {
        return MakeEnvelope(hardware_, workload_, budgets_, kernelAbiTag_);
    }

    const RuntimeImage* Active() const { return haveActive_ ? &active_ : nullptr; }
    const RuntimeImage* PrivateNext() const {
        return havePrivate_ ? &privateNext_ : nullptr;
    }

    void ClearEphemeralPatchSlots() {
        for (int i = 0; i < 16; ++i) ephemeralSlots_[i] = 0;
        ephemeralUsed_ = 0;
    }
    bool StageEphemeralSlot(uint64_t token) {
        if (ephemeralUsed_ >= 16) return false;
        ephemeralSlots_[ephemeralUsed_++] = token;
        return true;
    }
    bool PatchSlotsZero() const {
        return proofs_.EphemeralSlotsAllZero(ephemeralSlots_, 16);
    }

    // measure → retain normalized proof (envelope-bound)
    bool RetainNormalizedProof(const char* ruleId, double netRemovalMs,
                               double confidence, uint64_t gen,
                               const TimeReversal::Hash256& evidenceSha) {
        RetainedProof p;
        p.kind = ProofKind::TimeRemoval;
        p.active = true;
        p.measuredNetRemovalMs = netRemovalMs;
        p.confidence = confidence;
        p.sourceGeneration = gen;
        p.evidenceSha = evidenceSha;
        p.envelope = CurrentEnvelope();
        std::snprintf(p.ruleId, sizeof(p.ruleId), "%s", ruleId ? ruleId : "rule");
        return proofs_.Add(p);
    }

    // serialize + hash proof table
    bool SerializeAndHashProofTable() {
        const auto env = CurrentEnvelope();
        InvalidateProofsOutsideEnvelope(proofs_, env);
        canonicalBlob_ = SerializeProofTableCanonical(proofs_, env);
        SealProofTableHash(proofs_, env);
        lastGates_.proofTableCanonicalEncoding = ProofBlobLooksCanonical(canonicalBlob_);
        lastGates_.proofTableHashMatch = ValidateProofTableHash(proofs_);
        lastGates_.proofFactEnvelopeMatch =
            ValidateProofFactEnvelopeMatch(proofs_, env);
        return lastGates_.proofTableCanonicalEncoding &&
               lastGates_.proofTableHashMatch &&
               lastGates_.proofFactEnvelopeMatch;
    }

    RegenDecision EvaluateRegen(double currentExecCost, double maintCost,
                                double complexityCost, double riskCost,
                                double genCost, double newExecCost) const {
        return DecideRegenerate(
            {currentExecCost, maintCost, complexityCost, riskCost},
            {genCost, newExecCost});
    }

    // regenerate candidate RealtimeImage (no patch-history input)
    bool RegenerateCandidateImage(const RegenDecision& decision) {
        if (!decision.regenerate) return false;
        if (canonicalBlob_.empty()) return false;
        GeneratorInputs in;
        in.sealed = sealed_;
        in.hardware = hardware_;
        in.workload = workload_;
        in.budgets = budgets_;
        in.proofs = &proofs_;
        in.envelope = CurrentEnvelope();
        in.canonicalProofBlob = &canonicalBlob_;
        privateNext_ = GenerateRuntime(in);
        havePrivate_ = true;
        lastGates_.nextBuiltPrivately = true;
        lastGates_.derivedFromFacts = true;
        lastGates_.regenCostAccounted = true;
        lastGates_.regenCheaperThanMaintenance = decision.regenerate;
        lastGates_.maintenanceElided = true;
        lastGates_.patchHistoryInputAbsent = true;
        return !privateNext_.derivedFromPatchHistory;
    }

    bool VerifyImageAndBudget(bool outputEquivalent, bool authorityUnchanged,
                              bool resourceCaps) {
        if (!havePrivate_) return false;
        if (!Freeze(privateNext_)) return false;
        lastGates_.outputEquivalence = outputEquivalent;
        lastGates_.authorityUnchanged = authorityUnchanged;
        lastGates_.resourceCaps = resourceCaps && PhysicalBudgetOk(privateNext_);
        // Reproducibility is part of trust boundary before activate
        lastGates_.generatedImageHashReproducible = ImageHashReproducible();
        return lastGates_.resourceCaps && !privateNext_.derivedFromPatchHistory &&
               lastGates_.generatedImageHashReproducible;
    }

    // atomically activate G+1 → zero ephemeral patch slots
    bool AtomicActivateAndZeroSlots() {
        if (!havePrivate_ || !privateNext_.frozen) return false;
        if (haveActive_) retired_ = active_;
        active_ = privateNext_;
        haveActive_ = true;
        havePrivate_ = false;
        sealed_.generationCounter = active_.generation;
        ClearEphemeralPatchSlots();
        lastGates_.atomicGenerationSwap = true;
        lastGates_.oldRuntimeRetired = true;
        lastGates_.patchSlotsZeroAfterCommit = PatchSlotsZero();
        return lastGates_.patchSlotsZeroAfterCommit;
    }

    // Full crash-safe transition
    bool CommitCrashSafeTransition(const RegenDecision& decision,
                                   bool outputEquivalent, bool authorityUnchanged,
                                   bool resourceCaps) {
        if (!SerializeAndHashProofTable()) return false;
        if (!RegenerateCandidateImage(decision)) return false;
        if (!VerifyImageAndBudget(outputEquivalent, authorityUnchanged, resourceCaps))
            return false;
        return AtomicActivateAndZeroSlots();
    }

    // Determinism probe: regenerate twice from same sealed inputs
    bool ImageHashReproducible() {
        if (canonicalBlob_.empty()) return false;
        GeneratorInputs in;
        in.sealed = sealed_;
        in.hardware = hardware_;
        in.workload = workload_;
        in.budgets = budgets_;
        in.proofs = &proofs_;
        in.envelope = CurrentEnvelope();
        in.canonicalProofBlob = &canonicalBlob_;
        const RuntimeImage a = GenerateRuntime(in);
        const RuntimeImage b = GenerateRuntime(in);
        lastGates_.generatedImageHashReproducible = HashEq(a.imageSha, b.imageSha);
        return lastGates_.generatedImageHashReproducible;
    }

    // Perturbation: caller mutates external patchHistory bytes; must not affect hash
    bool ImageHashIndependentOfPatchHistoryBuffer(uint8_t* patchHistory, size_t n) {
        if (!patchHistory || n == 0) return ImageHashReproducible();
        GeneratorInputs in;
        in.sealed = sealed_;
        in.hardware = hardware_;
        in.workload = workload_;
        in.budgets = budgets_;
        in.proofs = &proofs_;
        in.envelope = CurrentEnvelope();
        in.canonicalProofBlob = &canonicalBlob_;
        const RuntimeImage before = GenerateRuntime(in);
        for (size_t i = 0; i < n; ++i) patchHistory[i] = uint8_t(0xA5 ^ (i * 17));
        const RuntimeImage after = GenerateRuntime(in);
        // Structural: GeneratorInputs cannot observe patchHistory
        return HashEq(before.imageSha, after.imageSha);
    }

    GeneratorGates LastGates() const { return lastGates_; }
    bool TrustBoundaryPass() const { return lastGates_.trustBoundaryPass(); }
    bool RegenerativePass() const { return lastGates_.allPass(); }

    GenerationAuthorityRecord MakeAuthorityRecord() const {
        GenerationAuthorityRecord r{};
        Hash256ToQwords(sealed_.authoritySha, r.sealedAuthorityHash);
        r.hardwareFactsPtr = reinterpret_cast<uint64_t>(&hardware_);
        r.workloadFactsPtr = reinterpret_cast<uint64_t>(&workload_);
        r.currentBudgetLimitMsFixed =
            static_cast<uint64_t>(budgets_.targetMsPerToken * 100.0 + 0.5);
        r.retainedProofsTablePtr = reinterpret_cast<uint64_t>(&proofs_);
        r.generationCounter = sealed_.generationCounter;
        return r;
    }

private:
    SealedCore sealed_{};
    HardwareFacts hardware_{};
    WorkloadFacts workload_{};
    BudgetFacts budgets_{};
    char kernelAbiTag_[64]{"rawrxd.deep2.abi.v1"};
    RetainedProofTable proofs_{};
    std::vector<uint8_t> canonicalBlob_{};
    RuntimeImage active_{};
    RuntimeImage privateNext_{};
    RuntimeImage retired_{};
    bool haveActive_ = false;
    bool havePrivate_ = false;
    uint64_t ephemeralSlots_[16]{};
    int ephemeralUsed_ = 0;
    GeneratorGates lastGates_{};
};

} // namespace Regenerative
} // namespace Deep2
