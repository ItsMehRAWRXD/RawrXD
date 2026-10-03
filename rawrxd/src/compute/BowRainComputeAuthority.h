#pragma once

// ===========================================================================
// BowRain compute authority
//
// Gates BowRain pattern computation and owns map-traversal evidence.
//
// Operator law:
//   WORD-LISH-<*> = IGNORE      (prose is not structure)
//   </>            = STRUCTURE BOUNDARY
//   NU-DROW        = REVERSE-SCRAPE structure only
//
// ---------------------------------------------------------------------------
// EVIDENCE DISCIPLINE — READ BEFORE ADDING A FUNCTION
// ---------------------------------------------------------------------------
//   SELF_REPORTING_EVIDENCE = ALLOWED   (a caller may report what it observed)
//   SELF_REPORTING_VERDICT  = FORBIDDEN (no caller may assert a verdict)
//
//   OBSERVATION_MUTATES_EVIDENCE = 1
//   EVALUATOR_DERIVES_VERDICT    = 1
//
// There is deliberately NO function that sets a verdict. There is deliberately
// NO function that accepts aggregate pass counts. Both were the two ways this
// authority previously manufactured its own success, and both are gone because
// the aggregate form is what erases per-node disagreement:
//
//     node0=PASS node1=FAIL node2=PASS  ->  "visited=3 executed=3 failed=0"
//
// A caller now records ONE record per node. The aggregates are computed. The
// failing node cannot be absorbed into a count.
//
//   VALID(A) + VALID(B) != VALID(A->B)   -- so every node is its own gate
//
// Certification is derived from recorded observations only:
//
//   CERTIFIED = productWired && runtimeExecuted && outputCount > 0
//            && callbacksObserved && finiteOutputMeasured
//            && localApplyValid
//            && nodesVisited > 0 && nodesExecuted > 0 && failedNodes == 0
//            && everyVisitedNodeHasARecord
//
// Receipt materialisation is deliberately NOT an input to certification: the
// receipt is the OUTPUT of certification, so requiring it as an input would be
// circular. It is reported in the receipt as an observation instead.
//
// STATUS: this authority is NOT in any CMake target and has NO product callsite
// in this tree. Source presence is not adoption. See AGENTS.md
// RAWRXD_COMPUTE_ADOPTION_AUTHORITY_001.
// ===========================================================================

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace rawrxd::compute
{
    // -------------------------------------------------------------------------
    // Per-node execution record. One of these per visited node, always.
    // -------------------------------------------------------------------------
    struct NodeExecution
    {
        std::string nodeId;
        bool passed = false;
        std::string detail;

        // Output actually produced by this node. Zero means the node ran and
        // produced nothing, which is a failure even if no exception was thrown.
        std::uint64_t outputCount = 0;
    };

    // -------------------------------------------------------------------------
    // Observation recorders. These mutate EVIDENCE only.
    // -------------------------------------------------------------------------
    void markSourceCreated();

    // Local, authority-internal apply contract.
    void apply(const std::string& mode,
               bool unFlag,
               bool nuFlag,
               bool patchFlag,
               bool coldFlag,
               int intensity);

    void recordParameters(const std::string& mode,
                          bool unFlag,
                          bool nuFlag,
                          bool patchFlag,
                          bool coldFlag,
                          int intensity);

    // Records that the authority is bound into a real call graph. The site is
    // evidence: an empty site is not a binding.
    void recordRuntimeBinding(const std::string& bindingSite);

    // Records ONE node's execution. There is no aggregate form.
    void recordNodeExecution(const std::string& nodeId,
                             bool passed,
                             std::uint64_t outputCount,
                             const std::string& detail);

    // Records measured evidence about the traversal as a whole, as observed by
    // the caller. `finiteOutputMeasured` must come from an actual scan, not
    // from a default.
    void recordExecutionEvidence(std::uint64_t outputCount,
                                 bool callbacksObserved,
                                 bool finiteOutputMeasured);

    // -------------------------------------------------------------------------
    // Execution provenance -- REVERSE_TRADE_TITAN_001
    //
    // These are OBSERVATIONS, not verdicts. They exist because a forward
    // receipt that cannot name the hardware, the route and the model it ran on
    // is not a certification: it is a hope. This repository already recorded
    // the rule as
    //
    //     ENABLE_VULKAN_TRUE != GPU_WEIGHT_RESIDENCY
    //
    // and the same rule applies here in general form:
    //
    //     FORWARD_RECEIPT_PASS != REVERSE_RECEIPT_COMPLETE
    //
    // `backend` is the route that ACTUALLY executed, e.g. "VulkanResident".
    // `device` is the physical device name as enumerated by Vulkan. `model` is
    // the released model whose weights were consumed. All three are supplied by
    // the caller because only the caller observed them; none of them can imply
    // success on their own.
    //
    // NOTE what is deliberately ABSENT: there is no parameter that states the
    // requirement was behaviourally satisfied. That is DERIVED by
    // evaluateRequirementBehaviour() from the measurements below, because a
    // caller-supplied "behaviour is fine" flag would be exactly the
    // self-certifying setter this authority was rebuilt to remove.
    void recordExecutionRoute(const std::string& backend);

    void recordExecutionProvenance(const std::string& device,
                                   const std::string& model,
                                   const std::string& stoneOriginal,
                                   const std::string& stoneReversed,
                                   const std::string& tradeApplied);

    // -------------------------------------------------------------------------
    // Derived evaluators. These compute verdicts; they never accept one.
    // -------------------------------------------------------------------------
    std::string evaluateLocalApply();
    std::string evaluateRuntime();
    std::string evaluateCertification();

    // Whether every measurement required for a reverse-walkable receipt is
    // present. Derived, never settable.
    bool provenanceComplete();
    std::string evaluateRequirementBehaviour();

    // Machine-readable reason the certification verdict is what it is.
    std::vector<std::string> certificationBlockers();

    // -------------------------------------------------------------------------
    // Receipt materialisation. Writes a real file; returns whether it did.
    // -------------------------------------------------------------------------
    std::string renderBowRainReceipt();
    bool writeBowRainReceipt(const std::string& outPath);

    // Test/reset seam for driving independent scenarios in one process.
    void resetBowRainAuthority();

    // Computed aggregates (derived from the node records, never settable).
    int mapNodesVisited();
    int mapNodesExecuted();
    int mapNodesPassed();
    int mapNodesFailed();

    // Provenance accessors, for the reverse receipt walk.
    std::string executionBackend();
    int executionBackendTokenCount();
    std::string executionDevice();
    std::string modelIdentity();
    std::string stoneOriginalForm();
    std::string stoneReversedForm();
    std::string tradeAppliedKind();
    // Distinct routes observed, and their per-route token counts.
    std::vector<std::pair<std::string, int>> routeHistogram();
} // namespace rawrxd::compute