// BowRain compute authority implementation.
//
// See BowRainComputeAuthority.h for the evidence discipline this file exists to
// enforce. The two load-bearing properties:
//
//   1. No function in this file can set a verdict. Verdicts are computed by
//      evaluate*() from recorded observations only.
//   2. No function in this file accepts an aggregate pass count. Aggregates are
//      computed from per-node records, so a failing node cannot be absorbed.

#include "BowRainComputeAuthority.h"

// RAWRXD_REVERSE_RECEIPT_TRADE_TITAN_001: the product verifies its own receipt.
// Header-only, so this adds no target and no CMake ownership.
#include "operators/ReverseReceiptTradeTitan.hpp"

#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

namespace rawrxd::compute
{
    namespace
    {
        struct BowRainState
        {
            // --- source / topology observations ---
            bool sourceCreated = false;
            std::string bindingSite;
            bool entered = false;
            std::string mode;
            bool unFlag = false;    // UN  = unseen / unmapped edge
            bool nuFlag = false;    // NU  = newly created capability
            bool patchFlag = false; // PATCH = bind into execution
            bool coldFlag = false;  // COLD = created/bound, not promoted (NOT failure)
            int intensity = 0;

            // --- measured traversal evidence ---
            std::vector<NodeExecution> nodes;

            // --- measured whole-run evidence ---
            bool executionEvidenceRecorded = false;
            std::uint64_t outputCount = 0;
            bool callbacksObserved = false;
            bool finiteOutputMeasured = false;

            // --- receipt materialisation (an observation, not a verdict) ---
            bool receiptWritten = false;
            std::string receiptPath;

            // --- execution provenance (REVERSE_TRADE_TITAN_001) ---
            // Which route actually executed, how many tokens it carried, and
            // which physical device / released model it executed against.
            // Recorded because a forward PASS that cannot name these cannot be
            // walked back into physical reality.
            std::string backend;
            std::map<std::string, int> backendTokens;
            std::string device;
            std::string model;
            std::string stoneOriginal;
            std::string stoneReversed;
            std::string tradeApplied;
        };

        BowRainState& state()
        {
            static BowRainState s;
            return s;
        }

        const char* yn(bool v) { return v ? "1" : "0"; }

        std::string passFail(bool ok)
        {
            return ok ? "PASS" : "FAIL";
        }
    } // namespace

    // ======================================================================
    // Observation recorders
    // ======================================================================

    void markSourceCreated()
    {
        state().sourceCreated = true;
    }

    void apply(const std::string& mode,
               bool unFlag,
               bool nuFlag,
               bool patchFlag,
               bool coldFlag,
               int intensity)
    {
        BowRainState& s = state();
        s.entered = true;
        s.mode = mode;
        s.unFlag = unFlag;
        s.nuFlag = nuFlag;
        s.patchFlag = patchFlag;
        s.coldFlag = coldFlag;
        s.intensity = intensity;
    }

    void recordParameters(const std::string& mode,
                          bool unFlag,
                          bool nuFlag,
                          bool patchFlag,
                          bool coldFlag,
                          int intensity)
    {
        BowRainState& s = state();
        s.mode = mode;
        s.unFlag = unFlag;
        s.nuFlag = nuFlag;
        s.patchFlag = patchFlag;
        s.coldFlag = coldFlag;
        s.intensity = intensity;
    }

    void recordRuntimeBinding(const std::string& bindingSite)
    {
        // An empty site is not a binding, so it is not recorded as one.
        if (bindingSite.empty())
            return;

        state().bindingSite = bindingSite;
    }

    void recordNodeExecution(const std::string& nodeId,
                             bool passed,
                             std::uint64_t outputCount,
                             const std::string& detail)
    {
        // A node that reported no output did not pass, whatever the caller
        // claimed. Observation is normalised here so no downstream aggregate
        // can forget this.
        const bool effective = passed && (outputCount > 0);

        NodeExecution rec;
        rec.nodeId = nodeId;
        rec.passed = effective;
        rec.outputCount = outputCount;
        rec.detail = detail;

        state().nodes.push_back(std::move(rec));
    }

    void recordExecutionEvidence(std::uint64_t outputCount,
                                 bool callbacksObserved,
                                 bool finiteOutputMeasured)
    {
        BowRainState& s = state();
        s.executionEvidenceRecorded = true;
        s.outputCount = outputCount;
        s.callbacksObserved = callbacksObserved;
        s.finiteOutputMeasured = finiteOutputMeasured;
    }

    // ======================================================================
    // Computed aggregates -- derived, never settable
    // ======================================================================

    int mapNodesVisited()
    {
        return static_cast<int>(state().nodes.size());
    }

    int mapNodesExecuted()
    {
        int n = 0;
        for (const NodeExecution& node : state().nodes)
        {
            if (node.passed)
                ++n;
        }
        return n;
    }

    int mapNodesPassed()
    {
        return mapNodesExecuted();
    }

    int mapNodesFailed()
    {
        return mapNodesVisited() - mapNodesExecuted();
    }

    // ======================================================================
    // Execution provenance -- REVERSE_TRADE_TITAN_001
    //
    // Observations only. None of these can make the verdict PASS; they exist
    // so that evaluateCertification() can REFUSE to reach PASS without them.
    // The asymmetry is the point: adding evidence can unblock certification,
    // and there is deliberately no evidence whose absence cannot be noticed.
    // ======================================================================

    void recordExecutionRoute(const std::string& backend)
    {
        if (backend.empty())
            return;

        BowRainState& s = state();
        s.backend = backend;
        // Count tokens per route so the receipt shows which route actually
        // carried the work, not merely which route was tried first.
        ++s.backendTokens[backend];
    }

    void recordExecutionProvenance(const std::string& device,
                                   const std::string& model,
                                   const std::string& stoneOriginal,
                                   const std::string& stoneReversed,
                                   const std::string& tradeApplied)
    {
        BowRainState& s = state();
        if (!device.empty())        s.device        = device;
        if (!model.empty())         s.model         = model;
        if (!stoneOriginal.empty()) s.stoneOriginal = stoneOriginal;
        if (!stoneReversed.empty()) s.stoneReversed = stoneReversed;
        if (!tradeApplied.empty())  s.tradeApplied  = tradeApplied;
    }

    std::string executionBackend()          { return state().backend; }
    std::string executionDevice()           { return state().device; }
    std::string modelIdentity()             { return state().model; }
    std::string stoneOriginalForm()         { return state().stoneOriginal; }
    std::string stoneReversedForm()         { return state().stoneReversed; }
    std::string tradeAppliedKind()          { return state().tradeApplied; }

    int executionBackendTokenCount()
    {
        const BowRainState& s = state();
        auto it = s.backendTokens.find(s.backend);
        return it == s.backendTokens.end() ? 0 : it->second;
    }

    std::vector<std::pair<std::string, int>> routeHistogram()
    {
        std::vector<std::pair<std::string, int>> out;
        const BowRainState& s = state();
        out.reserve(s.backendTokens.size());
        for (const auto& kv : s.backendTokens)
            out.emplace_back(kv.first, kv.second);
        return out;
    }

    // A value that names nothing is not evidence.
        //
        // Defence in depth. The caller is expected to store an ABSENT value as
        // empty, but a receipt is consumed by third parties that may not honour
        // that convention -- and the placeholder "<none>" is exactly what a
        // producer writes when it has nothing. Accepting it would make a
        // placeholder indistinguishable from a measured device name, which is
        // the whole failure this authority exists to prevent.
        //
        // Provenance is the ONLY gate in this file that checks the value and
        // not merely its presence, and that asymmetry is deliberate: every
        // other field is a boolean whose two states are unambiguous.
        auto names = [](const std::string& v) {
            return !v.empty() && v != "<none>" && v != "<unset>"
                && v != "none" && v != "unset" && v != "UNKNOWN";
        };

        bool provenanceComplete()
    {
        const BowRainState& s = state();
        auto names = [](const std::string& v) {
            return !v.empty() && v != "<none>" && v != "<unset>"
                && v != "none" && v != "unset" && v != "UNKNOWN";
        };
        return names(s.backend)
            && names(s.device)
            && names(s.model)
            && names(s.stoneOriginal)
            && names(s.stoneReversed)
            && names(s.tradeApplied);
    }

    // REQUIREMENT_BEHAVIOR_SATISFIED is DERIVED, never accepted.
    //
    // The requirement Deep2 must satisfy to produce a certification-grade
    // forward receipt is: real per-layer execution of real released weights,
    // observed on a named physical device, through a named route, producing a
    // real finite output. Every clause below is a measurement this authority
    // already holds. None can be asserted by a caller.
    //
    // This is the clause that stops a 3B model from presenting as a 671B one:
    // a logical claim without a named device and a named route is Missing, and
    // Missing forces UNPROVEN.
    std::string evaluateRequirementBehaviour()
    {
        const BowRainState& s = state();

        const bool ok =
            s.sourceCreated
            && !s.bindingSite.empty()
            && evaluateLocalApply() == "PASS"
            && s.executionEvidenceRecorded
            && s.outputCount > 0
            && s.callbacksObserved
            && s.finiteOutputMeasured
            && mapNodesVisited() > 0
            && mapNodesExecuted() > 0
            && mapNodesFailed() == 0
            && provenanceComplete();

        return yn(ok);
    }

    // ======================================================================
    // Derived evaluators
    // ======================================================================

    std::string evaluateLocalApply()
    {
        const BowRainState& s = state();

        const bool ok =
            s.entered
            && !s.mode.empty()
            && s.intensity >= 0;

        return passFail(ok);
    }

    std::string evaluateRuntime()
    {
        const BowRainState& s = state();

        // Not wired => nothing to certify at runtime.
        if (s.bindingSite.empty())
            return "UNPROVEN";

        const bool ok =
            evaluateLocalApply() == "PASS"
            && s.executionEvidenceRecorded
            && s.outputCount > 0
            && s.callbacksObserved
            && s.finiteOutputMeasured
            && mapNodesVisited() > 0
            && mapNodesExecuted() > 0
            && mapNodesFailed() == 0;

        return passFail(ok);
    }

    std::vector<std::string> certificationBlockers()
    {
        const BowRainState& s = state();
        std::vector<std::string> b;

        if (!s.sourceCreated)
            b.emplace_back("SOURCE_NOT_CREATED");
        if (s.bindingSite.empty())
            b.emplace_back("NOT_BOUND_TO_PRODUCT_CALL_GRAPH");
        if (evaluateLocalApply() != "PASS")
            b.emplace_back("LOCAL_APPLY_CONTRACT_FAILED");
        if (!s.executionEvidenceRecorded)
            b.emplace_back("NO_EXECUTION_EVIDENCE_RECORDED");
        if (s.outputCount == 0)
            b.emplace_back("ZERO_OUTPUT_COUNT");
        if (!s.callbacksObserved)
            b.emplace_back("NO_CALLBACKS_OBSERVED");
        if (!s.finiteOutputMeasured)
            b.emplace_back("FINITE_OUTPUT_NOT_MEASURED");
        if (mapNodesVisited() == 0)
            b.emplace_back("NO_NODES_VISITED");
        if (mapNodesFailed() != 0)
            b.emplace_back("FAILED_NODES_PRESENT");

        // --- REVERSE_TRADE_TITAN_001 -------------------------------------
        // A forward receipt that cannot be walked back into physical reality is
        // not a certification. These are the exact conditions under which this
        // authority previously produced a PASS that no reverse walk could
        // support: it had executed nodes and produced output, but it had never
        // been told -- and had therefore never checked -- which device ran it.
        if (s.backend.empty())
            b.emplace_back("EXECUTION_BACKEND_NOT_NAMED");
        if (s.device.empty())
            b.emplace_back("EXECUTION_DEVICE_NOT_NAMED");
        if (s.model.empty())
            b.emplace_back("MODEL_IDENTITY_NOT_BOUND");
        if (s.stoneOriginal.empty())
            b.emplace_back("STONE_ORIGINAL_NOT_RECORDED");
        if (s.stoneReversed.empty())
            b.emplace_back("STONE_REVERSED_NOT_RECORDED");
        if (s.tradeApplied.empty())
            b.emplace_back("TRADE_KIND_NOT_RECORDED");

        // Deliberately NOT a certification blocker: the receipt is the OUTPUT
        // of certification, so requiring it as an INPUT would be circular.
        // s.receiptWritten is reported in the receipt as an observation.

        return b;
    }

    std::string evaluateCertification()
    {
        // Unwired is UNPROVEN, not FAIL: there was nothing to evaluate.
        if (state().bindingSite.empty())
            return "UNPROVEN";

        return certificationBlockers().empty() ? "PASS" : "FAIL";
    }

    // ======================================================================
    // Receipt
    // ======================================================================

    // Forward declaration: the reverse section is defined below and appended to the
// finished forward body. See RAWRXD_REVERSE_RECEIPT_TRADE_TITAN_001.
static std::string renderReverseSection(const std::string& forwardBody);

std::string renderBowRainReceipt()
    {
        const BowRainState& s = state();
        std::ostringstream o;

        o << "# BowRain runtime receipt\n";
        o << "# Verdicts below are DERIVED from the observations above them.\n";
        o << "# No field in this file is settable by a caller.\n\n";

        o << "[observations]\n";
        o << "BOWRAIN_SOURCE_CREATED=" << yn(s.sourceCreated) << "\n";
        o << "BOWRAIN_BINDING_SITE=" << (s.bindingSite.empty() ? "<none>" : s.bindingSite) << "\n";
        o << "BOWRAIN_ENTERED=" << yn(s.entered) << "\n";
        o << "BOWRAIN_MODE=" << s.mode << "\n";
        o << "UN_FLAG=" << yn(s.unFlag) << "\n";
        o << "NU_FLAG=" << yn(s.nuFlag) << "\n";
        o << "PATCH_FLAG=" << yn(s.patchFlag) << "\n";
        o << "COLD_FLAG=" << yn(s.coldFlag) << "\n";
        o << "INTENSITY=" << s.intensity << "\n";
        o << "EXECUTION_EVIDENCE_RECORDED=" << yn(s.executionEvidenceRecorded) << "\n";
        o << "MEASURED_OUTPUT_COUNT=" << s.outputCount << "\n";
        o << "CALLBACKS_OBSERVED=" << yn(s.callbacksObserved) << "\n";
        o << "FINITE_OUTPUT_MEASURED=" << yn(s.finiteOutputMeasured) << "\n";
        o << "RECEIPT_MATERIALISED=" << yn(s.receiptWritten) << "\n\n";

        // --- provenance: the fields a reverse receipt walk requires ---------
        // Emitted as observations. Their ABSENCE is what made the previous
        // forward PASS unreversible, so they are written unconditionally, with
        // an explicit <none> rather than being omitted. A missing line and an
        // empty line must not be confusable.
        // Values that can contain a space are quoted, because the receipt parser is
        // shared with the reverse walk and must be able to recover the exact
        // string. A GPU name is the common case: "AMD Radeon AI PRO R9700".
        // Emitting it bare let the walk report the device as "AMD".
        auto q = [](const std::string& v) {
            if (v.empty()) return std::string("<none>");
            if (v.find(' ') == std::string::npos && v.find('"') == std::string::npos)
                return v;
            std::string out = "\"";
            for (char c : v) {
                if (c == '"') out += '\'';
                else out += c;
            }
            out += "\"";
            return out;
        };

        o << "[provenance]\n";
        o << "EXECUTION_BACKEND=" << (s.backend.empty() ? "<none>" : s.backend) << "\n";
        o << "EXECUTION_BACKEND_TOKEN_COUNT=" << executionBackendTokenCount() << "\n";
        o << "EXECUTION_DEVICE=" << q(s.device) << "\n";
        o << "MODEL_IDENTITY=" << q(s.model) << "\n";
        o << "ORIGINAL_STONE=" << q(s.stoneOriginal) << "\n";
        o << "REVERSED_REQUIREMENT=" << q(s.stoneReversed) << "\n";
        o << "TRADE_KIND=" << q(s.tradeApplied) << "\n";
        o << "PROVENANCE_COMPLETE=" << yn(provenanceComplete()) << "\n";
        {
            const auto hist = routeHistogram();
            o << "ROUTE_HISTOGRAM=";
            if (hist.empty())
            {
                o << "<none>\n";
            }
            else
            {
                for (std::size_t i = 0; i < hist.size(); ++i)
                {
                    o << (i == 0 ? "" : ",")
                      << hist[i].first << ":" << hist[i].second;
                }
                o << "\n";
            }
        }
        o << "\n";

        o << "[computed-aggregates]\n";
        o << "MAP_NODES_VISITED=" << mapNodesVisited() << "\n";
        o << "MAP_NODES_EXECUTED=" << mapNodesExecuted() << "\n";
        o << "MAP_NODES_PASSED=" << mapNodesPassed() << "\n";
        o << "MAP_NODES_FAILED=" << mapNodesFailed() << "\n\n";

        // Per-node records are preserved verbatim. This is the point: an
        // aggregate can never be the only surviving statement of what happened.
        o << "[per-node]\n";
        if (s.nodes.empty())
        {
            o << "# <no node records>\n";
        }
        else
        {
            int idx = 0;
            for (const NodeExecution& node : s.nodes)
            {
                o << "NODE_" << idx
                  << "_ID=" << node.nodeId
                  << " NODE_" << idx
                  << "_VERDICT=" << (node.passed ? "PASS" : "FAIL")
                  << " NODE_" << idx
                  << "_OUTPUT=" << node.outputCount
                  << " NODE_" << idx
                  << "_DETAIL=" << (node.detail.empty() ? "<none>" : node.detail)
                  << "\n";
                ++idx;
            }
        }
        o << "\n";

        o << "[derived]\n";
        o << "LOCAL_APPLY_VERDICT=" << evaluateLocalApply() << "\n";
        o << "REQUIREMENT_BEHAVIOR_SATISFIED=" << evaluateRequirementBehaviour() << "\n";
        o << "RUNTIME_VERDICT=" << evaluateRuntime() << "\n";
        o << "CERTIFICATION_VERDICT=" << evaluateCertification() << "\n";
        o << "CERTIFICATION_BLOCKERS=";
        const std::vector<std::string> blockers = certificationBlockers();
        if (blockers.empty())
        {
            o << "<none>\n";
        }
        else
        {
            for (size_t i = 0; i < blockers.size(); ++i)
            {
                o << (i == 0 ? "" : ",") << blockers[i];
            }
            o << "\n";
        }

        // The reverse walk reads the finished forward body, so it consumes the
        // same bytes an external verifier would. Building it first and parsing
        // that string is what prevents this from being a self-congratulatory
        // summary of private state.
        const std::string forwardBody = o.str();
        return forwardBody + renderReverseSection(forwardBody);
    }

    // -----------------------------------------------------------------------
    // RAWRXD_REVERSE_RECEIPT_TRADE_TITAN_001 -- PRODUCT SELF-VERIFICATION
    //
    // The product reverse-walks its OWN receipt and emits the result into that
    // same receipt. This closes the adoption gap where the only verifier lived
    // in a standalone driver: a binary that emits a PASS nobody inside it ever
    // checks. Here, a forward PASS that cannot be walked back into named
    // physical reality is contradicted in the receipt that claims it.
    //
    // The walk parses the forward body it just rendered, so it is reading the
    // same bytes a third party would read -- not an in-memory summary that
    // could flatter itself.
    // -----------------------------------------------------------------------
    static std::string renderReverseSection(const std::string& forwardBody)
    {
        namespace op = RawrXD::Operators;

        const op::ParsedEvidence ev = op::parseReceipt(forwardBody);
        const op::ReverseReceipt rev = op::ReverseReceiptTradeTitan::reverse(ev);

        std::ostringstream r;
        r << "\n[reverse]\n";
        r << "REVERSE_DIRECTION=PASS_TO_REALITY\n";
        r << "REVERSE_LINKS_EXPECTED=" << op::kLinkCount << "\n";
        r << "REVERSE_LINKS_RECOVERED=" << rev.recovered << "\n";
        r << "REVERSE_LINKS_MISSING=" << rev.missing << "\n";
        r << "REVERSE_LINKS_CONTRADICTED=" << rev.contradicted << "\n";
        for (std::size_t i = 0; i < rev.links.size(); ++i)
        {
            const op::ReverseLink& l = rev.links[i];
            // Evidence values are quoted for the same reason the provenance fields are:
            // a link's evidence is a GPU name or a path, and emitting it bare
            // made the receipt print REVERSE_LINK_7 as `"AMD` while the receipt
            // two lines above said the device was "AMD Radeon AI PRO R9700". A
            // receipt that contradicts itself about its own evidence is the
            // hazard this walk exists to catch, so it cannot commit one.
            auto qev = [](const std::string& v) {
                if (v.empty()) return std::string("");
                if (v.find(' ') == std::string::npos && v.find('"') == std::string::npos)
                    return v;
                std::string out = "\"";
                for (char c : v) {
                    if (c == '"') out += '\'';
                    else out += c;
                }
                out += "\"";
                return out;
            };

            r << "REVERSE_LINK_" << i
              << "=" << op::linkName(l.id)
              << ":" << op::linkStateName(l.state);
            if (!l.evidence.empty())
                r << ":" << qev(l.evidence);
            r << "\n";
        }
        r << "REVERSE_RECEIPT_COMPLETE=" << yn(rev.complete) << "\n";
        r << "REVERSE_VERDICT=" << op::reverseVerdictName(rev.verdict) << "\n";

        // The asymmetry is the finding. A forward PASS whose reverse walk does
        // not complete is the exact condition this authority exists to catch,
        // so it is stated as its own field rather than left to be inferred.
        const bool forwardPass = ev.equals("CERTIFICATION_VERDICT", "PASS");
        r << "FORWARD_VERDICT=" << (forwardPass ? "PASS" : "NOT_PASS") << "\n";
        r << "ASYMMETRY_FORWARD_PASS_REVERSE_NOT="
          << yn(forwardPass && rev.verdict != op::ReverseVerdict::Pass) << "\n";

        r << "REVERSE_BLOCKERS=";
        if (rev.blockers.empty())
        {
            r << "<none>\n";
        }
        else
        {
            for (std::size_t i = 0; i < rev.blockers.size(); ++i)
                r << (i == 0 ? "" : ",") << rev.blockers[i];
            r << "\n";
        }
        return r.str();
    }

    bool writeBowRainReceipt(const std::string& outPath)
    {
        if (outPath.empty())
            return false;

        // RENDER BEFORE TRUNCATING.
        //
        // This used to open the file with trunc first and call
        // renderBowRainReceipt() second. When the receipt's own reverse walk
        // hung inside rendering, the file had already been truncated: a 0-byte
        // receipt replaced a good one, so the defect destroyed the very
        // evidence it was produced for. Verification must never be able to
        // destroy what it verifies.
        const std::string body = renderBowRainReceipt();

        std::ofstream f(outPath, std::ios::binary | std::ios::trunc);
        if (!f)
            return false;

        f << body;
        f.flush();

        if (!f)
            return false;

        f.close();

        BowRainState& s = state();
        s.receiptWritten = true;
        s.receiptPath = outPath;
        return true;
    }

    void resetBowRainAuthority()
    {
        state() = BowRainState{};
    }

} // namespace rawrxd::compute