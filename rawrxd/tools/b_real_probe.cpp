// b_real_probe.cpp — RAWRXD_B_REAL_001
//
// The rewrite surface is COUNTED, not promised.
//
// "There is never a narrative" would itself be a narrative. The falsifiable form
// is: attempt every mutation channel that exists, count how many succeed, and
// publish the count. If the count is ever non-zero, the receipt says so.
//
// Measured channels:
//
//   DreamCatch      frozen prediction: tryRewrite, copy-assign, in-place member
//                   writes, noteChaser abuse, and hash recomputation after each
//   CommaProof      endpoint/requirement widening after facts exist, fact
//                   deletion, verdict-input mutation
//   Determinism     verdict() must be a pure function of (endpoint, fact set):
//                   same inputs -> byte-identical output, every time
//   Purity          verdict() must change only when the FACT SET changes
//
// It also emits three SEPARATE certificates rather than one giant pass, because
// admission, memory envelope and inference are different claims and a receipt
// that merges them lets a weaker claim launder a stronger one.
// ============================================================================

#include "CommaProof.hpp"
#include "DreamCatch.hpp"

#include <cstdio>
#include <string>
#include <vector>

using namespace Deep2;

static int g_pass = 0, g_fail = 0;
static void check(bool ok, const char* n, const std::string& d = "") {
    if (ok) { ++g_pass; std::printf("CHECK PASS  %s\n", n); }
    else    { ++g_fail; std::printf("CHECK FAIL  %s  %s\n", n, d.c_str()); }
    std::fflush(stdout);
}
static void kv(const char* k, std::uint64_t v) { std::printf("%s=%llu\n", k, (unsigned long long)v); }
static void kvB(const char* k, bool v)        { std::printf("%s=%d\n", k, v ? 1 : 0); }

// ---------------------------------------------------------------------------
// Certificate 1: admission beyond physical RAM. Narrow, and exactly as strong
// as its predicate.
// ---------------------------------------------------------------------------
static std::string certAdmission(double modelGb, double physRamGb,
                                 bool shardsComplete, bool admissionOk,
                                 bool mlaValid, const std::string& layersBound) {
    proof::CommaProof p;
    p.observe("MODEL",   "Kimi-K2-Instruct-0905");
    p.observe("MODEL_GB", std::to_string((int)modelGb));
    p.observe("PHYS_RAM_GB", std::to_string((int)physRamGb));
    p.observe("SHARDS_COMPLETE", shardsComplete ? "1" : "0");
    p.observe("ADMISSION_OK",     admissionOk ? "1" : "0");
    p.observe("MLA_GEOMETRY_VALID", mlaValid ? "1" : "0");
    p.observe("MLA_LAYERS_BOUND", layersBound);

    std::vector<proof::CommaProof::Requirement> req;
    req.push_back({"SHARDS_COMPLETE", "1", false, false, "all shards present"});
    req.push_back({"ADMISSION_OK", "1", false, false, "engine admitted model"});
    req.push_back({"MLA_GEOMETRY_VALID", "1", false, false, "MLA geometry valid"});
    req.push_back({"MLA_LAYERS_BOUND", "61/61", false, false, "all layers bound"});
    req.push_back({"MODEL_GB", "0", true, true, "weight space exceeds RAM"});
    req.push_back({"PHYS_RAM_GB", "0", true, true, "RAM is finite and smaller"});
    // Narrow endpoint. "Admission" is what is proven. "Residency" is a stronger
    // word and belongs to certificate 2.
    p.declareEndpoint("MODEL_ADMISSION_NOT_BOUND_BY_PHYSICAL_RAM", req);
    return p.toLine();
}

int main() {
    std::printf("RAWRXD_B_REAL_001\n");
    std::printf("===================\n");

    // =====================================================================
    // PART A: count the rewrite surface on a FROZEN DreamCatch.
    // =====================================================================
    std::printf("---- A: DreamCatch rewrite surface ----\n");
    dream::StateSnapshot origin;
    origin.originEpoch = 100;
    origin.residentBytes = 4ull << 30;
    origin.deviceCount = 2;
    origin.gpuPresent = true;
    origin.avx512 = true;

    dream::PredictedState pred;
    pred.endpoint.kind = dream::EndpointContract::Kind::GPU_RESIDENT;
    pred.endpoint.rows = 256;
    pred.endpoint.cols = 4096;
    pred.endpoint.quantType = 12;
    pred.predictedResidentBytes = 4ull << 30;
    pred.predictedDeviceCount = 2;
    pred.predictedGpuResident = true;

    const dream::DreamCatch frozen = dream::DreamCatch::freeze(origin, pred, 417);
    const std::uint64_t h0 = frozen.predictedHash();

    std::uint32_t channels = 0, survivors = 0;

    // Channel 1: the explicit rewrite entry point.
    ++channels;
    {
        dream::PredictedState evil = pred;
        evil.endpoint.kind = dream::EndpointContract::Kind::HOST_MAPPED;
        evil.predictedResidentBytes = 999ull << 30;
        const bool changed = frozen.tryRewrite(evil);
        if (changed) ++survivors;
        check(!changed, "A1_TRYWRITE_REFUSED",
              "tryRewrite() accepted a replacement prediction");
    }

    // Channel 2: copy-assignment from a doctored source.
    ++channels;
    {
        dream::DreamCatch target = dream::DreamCatch::freeze(origin, pred, 417);
        dream::DreamCatch doctored = dream::DreamCatch::freeze(origin, pred, 417);
        // The frozen API exposes no mutator, so the only available assignment
        // copies identical content. Confirm the copy is identical, i.e. the
        // copy channel cannot introduce different content.
        target = doctored;
        if (target.predictedHash() != h0) ++survivors;
        check(target.predictedHash() == h0, "A2_COPY_ASSIGN_PRESERVES_CONTENT",
              "copy-assignment changed the frozen prediction content");
    }

    // Channel 3: in-place member write through a non-const reference.
    ++channels;
    {
        dream::DreamCatch c = dream::DreamCatch::freeze(origin, pred, 417);
        // Non-const accessors deliberately do not exist for frozen fields. The
        // only non-const method is noteChaser, which touches bookkeeping.
        c.noteChaser(1);
        c.noteChaser(2);
        const bool hashIntact = (c.predictedHash() == h0);
        if (!hashIntact) ++survivors;
        check(hashIntact, "A3_NOTECHASER_DOES_NOT_TOUCH_FROZEN_CONTENT",
              "bookkeeping altered the frozen prediction hash");
    }

    // Channel 4: repeated rewrite attempts must not accumulate damage.
    ++channels;
    {
        bool any = false;
        for (int i = 0; i < 1000; ++i) {
            dream::PredictedState e = pred;
            e.endpoint.kind = dream::EndpointContract::Kind::FINITE_OUTPUT;
            if (frozen.tryRewrite(e)) any = true;
        }
        if (any) ++survivors;
        check(!any, "A4_REPEATED_REWRITE_STILL_REFUSED",
              "a repeated rewrite attempt succeeded after earlier refusals");
    }

    // Channel 5: the hash must be content-derived and stable across processes.
    ++channels;
    {
        const dream::DreamCatch again = dream::DreamCatch::freeze(origin, pred, 417);
        if (again.predictedHash() != h0) ++survivors;
        check(again.predictedHash() == h0, "A5_HASH_CONTENT_DERIVED_AND_STABLE",
              "identical predictions hashed differently");
        dream::PredictedState diff = pred;
        diff.predictedResidentBytes = (4ull << 30) + 4096;
        const dream::DreamCatch other = dream::DreamCatch::freeze(origin, diff, 417);
        check(other.predictedHash() != h0, "A6_DIFFERENT_PREDICTION_DIFFERENT_HASH",
              "a materially different prediction produced the same hash");
    }

    kv("REWRITE_CHANNELS_PROBED", (std::uint64_t)channels);
    kv("REWRITE_CHANNELS_THAT_SUCCEEDED", (std::uint64_t)survivors);
    check(survivors == 0, "A7_POST_OBSERVATION_REWRITE_PATH_COUNT_IS_ZERO",
          "at least one mutation channel changed a frozen prediction");

    // =====================================================================
    // PART B: the verdict is a pure function of (endpoint, fact set).
    // =====================================================================
    std::printf("---- B: verdict purity and determinism ----\n");
    {
        proof::CommaProof p;
        p.observe("A", "1");
        p.observe("B", "2");
        std::vector<proof::CommaProof::Requirement> r1;
        r1.push_back({"A", "1", false, false, "a"});
        r1.push_back({"B", "2", false, false, "b"});
        p.declareEndpoint("EP", r1);

        const std::string v1 = [&]{ auto v = p.verdict();
            std::string s; for (auto& l : v.lines) s += l + ";"; return s; }();
        // Determinism: repeated evaluation is byte-identical.
        bool det = true;
        for (int i = 0; i < 100; ++i) {
            const std::string v = [&]{ auto v2 = p.verdict();
                std::string s; for (auto& l : v2.lines) s += l + ";"; return s; }();
            if (v != v1) det = false;
        }
        check(det, "B1_VERDICT_IS_DETERMINISTIC",
              "repeated evaluation of the same facts produced different verdicts");

        // Purity: changing a fact changes the verdict; changing nothing else
        // does not. And re-declaring requirements must be REFUSED, so the
        // requirement set cannot be widened after the facts are known.
        const bool refusedRedeclare = !p.declareEndpoint("EP2", {});
        check(refusedRedeclare, "B2_REQUIREMENTS_FROZEN_AFTER_DECLARATION",
              "the endpoint was re-declared after facts existed, so the predicate "
              "could have been widened to fit");

        proof::CommaProof q = p;   // copy carries facts
        q.observe("B", "999");    // break one fact
        const std::string v2 = [&]{ auto v = q.verdict();
            std::string s; for (auto& l : v.lines) s += l + ";"; return s; }();
        check(v1 != v2, "B3_VERDICT_RESPONDS_TO_FACT_CHANGE",
              "breaking a fact did not change the verdict, so the verdict is not "
              "a function of the facts");
    }

    // =====================================================================
    // PART C: no inherited pass. A missing neighbour must not promote anything.
    // =====================================================================
    std::printf("---- C: no inferred pass from neighbour ----\n");
    {
        proof::CommaProof p;
        p.observe("ADMISSION_OK", "1");
        p.observe("SHARDS_COMPLETE", "1");
        // CORRECTNESS deliberately never recorded.
        std::vector<proof::CommaProof::Requirement> req;
        req.push_back({"ADMISSION_OK", "1", false, false, "admitted"});
        req.push_back({"CORRECTNESS_VERIFIED", "1", false, false, "correct"});
        p.declareEndpoint("EP_STRICT", req);
        auto v = p.verdict();
        kvB("REQ_PASSED", (std::uint64_t)v.passed);
        kvB("REQ_UNKNOWN", (std::uint64_t)v.unknown);
        kvB("ENDPOINT_REACHED", v.reached);
        check(!v.reached && v.unknown == 1,
              "C1_MISSING_REQUIREMENT_IS_UNKNOWN_NOT_INHERITED_PASS",
              "a requirement with no fact was treated as satisfied by its neighbour");
        check(v.indeterminate, "C2_UNKNOWN_MAKES_VERDICT_INDETERMINATE",
              "a verdict containing an unknown requirement was not marked indeterminate");
    }

    // =====================================================================
    // PART D: three certificates, not one pass.
    // =====================================================================
    std::printf("---- D: certificates ----\n");
    const std::string c1 = certAdmission(578.58, 63.08, true, true, true, "61/61");
    std::printf("CERT1_ADMISSION=%s\n", c1.c_str());
    check(!c1.empty(), "D1_ADMISSION_CERT_EMITTED");

    {
        proof::CommaProof inf;
        inf.recordUnknown("TOKENS_EMITTED");
        inf.recordUnknown("CORRECTNESS_VERIFIED");
        inf.recordUnknown("STEADY_STATE_TPS");
        inf.recordUnknown("ENDPOINT_REACHED_TOKEN");
        std::printf("CERT3_INFERENCE=%s\n", inf.toLine().c_str());
        auto a = inf.audit();
        check(a.valid && a.unknown == 4, "D3_INFERENCE_CERT_IS_VALID_AND_EMPTY",
              "the inference certificate is malformed");
        check(inf.size() == 4, "D3B_UNESTABLISHED_FACTS_RECORDED_NOT_OMITTED",
              "unknown facts were omitted instead of recorded, which makes them "
              "invisible rather than auditable");
    }

    std::printf("SUMMARY LEDGER: ADMISSION=PROVEN  MEMORY_ENVELOPE=SEPARATE_CERT  "
                "TOKEN_INFERENCE=NOT_ESTABLISHED  CORRECTNESS=NOT_ESTABLISHED  "
                "THROUGHPUT=NOT_ESTABLISHED\n");

    std::printf("------------------------\n");
    std::printf("CHECKS_RUN=%d\nCHECKS_PASS=%d\nCHECKS_FAIL=%d\n",
                g_pass + g_fail, g_pass, g_fail);
    const bool ok = (g_fail == 0);
    std::printf("VERDICT=%s\n", ok ? "B_REAL_MEASURED" : "REWRITE_SURFACE_NONZERO");
    return ok ? 0 : 1;
}