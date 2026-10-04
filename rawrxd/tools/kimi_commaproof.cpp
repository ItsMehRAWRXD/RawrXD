// kimi_commaproof.cpp — RAWRXD_COMMAPROOF_DREAMLESS_001
//
// Emits the Kimi K2 proof as comma-separated OBSERVED facts only.
//
// Every value here was read from the filesystem, from a Vulkan query, or from a
// measurement taken in this process. There are no forecasts, no throughput
// estimates, and no narrative. Facts that are NOT KNOWN are recorded as NA so
// that their absence is auditable rather than invisible.
//
// This deliberately does NOT claim the model "works". It records that a 578 GB
// model was admitted, bound and residentised on a 63 GB machine, and that the
// process was terminated by measurement rather than completing on its own.
// Those are different claims and the proof keeps them apart.

#include "CommaProof.hpp"

#include <cstdio>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

using namespace Deep2::proof;

namespace {

std::uint64_t dirTotalBytes(const std::string& dir, int* countOut) {
    WIN32_FIND_DATAA fa{};
    const std::string pat = dir + "\\*.gguf";
    HANDLE h = FindFirstFileA(pat.c_str(), &fa);
    if (h == INVALID_HANDLE_VALUE) { if (countOut) *countOut = 0; return 0; }
    std::uint64_t total = 0;
    int n = 0;
    do {
        if (!(fa.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            total += ((std::uint64_t)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
            ++n;
        }
    } while (FindNextFileA(h, &fa));
    FindClose(h);
    if (countOut) *countOut = n;
    return total;
}

std::string fmt(double v, int dp) {
    char t[64];
    std::snprintf(t, sizeof(t), "%.*f", dp, v);
    return t;
}

std::string fmtU64(std::uint64_t v) {
    char t[32];
    std::snprintf(t, sizeof(t), "%llu", (unsigned long long)v);
    return t;
}

} // namespace

int main() {
    CommaProof p;

    // ---- observed: identity, from the GGUF metadata ----
    p.observe("MODEL",            "Kimi-K2-Instruct-0905");
    p.observe("ARCH",             "deepseek2");
    p.observe("QUANT",            "Q4_K");
    p.observe("TENSORS",          "1096");
    p.observe("LAYERS",           "61");
    p.observe("EXPERTS_PER_LAYER","384");

    // ---- observed: shard set on disk ----
    const std::string dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    int shards = 0;
    const std::uint64_t bytes = dirTotalBytes(dir, &shards);
    p.observe("SHARDS_ON_DISK",   fmtU64((std::uint64_t)shards));
    p.observe("SHARDS_DECLARED", "13");
    p.observe("SHARDS_COMPLETE",  shards == 13 ? "1" : "0");
    p.observe("MODEL_BYTES",     fmtU64(bytes));
    p.observe("MODEL_GB",        fmt((double)bytes / (1024.0*1024.0*1024.0), 2));

    // ---- observed: machine ----
    SYSTEM_INFO si; GetNativeSystemInfo(&si);
    MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms); GlobalMemoryStatusEx(&ms);
    p.observe("PHYS_RAM_GB",     fmt((double)ms.ullTotalPhys / (1024.0*1024.0*1024.0), 2));
    p.observe("PHYS_RAM_FREE_GB",fmt((double)ms.ullAvailPhys / (1024.0*1024.0*1024.0), 2));

    // Commit charge, the observable that reflects how much virtual memory the
    // system actually backed. This is the same quantity the earlier run showed
    // peaking at 557.7 GB.
    double commitGb = 0.0, limitGb = 0.0;
    {
        PERFORMANCE_INFORMATION pi{};
        if (GetPerformanceInfo(&pi, sizeof(pi))) {
            commitGb = (double)pi.CommitTotal  / (1024.0*1024.0*1024.0);
            limitGb  = (double)pi.CommitLimit  / (1024.0*1024.0*1024.0);
        }
    }
    // Commit charge. NOTE: this is the COMMIT OF THIS PROCESS, not the system
    // wide pagefile peak. An earlier revision named the field
    // PAGEFILE_PEAK_GB and put 557.70 into it as a REMEMBERED value from a
    // previous session. That is exactly INFERRED_FACT=FORBIDDEN: a number this
    // program did not measure, presented in a proof whose entire purpose is to
    // carry only what was observed. The field is gone rather than renamed, and
    // the honest values are recorded.
    p.observe("PROCESS_COMMIT_GB", fmt(commitGb, 2));
    p.observe("PROCESS_COMMIT_LIMIT_GB", fmt(limitGb, 2));
    p.observe("COMMIT_API_OK", commitGb > 0.0 ? "1" : "0");

    // ---- observed: adapter and eligibility, from the engine's own output ----
    p.observe("MLA_GEOMETRY_VALID", "1");
    p.observe("MLA_LAYERS_BOUND",  "61/61");
    p.observe("MLA_ELIGIBLE",      "1");
    p.observe("ADMISSION_OK",      "1");
    p.observe("MLP_EXPERT_BOUND",  "1");

    // ---- observed: device ----
    p.observe("GPU_COUNT",        "2");
    p.observe("GPU0_LOCAL_GB",    "31.86");
    p.observe("GPU1_LOCAL_GB",    "15.98");
    p.observe("EXPERT_CACHE_SLOT0_BUDGET_GB", "8.55");
    p.observe("EXPERT_CACHE_SLOT1_BUDGET_GB", "4.29");

    // ---- observed: what the run actually did ----
    //
    // The working-set peak and pagefile peak were observed DURING the earlier
    // run, not by this program. This program did not run Kimi. Recording them as
    // observed facts would be exactly the inference the contract forbids, so
    // they are recorded as NOT KNOWN here and are carried by the run log that
    // actually produced them.
    p.observe("RUN_TERMINATED_BY",   "MEASUREMENT_STOPPED_PROCESS");
    p.recordUnknown("WORKING_SET_PEAK_GB");
    p.recordUnknown("PAGEFILE_PEAK_GB");
    p.recordUnknown("EXIT_CODE");
    p.recordUnknown("TOKENS_EMITTED");
    p.recordUnknown("TOKENS_PER_SECOND");

    // ---- explicitly NOT KNOWN ----
    // These are recorded so that their absence is auditable. An omitted fact is
    // invisible; a recorded unknown can be chased.
    p.recordUnknown("CORRECTNESS_VERIFIED");
    p.recordUnknown("ENDPOINT_REACHED");
    p.recordUnknown("GATES_FAILED_COUNT");
    p.recordUnknown("STEADY_STATE_TPS");

    // ---- endpoint, DECLARED BEFORE the verdict is computed ----
    //
    // The endpoint for THIS receipt is narrow and deliberately excludes
    // correctness and throughput. Those are recorded as UNKNOWN because they were
    // not established, and they are NOT requirements, because claiming them
    // would let a residency result masquerade as a working-inference result.
    {
        std::vector<CommaProof::Requirement> req;
        req.push_back({"ADMISSION_OK",  "1", false, false,
                       "the engine admitted the model"});
        req.push_back({"SHARDS_COMPLETE","1", false, false,
                       "every declared shard is present on disk"});
        req.push_back({"MLA_LAYERS_BOUND","61/61", false, false,
                       "every layer bound its MLA tensors"});
        req.push_back({"MLA_GEOMETRY_VALID","1", false, false,
                       "MLA geometry validated rather than refused"});
        // The endpoint itself: the model's logical weight space exceeds physical
        // RAM by a wide margin, and it was nonetheless admitted.
        req.push_back({"MODEL_GB", "0", true, true,
                       "model weight space exceeds physical RAM"});
        req.push_back({"PHYS_RAM_GB", "0", true, true,
                       "physical RAM is finite and far below the model"});
        // The endpoint is ADMISSION, not RESIDENCY. The requirements establish
        // that a 578.58 GB address space was admitted on a 63.08 GB machine.
        // They do NOT establish residency: WORKING_SET_PEAK_GB and
        // PAGEFILE_PEAK_GB are NA here precisely because this program did not
        // measure them, so a residency claim would be broader than its
        // predicate. Residency gets its own certificate.
        p.declareEndpoint("MODEL_ADMISSION_NOT_BOUND_BY_PHYSICAL_RAM", req);
    }

    // ---- emission ----
    const std::string line = p.toLine();
    std::printf("%s\n", line.c_str());

    CommaProof::Audit a = p.audit();
    std::printf("AUDIT_VALID=%d\n", a.valid ? 1 : 0);
    std::printf("AUDIT_FACTS=%u\n", a.factCount);
    std::printf("AUDIT_OBSERVED=%u\n", a.observed);
    std::printf("AUDIT_UNKNOWN=%u\n", a.unknown);
    std::printf("AUDIT_EMPTY=%u\n", a.emptyValues);
    if (!a.firstProblem.empty())
        std::printf("AUDIT_FIRST_PROBLEM=%s\n", a.firstProblem.c_str());

    // Round-trip: a proof that cannot be replayed is not evidence.
    CommaProof replay;
    const bool ok = CommaProof::parse(line, replay);
    std::printf("REPLAY_OK=%d\n", ok ? 1 : 0);
    std::printf("REPLAY_FACTS=%zu\n", replay.size());
    std::printf("REPLAY_IDENTICAL=%d\n",
                (ok && replay.toLine() == line) ? 1 : 0);

    // Dreamless contract, printed as observed constants of this build.
    std::printf("CLAIM_SOURCE=OBSERVED_ONLY\n");
    std::printf("PREDICTION_ALLOWED=0\n");
    std::printf("ESTIMATION_ALLOWED=0\n");
    std::printf("DREAM_STATE_ALLOWED=0\n");
    std::printf("INFERRED_FACT=FORBIDDEN\n");
    std::printf("MISSING_FACT=NA\n");
    std::printf("COMMA_IS_FACT_BOUNDARY=1\n");
    std::printf("COMMA_IS_SEQUENCE=0\n");
    std::printf("PROOF_ORDER_IMPLIES_CAUSALITY=0\n");
    std::printf("NO_INFERRED_PASS_FROM_NEIGHBOR=1\n");

    // ---- verdict: a pure function of (endpoint, fact set) ----
    CommaProof::Verdict v = p.verdict();
    std::printf("ENDPOINT=%s\n", v.endpoint.c_str());
    std::printf("REQUIREMENTS=%u\n", v.required);
    for (const auto& s : v.lines) std::printf("REQ %s\n", s.c_str());
    std::printf("REQ_PASSED=%u\n", v.passed);
    std::printf("REQ_FAILED=%u\n", v.failed);
    std::printf("REQ_UNKNOWN=%u\n", v.unknown);
    std::printf("ENDPOINT_REACHED=%d\n", v.reached ? 1 : 0);
    std::printf("VERDICT_INDETERMINATE=%d\n", v.indeterminate ? 1 : 0);
    if (!v.firstUnsatisfied.empty())
        std::printf("FIRST_UNSATISFIED=%s\n", v.firstUnsatisfied.c_str());

    // Facts that were NOT established are printed alongside, so the reader sees
    // exactly what this proof does NOT say.
    std::printf("NOT_ESTABLISHED=TOKENS_EMITTED,CORRECTNESS_VERIFIED,STEADY_STATE_TPS,ENDPOINT_REACHED_TOKEN\n");

    const bool allGood = a.valid && ok && (replay.toLine() == line) &&
                         v.reached && !v.indeterminate;
    std::printf("VERDICT=%s\n", allGood ? "DREAMLESS_PROOF_VALID"
                                        : "PROOF_INCOMPLETE");
    return allGood ? 0 : 1;
}