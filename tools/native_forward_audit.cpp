// ============================================================================
// native_forward_audit.cpp  --  RAWRXD Gate 4 native-forward dispatch audit
// ============================================================================
// Proves, against a REAL GGUF model running a REAL forward pass, that dispatch
// was honest:
//
//   1. every required forward operation executes
//   2. no UNAUTHORIZED fallback (nothing with an implemented GPU primitive ran
//      on the CPU while the GPU was requested)
//   3. no missing kernel silently becomes a success
//   4. all expected model layers execute
//   5. the forward pass produces finite logits
//   6. the host-derived counters (BindStats) agree EXACTLY with the recorded
//      dispatch events
//   7. binary + results tied to one source revision (commit SHA + binary SHA-256)
//
// Two configurations, each reported separately:
//   --config cpu-native  CPU is the requested backend; fallback forbidden
//   --config gpu-native  GPU is the requested backend;  fallback forbidden
//   --config both        run both, write a combined evidence object
//
// Exit code: 0 iff the run completed and, for the requested config(s), the gate
// PASSED. A config that fails is reported truthfully (exit 1), never faked.
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"
#include "dispatch_trace.hpp"

using RawrXD::Deep2::RuntimeGraph::Executor;
using RawrXD::Deep2::RuntimeGraph::DispatchTrace::Backend;
using RawrXD::Deep2::RuntimeGraph::DispatchTrace::GateInput;
using RawrXD::Deep2::RuntimeGraph::DispatchTrace::GateResult;
using namespace RawrXD::Deep2::Universal;   // Ingest, IngestReport, Provenance, GetProvenance, ModelSpec

// ---------------------------------------------------------------------------
// Minimal, self-contained SHA-256 (FIPS 180-4) for provenance.
// ---------------------------------------------------------------------------
namespace {
struct Sha256 {
    uint32_t h[8];
    uint64_t len = 0;
    uint8_t  buf[64];
    size_t   bufn = 0;

    Sha256() {
        static const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                       0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
        for (int i = 0; i < 8; ++i) h[i] = iv[i];
    }
    static uint32_t rotr(uint32_t x, int c) { return (x >> c) | (x << (32 - c)); }
    void block(const uint8_t* p) {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(p[i*4])<<24)|(uint32_t(p[i*4+1])<<16)|(uint32_t(p[i*4+2])<<8)|uint32_t(p[i*4+3]);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
            uint32_t ch = (e&f)^(~e&g);
            uint32_t t1 = hh+S1+ch+k[i]+w[i];
            uint32_t S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
            uint32_t maj = (a&b)^(a&c)^(b&c);
            uint32_t t2 = S0+maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    void update(const uint8_t* p, size_t n) {
        len += n;
        while (n) {
            size_t take = 64 - bufn; if (take > n) take = n;
            std::memcpy(buf + bufn, p, take); bufn += take; p += take; n -= take;
            if (bufn == 64) { block(buf); bufn = 0; }
        }
    }
    std::string final() {
        uint64_t bits = len * 8;
        uint8_t pad = 0x80; update(&pad, 1);
        uint8_t z = 0; while (bufn != 56) update(&z, 1);
        uint8_t lb[8]; for (int i=0;i<8;++i) lb[i]=uint8_t(bits>>(56-8*i));
        update(lb, 8);
        static const char* hx = "0123456789abcdef";
        std::string s; s.reserve(64);
        for (int i=0;i<8;++i) for (int j=28;j>=0;j-=4) s += hx[(h[i]>>j)&0xf];
        return s;
    }
};

std::string Sha256FileBytes(const std::string& path) {
    Sha256 sh; std::ifstream f(path, std::ios::binary); char b[65536];
    while (f) { f.read(b, sizeof(b)); sh.update((const uint8_t*)b, (size_t)f.gcount()); }
    return sh.final();
}

struct RunOutcome {
    GateResult gate;
    std::string json;
    bool ran = false;
};

RunOutcome RunConfig(const std::string& model, const std::string& cfgName,
                     bool gpu_native, const std::string& bin_sha,
                     const std::string& src_sha, const std::string& cmd,
                     uint32_t token, const std::string& gpu_name,
                     bool gpu_present)
{
    using namespace RawrXD::Deep2::RuntimeGraph::DispatchTrace;
    RunOutcome out;

    Reset();
    SetRunConfig(cfgName, gpu_native ? Backend::GPU : Backend::CPU);

    Executor ex;
    ex.SetForceCpu(!gpu_native);
    ex.SetOpTrace(true);

    const IngestReport& rep = Ingest(model, false);
    if (!rep.ok) {
        std::printf("  [FAIL] ingest: %s\n", rep.error.c_str());
        out.gate.gate_pass = false;
        out.gate.reason = std::string("ingest-failed: ") + rep.error;
        return out;
    }

    const bool bound = ex.Bind(rep);
    const auto& st = ex.Stats();
    std::printf("  bind ok=%d ops_total=%zu ops_bound=%zu ops_unbound=%zu weights=%zu\n",
                bound?1:0, st.ops_total, st.ops_bound, st.ops_unbound, st.weights_resolved);
    for (const auto& u : st.unbound_ops) std::printf("  UNBOUND: %s\n", u.c_str());

    const bool okExec = bound ? ex.ExecuteToken(token, 0) : false;
    const std::string execErr = ex.LastError();
    if (!okExec) std::printf("  [FAIL] forward: %s\n", execErr.c_str());

    // Finite-logits evidence computed explicitly here (independent witness).
    const std::vector<float>& logits = ex.Logits();
    uint64_t nonfinite = 0;
    double lmin = 0, lmax = 0, l2 = 0;
    for (size_t i = 0; i < logits.size(); ++i) {
        double v = logits[i];
        l2 += v * v;
        if (!std::isfinite(v)) { ++nonfinite; continue; }
        if (i == 0 || v < lmin) lmin = v;
        if (i == 0 || v > lmax) lmax = v;
    }
    const bool finite = okExec && nonfinite == 0 && !logits.empty();

    const Provenance& pv = GetProvenance();
    std::printf("  model arch=%s block_count=%llu tensor_count=%zu (geometry=255)\n",
                pv.architecture.c_str(),
                (unsigned long long)rep.spec.block_count, pv.tensor_count);
    std::printf("  logits=%zu nonfinite=%llu l2=%.6f min=%.6f max=%.6f execNonFinite=%zu\n",
                logits.size(), (unsigned long long)nonfinite, std::sqrt(l2), lmin, lmax,
                ex.NonFiniteLogits());
    std::printf("  host counters: gpu_calls=%llu cpu_calls=%llu fallback=%s\n",
                (unsigned long long)st.gpu_calls, (unsigned long long)st.cpu_calls,
                st.fallback_reason.empty() ? "(none)" : st.fallback_reason.c_str());

    GateInput in;
    in.source_sha      = src_sha;
    in.binary_sha256   = bin_sha;
    in.command         = cmd;
    in.model_path      = model;
    in.model_sha256    = pv.sha256;
    in.tensor_count    = pv.tensor_count;
    in.host_gpu_calls  = st.gpu_calls;   // HOST-derived, not recorder-asserted
    in.host_cpu_calls  = st.cpu_calls;
    in.program_ops     = st.ops_total;
    in.executed_ops    = ex.OpTraces().size();
    in.block_count     = rep.spec.block_count;
    in.have_gpu_device = gpu_present;
    in.gpu_device_name = gpu_name;
    in.logits_finite   = finite;
    in.nonfinite_logits= nonfinite;
    in.logits_count    = logits.size();

    out.gate = EvaluateGate(in);
    out.json = ToJson(in, out.gate);
    out.ran  = true;

    using namespace RawrXD::Deep2::RuntimeGraph::DispatchTrace;
    std::printf("  <summary matmul=%llu gpu=%llu cpu=%llu unauthorized_fallback=%llu "
                "declared_unimplemented=%llu silent_missing_kernel=%llu layers=%llu>\n",
                (unsigned long long)MatmulCount(), (unsigned long long)SelectedGPU(),
                (unsigned long long)SelectedCPU(), (unsigned long long)UnauthorizedFallback(),
                (unsigned long long)DeclaredUnimplemented(),
                (unsigned long long)SilentMissingKernelSuccess(), (unsigned long long)DistinctLayers());
    std::printf("  <conditions 1=%d 2=%d 3=%d 4=%d 5=%d 6=%d 7=%d native_complete=%d>\n",
                out.gate.cond1_all_ops_execute, out.gate.cond2_no_unauthorized_fallback,
                out.gate.cond3_no_silent_missing_kernel, out.gate.cond4_all_layers_execute,
                out.gate.cond5_finite_logits, out.gate.cond6_counters_agree,
                out.gate.cond7_provenance_tie, out.gate.native_forward_complete);
    std::printf("  GATE_%s: %s\n", cfgName.c_str(), out.gate.gate_pass ? "PASS" : "FAIL");
    std::printf("  reason: %s\n", out.gate.reason.c_str());
    return out;
}
}  // namespace

int main(int argc, char* argv[])
{
    std::ios::sync_with_stdio(false);
    std::string model, cfg = "both", jsonPath, srcSha, gpuName;
    uint32_t token = 1;
    bool gpuPresent = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? std::string(argv[++i]) : std::string(); };
        if (a == "--model") model = next();
        else if (a == "--config") cfg = next();
        else if (a == "--json") jsonPath = next();
        else if (a == "--source-sha") srcSha = next();
        else if (a == "--token") token = (uint32_t)std::strtoul(next().c_str(), nullptr, 10);
        else if (a == "--gpu-device") gpuName = next();
        else if (a == "--gpu-present") gpuPresent = true;
        else if (a == "--no-buf") {} else { std::printf("arg: %s\n", a.c_str()); }
    }
    if (model.empty()) {
        std::printf("usage: native_forward_audit --model <gguf> --config cpu-native|gpu-native|both "
                    "[--json path] [--source-sha SHA] [--token N] [--gpu-device name] [--gpu-present]\n");
        return 2;
    }
    // Build the exact command line recorded into the evidence.
    std::string cmd = argv[0];
    for (int i = 1; i < argc; ++i) { cmd += " "; cmd += argv[i]; }

    const std::string binSha = Sha256FileBytes(argv[0]);
    std::printf("=== RAWRXD Gate 4 native-forward dispatch audit ===\n");
    std::printf("config=%s model=%s\n", cfg.c_str(), model.c_str());
    std::printf("source_commit_sha=%s\n", srcSha.c_str());
    std::printf("binary_sha256=%s\n\n", binSha.c_str());

    auto save = [&](const std::string& content) {
        if (jsonPath.empty()) return;
        std::ofstream o(jsonPath, std::ios::binary);
        o << content;
        std::printf("wrote %s (%zu bytes)\n", jsonPath.c_str(), content.size());
    };

    bool overall_pass = true;
    std::vector<std::string> configJsons;

    if (cfg == "both" || cfg == "cpu-native") {
        std::printf("--- config A: cpu-native (fallback forbidden) ---\n");
        RunOutcome a = RunConfig(model, "cpu-native", /*gpu_native=*/false, binSha, srcSha,
                                 cmd, token, gpuName, gpuPresent);
        overall_pass = overall_pass && a.gate.gate_pass;
        configJsons.push_back(a.json);
        std::printf("\n");
    }
    if (cfg == "both" || cfg == "gpu-native") {
        std::printf("--- config B: gpu-native (fallback forbidden) ---\n");
        RunOutcome b = RunConfig(model, "gpu-native", /*gpu_native=*/true, binSha, srcSha,
                                 cmd, token, gpuName, gpuPresent);
        overall_pass = overall_pass && b.gate.gate_pass;
        configJsons.push_back(b.json);
        std::printf("\n");
    }

    if (cfg == "both") {
        std::ostringstream combined;
        combined << "{\n";
        combined << "  \"gate\": \"native_forward_dispatch_gate4\",\n";
        combined << "  \"source_commit_sha\": \"" << srcSha << "\",\n";
        combined << "  \"binary_sha256\": \"" << binSha << "\",\n";
        combined << "  \"overall_pass\": " << (overall_pass ? "true" : "false") << ",\n";
        combined << "  \"configs\": [\n";
        for (size_t i = 0; i < configJsons.size(); ++i) {
            combined << configJsons[i];
            combined << (i + 1 < configJsons.size() ? ",\n" : "\n");
        }
        combined << "  ]\n}\n";
        save(combined.str());
    } else if (!configJsons.empty()) {
        save(configJsons.back());
    }

    std::printf("=== OVERALL GATE: %s (exit %d) ===\n",
                overall_pass ? "PASS" : "FAIL", overall_pass ? 0 : 1);
    return overall_pass ? 0 : 1;
}
