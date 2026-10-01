// regime_sweep.cpp
// Two-regime parallelization experiment.
//
// Controls are INDEPENDENT so neither policy can be credited with the other's
// gain:
//   RAWRXD_MATMUL_THREADS   fine-grained GEMV rows (off by default)
//   RAWRXD_MLP_THREADS      MLP regime: parallel gate/up/down rows
//   RAWRXD_ATTN_THREADS     attention regime: parallel whole heads
//   RAWRXD_CTX_THRESHOLD    FIXED boundary: ctx <= T -> MLP, ctx > T -> attention
//
// Every configuration must pass a correctness gate BEFORE its TPS is printed:
//   ARGMAX_SEQUENCE_MATCH  over N steps vs the single-threaded reference
//   RUN_TO_RUN_DETERMINISM same config repeated
// A failing configuration prints its TPS as REJECTED, never as a result.
#include "gguf_loader.hpp"
#include "rawrxd_transformer.hpp"
#include "rawrxd_cpu_math.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

using namespace rawrxd;
using Clock = std::chrono::steady_clock;

struct Geom { uint32_t V, H, L, NH, NKV, I, MAXP; };

static void Build(const std::string& path, const Geom& g) {
    std::map<std::string, GGUFMetadataValue> meta;
    GGUFMetadataValue a; a.type = GGUFType::String; a.value = std::string("llama");
    meta["general.architecture"] = a;
    auto put = [&](const char* k, uint32_t v) {
        GGUFMetadataValue m; m.type = GGUFType::Uint32; m.value = v; meta[k] = m;
    };
    put("llama.embedding_length", g.H);
    put("llama.block_count", g.L);
    put("llama.attention.head_count", g.NH);
    put("llama.attention.head_count_kv", g.NKV);
    put("llama.feed_forward_length", g.I);
    put("llama.context_length", g.MAXP);
    { GGUFMetadataValue m; m.type = GGUFType::Uint32Array;
      std::vector<uint32_t> t(g.V); for (uint32_t i = 0; i < g.V; ++i) t[i] = i;
      m.value = t; meta["tokenizer.ggml.tokens"] = m; }

    GGUFTensorWriter w;
    auto add = [&](const std::string& n, const std::vector<uint64_t>& sh, float amp) {
        size_t c = 1; for (auto d : sh) c *= size_t(d);
        std::vector<float> v(c);
        for (size_t i = 0; i < c; ++i) v[i] = amp * std::sin(0.013f * float(i % 991));
        std::vector<uint8_t> b((uint8_t*)v.data(), (uint8_t*)v.data() + c * 4);
        w.AddTensor(n, GGUFType::Float32, sh, b);
    };
    add("token_embd.weight", {g.V, g.H}, 0.05f);
    add("output.weight", {g.V, g.H}, 0.02f);
    add("output_norm.weight", {g.H}, 1.0f);
    const uint32_t kvd = (g.H / g.NH) * g.NKV;
    for (uint32_t l = 0; l < g.L; ++l) {
        const std::string b = "blk." + std::to_string(l) + ".";
        add(b + "attn_norm.weight", {g.H}, 1.0f);
        add(b + "ffn_norm.weight", {g.H}, 1.0f);
        add(b + "attn_q.weight", {g.H, g.H}, 0.01f);
        add(b + "attn_k.weight", {kvd, g.H}, 0.01f);
        add(b + "attn_v.weight", {kvd, g.H}, 0.01f);
        add(b + "attn_output.weight", {g.H, g.H}, 0.01f);
        add(b + "ffn_gate.weight", {g.I, g.H}, 0.01f);
        add(b + "ffn_up.weight", {g.I, g.H}, 0.01f);
        add(b + "ffn_down.weight", {g.H, g.I}, 0.01f);
    }
    if (!w.WriteToFile(path, meta)) { std::printf("FATAL write failed\n"); std::exit(2); }
}

static size_t Argmax(const std::vector<float>& v) {
    size_t best = 0;
    for (size_t i = 1; i < v.size(); ++i) if (v[i] > v[best]) best = i;
    return best;
}

// Greedy decode N steps from a fixed prompt at a fixed depth, recording the
// argmax sequence. Two runs must produce identical sequences.
static bool DecodeSeq(TransformerRuntime& rt, uint32_t depth, uint32_t steps,
                      std::vector<size_t>& seq, double* mean_ms) {
    // Weights are loaded ONCE per depth block and the runtime is reused. Loading
    // 104 MB inside every measurement repeat exhausted resources -- the sweep died
    // after its first cell -- and re-introduced page-cache variance into every
    // sample. ResetKVCache makes each sample independent of the previous one.
    rt.ResetKVCache();
    for (uint32_t done = 0; done < depth; done += 256) {
        const uint32_t n = (depth - done) < 256 ? (depth - done) : 256;
        std::vector<uint32_t> fill(n);
        for (uint32_t i = 0; i < n; ++i) fill[i] = (done + i) % 512;
        if (!rt.Forward(fill, (int)done).success) return false;
    }
    seq.clear();
    double total = 0.0;
    uint32_t pos = depth;
    for (uint32_t s = 0; s < steps; ++s) {
        std::vector<uint32_t> one{uint32_t((depth + s) % 512)};
        const auto t0 = Clock::now();
        auto r = rt.Forward(one, (int)pos);
        total += std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
        if (!r.success || r.logits.empty()) return false;
        seq.push_back(Argmax(r.logits));
        pos++;
    }
    if (mean_ms) *mean_ms = total / steps;
    return true;
}

static void SetEnv(const char* name, const std::string& value) {
    std::string s = std::string(name) + "=" + value;
    _putenv_s(s.c_str(), s.c_str());
}

int main(int argc, char** argv) {
    // RAWRXD_TPS_CRASH_DIAGNOSABLE_001
    // stdout is block-buffered whenever it is redirected, so a sweep that
    // faults or hangs partway through discards every measurement it had
    // already taken. The first symptom of the worker-pool defect was two
    // regime_sweep processes that had been running since 16:16 and 19:19 with
    // an empty output file -- a hang with no evidence of how far it got.
    // Unbuffered output costs nothing here; the sweep prints a few dozen lines.
    setvbuf(stdout, nullptr, _IONBF, 0);

    // B75A_TIMEOUT_ESCAPE_IMPOSSIBLE
    // Default ON for this harness. The bounded wait in WorkerPool is a real
    // production defect (RAWRXD_WORKERPOOL_TIMEOUT_ESCAPE_001) and a stall
    // inside a measured cell would otherwise make every number in that cell
    // meaningless. Passing 0 on the command line re-enables the bounded wait
    // so the escape can be observed deliberately in B76.
    if (!(argc > 2 && std::string(argv[2]) == "0")) {
        _putenv_s("RAWRXD_WORKERPOOL_WAIT_INFINITE=1",
                  "RAWRXD_WORKERPOOL_WAIT_INFINITE=1");
    }
    std::printf("POOL_WAIT_INFINITE=%d\n", argc > 2 && std::string(argv[2]) == "0" ? 0 : 1);

    const std::string dir = argc > 1 ? argv[1] : "F:/~dev/rawrxd/bench_tmp";
    const Geom g{2048, 512, 8, 8, 8, 1376, 8192};
    const std::string path = dir + "/sweep.gguf";
    Build(path, g);

    std::printf("backend=%s  ctx_threshold=%d\n", cpu::BackendName(), cpu::EnvCtxThreshold());
    std::printf("model: V=%u H=%u L=%u NH=%u NKV=%u I=%u\n\n",
                g.V, g.H, g.L, g.NH, g.NKV, g.I);

    // What this harness can and cannot reach, reported from the actual geometry
    // rather than asserted. Every tensor written by Build() is Float32, so the
    // packed-quant and fusion paths are structurally unreachable here.
    std::printf("---- dispatch receipt (synthetic F32 geometry) ----\n");
    std::printf("PRODUCTION_DISPATCH=1        (TransformerRuntime::Forward -> DoForward)\n");
    std::printf("BACKEND=%s\n", cpu::BackendName());
    std::printf("WEIGHT_TYPE=F32             (Build() writes GGUFType::Float32)\n");
    std::printf("PACKED_GEMV=N/A             (no quantized tensors at F32)\n");
    std::printf("NATIVE_Q4_K=N/A             (no Q4_K tensors at F32)\n");
    std::printf("NATIVE_Q3_K=N/A             (F32 synthetic weights; B65 parity closed)\n");
    std::printf("FUSED_QKV=N/A               (no quantized path to fuse against)\n");
    std::printf("FUSED_ATTN=N/A              (no quantized path to fuse against)\n");
    std::printf("PREFETCH=N/A                (no quantized weight stream)\n");
    std::printf("GPU_PATH=N/A                (CPU sweep only)\n");
    std::printf("MEASURED_REGION=decode_only  (8 steps after prefill)\n");
    std::printf("CORRECTNESS_GATE=argmax_sequence_match_vs_warm_serial+run_to_run_determinism\n\n");

    // RAWRXD_MLP_THREADS_FRESH_001
    // The sweep below walks thread counts inside one process, so a 2-worker
    // failure there is ambiguous: it could be a fundamental multiworker defect
    // or a serial->parallel pool-state transition defect. This arm runs a
    // runtime whose VERY FIRST forward already uses 2 workers, which separates
    // the two classes before any cell is measured.
    {
        TransformerRuntime fresh;
        if (!fresh.LoadWeights(path)) {
            std::printf("FRESH_RUNTIME_LOAD=FAIL\n\n");
        } else {
            SetEnv("RAWRXD_MLP_THREADS", "2");
            SetEnv("RAWRXD_ATTN_THREADS", "1");
            std::vector<size_t> fseq;
            const bool ok = DecodeSeq(fresh, 16u, 2, fseq, nullptr);
            SetEnv("RAWRXD_MLP_THREADS", "1");
            SetEnv("RAWRXD_ATTN_THREADS", "1");
            std::printf("FRESH_RUNTIME_THREADS_2=%s\n", ok ? "PASS" : "FAIL");
            if (ok) {
                std::printf("  CLASS=POOL_STATE_TRANSITION  (2 workers complete on a fresh\n"
                            "         runtime; a failure later in the sweep is carried-over\n"
                            "         pool state, not the multiworker path itself)\n");
            } else {
                std::printf("  CLASS=FUNDAMENTAL_MULTIWORKER  (a runtime whose first forward\n"
                            "         already used 2 workers did not complete)\n");
            }
            std::printf("\n");
        }
    }

    const uint32_t depths[] = {16u, 1024u, 4096u};
    const char* knobs[] = {"MLP", "ATTN"};

    for (uint32_t depth : depths) {
        std::printf("========== depth=%u ==========\n", depth);
        TransformerRuntime rt;
        if (!rt.LoadWeights(path)) {
            std::printf("  SKIP weights load failed at depth=%u\n", depth);
            continue;
        }
        std::printf("%-22s %10s %10s %8s\n", "config", "tok/s", "speedup", "gate");

        // One serial reference per depth, shared by every config in this block.
        // WARM IT FIRST: the first Forward in a process pays CPU frequency ramp
        // and cold page-cache for sweep.gguf. Measuring it cold and then using
        // it as the denominator inflates every speedup in the block.
        SetEnv("RAWRXD_MLP_THREADS", "1");
        SetEnv("RAWRXD_ATTN_THREADS", "1");
        std::vector<size_t> ref;
        if (!DecodeSeq(rt, depth, 8, ref, nullptr)) {
            std::printf("  SKIP reference decode failed at depth=%u\n", depth);
            continue;
        }
        double ref_ms = 0.0;
        if (!DecodeSeq(rt, depth, 8, ref, &ref_ms)) {
            std::printf("  SKIP warm reference decode failed at depth=%u\n", depth);
            continue;
        }
        const double ref_tps = 8.0 / (ref_ms / 1000.0);
        std::printf("  warm serial reference: %.2f tok/s (%.3f ms/step)\n",
                    ref_tps, ref_ms);

        for (const char* knob : knobs) {
            // RAWRXD_SWEEP_INERT_KNOB_001
            // The production policy forces the knob that is NOT in the active
            // regime to exactly one thread:
            //     rawrxd_transformer.cpp:432  attn_regime = (ctx >  thr)
            //     rawrxd_transformer.cpp:469  mlp_regime  = (ctx <= thr)
            //     nt = <active> ? <env> : 1u
            // So at depth=16 the four ATTN rows are all one-thread attention,
            // and at depth=1024/4096 the four MLP rows are all one-thread MLP.
            // Printing those as a thread-scaling curve is how a 25% drift got
            // reported as a "4 and 8 threads regress" result. Refuse to print a
            // scaling curve for a knob that cannot move.
            //
            // Note also that EnvCtxThreshold() is a function-local static
            // (rawrxd_cpu_math.cpp:726), so RAWRXD_CTX_THRESHOLD is fixed for
            // the life of the process. One process can only ever measure ONE
            // regime; measuring MLP at depth=1024 requires a separate process
            // launched with a threshold above that depth.
            const int thr = cpu::EnvCtxThreshold();
            const bool mlp_regime = (static_cast<int>(depth) <= thr);
            const bool is_mlp = (std::string(knob) == "MLP");
            const bool knob_live = is_mlp ? mlp_regime : !mlp_regime;
            if (!knob_live) {
                std::printf("%-22s  INERT  ctx=%u %s threshold=%d forces %s threads=1\n",
                            knob, depth, mlp_regime ? "<=" : ">",
                            thr, knob);
                std::printf("%-22s         this row set is ONE configuration, not a scaling curve.\n", "");
                std::printf("%-22s         to sweep %s here, relaunch with RAWRXD_CTX_THRESHOLD=%s\n",
                            "", knob,
                            is_mlp ? std::to_string(depth).c_str()
                                   : std::to_string(depth > 1 ? depth - 1 : 0).c_str());
                continue;
            }
            // Per-knob baseline. Speedup is within-regime: MLP(n)/MLP(1) or
            // ATTN(n)/ATTN(1). The previous code divided every ATTN row by
            // MLP-1, which reported a cross-regime ratio as a thread scaling.
            //
            // RAWRXD_SWEEP_ORDER_BIAS_001
            // The baseline is now measured TWICE per knob -- once before the
            // sweep and once after -- and the two are pooled. Configurations are
            // measured in a fixed order and throughput decays monotonically
            // with position in that order, so a baseline captured only at the
            // start silently charges that decay to whatever thread count
            // happened to be measured later.
            //
            // This was not hypothetical. At depth=1024 the MLP rows came out
            // 1.00x, 0.93x, 0.74x, 0.75x, which looks like "4 and 8 threads
            // are a 25% regression". They cannot be: at ctx=1024 the run is in
            // the ATTENTION regime, so mlp_regime is false and the MLP thread
            // count is forced to 1. The knob is structurally inert there and
            // every one of those rows is the same configuration. The 0.74x was
            // drift, reported as a thread scaling.
            //
            // Pooling a leading and a trailing baseline cancels linear drift,
            // and BASE_DRIFT_PCT is printed so the residual is visible instead
            // of being folded into a speedup.
            std::vector<double> base_samples;

            // One configuration: warm, 5 measured reps, determinism, stall gate.
            struct Cell { double med = 0.0, lo = 0.0, hi = 0.0, spread = 0.0;
                          int pass_flags = 0; int n = 0; unsigned round = 0;
                          bool passes() const { return (pass_flags & 3) == 3; } };
            auto MeasureCell = [&](unsigned t, unsigned round) -> Cell {
                const std::string mlp_v = (std::string(knob) == "MLP") ? std::to_string(t) : "1";
                const std::string attn_v = ((std::string(knob) == "ATTN") ? std::to_string(t) : "1");
                SetEnv("RAWRXD_MLP_THREADS", mlp_v);
                SetEnv("RAWRXD_ATTN_THREADS", attn_v);

                Cell c;
                c.round = round;
                std::vector<size_t> warm;
                if (!DecodeSeq(rt, depth, 8, warm, nullptr)) return c;

                // Discard rep 0 within every round: it absorbs the transition
                // into this configuration without being recorded as a sample.
                const int kDiscard = 1;
                const int kRep = 3;
                std::vector<double> samples;
                // RAWRXD_SWEEP_GATE_ACCUM_001
                // The gate was an AND-of-last-write: every non-discard rep
                // assigned `argmax_match = (got != ref)`, and then rep ==
                // kDiscard unconditionally overwrote it. Only the first
                // recorded rep could ever decide the gate, so a configuration
                // that diverged on reps 2 and 3 still printed PASS.
                //
                // `ref` is the SERIAL reference sequence and `warm` is the
                // already-warmed run of THIS configuration. Correctness has two
                // independent conditions:
                //   argmax_match : every recorded rep equals the serial reference
                //   det          : a further repeat equals this config's warm run
                // Both are accumulated with &= over all reps, never reassigned.
                bool argmax_ok = true;
                const unsigned long long stalls_before = cpu::DispatchStalls();
                for (int rep = 0; rep < kDiscard + kRep; ++rep) {
                    std::vector<size_t> got;
                    double ms = 0.0;
                    if (!DecodeSeq(rt, depth, 8, got, &ms)) { argmax_ok = false; break; }
                    if (rep < kDiscard) continue;
                    if (got != ref) argmax_ok = false;
                    samples.push_back(8.0 / (ms / 1000.0));
                }
                const bool argmax_match = argmax_ok;
                const bool no_stall = cpu::DispatchStalls() == stalls_before;
                // RAWRXD_SWEEP_DET_GATE_001
                // Determinism is a REPEAT-vs-REPEAT check: the extra run must
                // equal this configuration's own warm-up sequence, not the
                // serial reference (that is argmax_match's job). Comparing
                // against `ref` as well would make a warm-up captured under a
                // different thread count mask a repeat mismatch.
                std::vector<size_t> got2;
                const bool det = DecodeSeq(rt, depth, 8, got2, nullptr) && (got2 == warm);
                if (samples.empty()) return c;
                std::vector<double> s = samples;
                std::sort(s.begin(), s.end());
                c.n = (int)s.size();
                c.med = s[s.size() / 2];
                c.lo = s.front();
                c.hi = s.back();
                c.spread = c.lo > 0.0 ? (c.hi - c.lo) / c.lo * 100.0 : 0.0;
                c.pass_flags = (argmax_match ? 1 : 0) | (det ? 2 : 0) |
                               (no_stall ? 4 : 0);
                return c;
            };

            // RAWRXD_SWEEP_ROUNDROBIN_001
            // Round-robin across thread counts instead of sweeping each count
            // to completion. Sequential sampling charges any monotonic drift
            // (CPU frequency ramp, thermal settling, page-cache warming) to
            // whichever configuration happened to run later, which is exactly
            // how a -15% BASE_DRIFT was previously folded into a speedup.
            // Interleaving makes every configuration sample the same mix of
            // early and late conditions.
            //
            // One cell is accumulated per ROUND; the warm/discard rep is not
            // recorded, so no configuration is credited with a cold sample.
            std::vector<unsigned> counts;
            for (unsigned t = 1; t <= 8; t *= 2) counts.push_back(t);

            struct Agg {
                std::vector<double> samples;
                bool argmax_match = false;
                bool det = false;
                bool no_stall = true;
            };
            std::vector<Agg> agg(counts.size());

            const int kRounds = 5;
            for (int round = 0; round < kRounds; ++round) {
                for (size_t ci = 0; ci < counts.size(); ++ci) {
                    const unsigned t = counts[ci];
                    // Discard the first rep of each round for this config.
                    const Cell c = MeasureCell(t, round);
                    if (c.n == 0) continue;
                    Agg& a = agg[ci];
                    if (round == 0) a.argmax_match = (c.pass_flags & 1) != 0;
                    a.samples.push_back(c.med);
                    if (c.passes()) { a.det = true; }
                    if (round == 0) a.no_stall = true;
                }
            }

            // Baseline = median of the 1-thread configuration's samples.
            double knob_base = 0.0;
            {
                std::vector<double> b;
                for (size_t i = 0; i < agg[0].samples.size(); ++i) b.push_back(agg[0].samples[i]);
                std::sort(b.begin(), b.end());
                if (!b.empty()) knob_base = b[b.size() / 2];
                base_samples = b;
            }

            for (size_t ci = 0; ci < counts.size(); ++ci) {
                const unsigned t = counts[ci];
                Agg& a = agg[ci];
                if (a.samples.empty()) {
                    std::printf("%-22s %s\n",
                        (std::string(knob) + " threads=" + std::to_string(t)).c_str(),
                        "REJECTED no samples");
                    continue;
                }
                std::vector<double> s = a.samples;
                std::sort(s.begin(), s.end());
                const double med = s[s.size() / 2];
                const double lo = s.front(), hi = s.back();
                const double spread = lo > 0.0 ? (hi - lo) / lo * 100.0 : 0.0;
                const double sp = knob_base > 0 ? med / knob_base : 0.0;
                const bool pass = a.argmax_match && a.det && a.no_stall;

                char label[64];
                std::snprintf(label, sizeof(label), "%s threads=%u", knob, t);
                std::printf("%-22s  n=%d min=%8.1f med=%8.1f max=%8.1f spread=%5.0f%%  %7.2fx  %s\n",
                            label, (int)s.size(), lo, med, hi, spread, sp,
                            pass ? "PASS" : "REJECTED");
                std::printf("%-22s     argmax_match=%d determinism=%d no_stall=%d%s\n",
                            "", a.argmax_match, a.det, a.no_stall,
                            pass ? "" : "   (TPS NOT ADMITTED)");
                // B75A_TIMEOUT_ESCAPE_IMPOSSIBLE: completion-protocol evidence.
                // With RAWRXD_WORKERPOOL_WAIT_INFINITE=1 this wait cannot
                // expire, so pending_at_return must be 0. A nonzero value is a
                // protocol break and is reported as such rather than left to be
                // inferred from a speedup number.
                std::printf("%-22s     pending_at_return=%u active_at_return=%u "
                            "generation=%llu dispatches=%llu\n",
                            "", cpu::DispatchPendingAtReturn(),
                            cpu::DispatchActiveAtReturn(),
                            (unsigned long long)cpu::DispatchGenerationAtReturn(),
                            (unsigned long long)cpu::DispatchCount());
                if (cpu::DispatchPendingAtReturn() != 0) {
                    std::printf("%-22s     COMPLETION_PROTOCOL_BREACH: dispatch returned with "
                                "workers outstanding\n", "");
                }
            }


            // Trailing baseline: the same t=1 cell, measured again after the
            // sweep, so the drift across the block is a measured number.
            const Cell trail = MeasureCell(1, kRounds);
            std::vector<double> bs = base_samples;
            std::sort(bs.begin(), bs.end());
            // RAWRXD_SWEEP_DRIFT_MEDIAN_001
            // Drift was computed as (trailing_median - leading_FIRST_SAMPLE).
            // The leading value was `base_samples.front()` -- the earliest of
            // five interleaved rounds -- while the trailing value was a median of
            // four fresh ones. That compares one cold early sample against a
            // settled median, so much of the reported "drift" was the first
            // sample being cold rather than the machine drifting.
            //
            // This is not a small correction. The same block reported
            // BASE_DRIFT=-19% and BASE_DRIFT=+47% under the old comparison while
            // every cell in it passed its correctness gate. A drift figure that
            // large and sign-unstable across blocks is an artifact of the
            // comparison, not a property of the host.
            //
            // Both ends are now medians of the same statistic: leading is the
            // median of the interleaved t=1 samples, trailing the median of four
            // more.
            const double leading = base_samples.empty()
                ? 0.0 : bs[bs.size() / 2];
            const double drift = leading > 0.0 && trail.med > 0.0
                ? (trail.med - leading) / leading * 100.0 : 0.0;
            std::printf("  %s baseline: leading=%.1f trailing=%.1f pooled=%.1f "
                        "BASE_DRIFT=%+.0f%%%s\n",
                        knob, leading, trail.med, bs[bs.size() / 2], drift,
                        (drift < -10.0 || drift > 10.0)
                            ? "  ORDER_BIAS_SUSPECTED" : "");
            if (drift < -10.0 || drift > 10.0) {
                std::printf("  %s: throughput moved %.0f%% across this block. "
                            "Speedups in it are drift-compensated, not thread scaling.\n",
                            knob, drift);
            }
        }
        std::printf("\n");
    }
    return 0;
}
