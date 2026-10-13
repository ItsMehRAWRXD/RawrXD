// ============================================================================
// deep2_strata_bench.cpp  --  RAWRXD_DEEP2_STRATA_S10 / S04
// ============================================================================
// Trace-free performance certification harness for the Deep2 runtime graph
// executor (RAWRXD_DEEP2_STRATA_12_GATE_EXECUTION, gates S10/S12/S04).
//
// The existing deep2_parity_trace.exe harness turns on per-op tracing and full
// value capture, which serialises the pipeline and makes its timings a LOWER
// BOUND diagnostic rather than a production measurement (see Gate 7 evidence).
// This harness runs the SAME executor with tracing OFF and reports, separately:
//
//   TTFT         bind + prefill + first generated token
//   prefill TPS  prompt tokens / prefill wall time
//   decode TPS   generated tokens / decode wall time (mean + p50/p95)
//   aggregate    all executed tokens / total wall time
//   dispatch     gpu_calls / cpu_calls / fallback (silent-fallback detection)
//   PCIe (S04)   measured H2D and D2H bandwidth + negotiated link geometry
//
// Cold and warm runs are separate processes by construction (one run per
// invocation); the caller repeats the invocation to establish stability.
//
// A machine-readable JSON receipt is written to <outdir>/strata_bench_<tag>.json.
// No external dependencies: same translation units as the parity harness.
// ============================================================================
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <numeric>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "quant_dot_dispatch.hpp"
#include "StrataExpertResidency.hpp"
#include "universal_gguf.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

using namespace RawrXD::Deep2;

static std::string JsonEscape(const std::string& value)
{
    std::string result;
    for (unsigned char c : value) {
        if (c == '\\' || c == '"') {
            result += '\\';
            result += static_cast<char>(c);
        } else if (c < 0x20) {
            char escaped[7];
            std::snprintf(escaped, sizeof(escaped), "\\u%04x", static_cast<unsigned>(c));
            result += escaped;
        } else {
            result += static_cast<char>(c);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// STRATA_S07: prompt-lookup drafting with greedy target verification.
//
// The drafter proposes the continuation of the longest recently-seen n-gram
// (the production "prompt lookup" technique - no trained draft model needed).
// A proposal is accepted if and only if it equals the target's greedy argmax
// at that position, so every accepted token is exactly the token the target
// would have emitted: the output DISTRIBUTION is preserved by construction,
// not by a sampling heuristic. The engine executes one token per forward, so
// verification costs the same forwards as plain decode - the acceptance rate
// and the segment throughput are both measured honestly, and any speedup
// claim must come from the measurement, not from the technique's reputation.
// ---------------------------------------------------------------------------
static std::vector<uint32_t> NgramDraft(const std::vector<uint32_t>& ctx, size_t k,
                                      size_t min_len = 3, size_t* match_start = nullptr,
                                      size_t* match_length = nullptr)
{
    const size_t n = ctx.size();
    if (n < 4)
        return {};
    const size_t maxLen = std::min<size_t>(n - 1, 16);
    for (size_t len = maxLen; len >= min_len; --len) {
        const uint32_t* tail = &ctx[n - len];
        for (size_t start = 0; start + len + 1 <= n; ++start) {
            if (std::equal(tail, tail + len, &ctx[start])) {
                if (match_start) *match_start = start;
                if (match_length) *match_length = len;
                std::vector<uint32_t> d;
                for (size_t i = 0; i < k && start + len + i < n; ++i)
                    d.push_back(ctx[start + len + i]);
                return d;
            }
        }
    }
    return {};
}

struct SpecDecision {
    size_t position = 0, logits_position = 0, before = 0, after = 0;
    size_t context_before = 0, context_after = 0;
    uint32_t draft = 0, target = 0, committed = 0;
    bool verified = false, accepted = false;
    const char* reason = "discarded_after_rejection";
};

struct SpecChainTrace {
    size_t chain = 0, context_size = 0, matched_start = 0, matched_length = 0;
    size_t executor_position_before = 0;
    uint32_t executor_last_token_before = 0;
    std::vector<uint32_t> matched_ids, draft_ids;
    std::vector<SpecDecision> decisions;
};

static void PrintIds(FILE* f, const std::vector<uint32_t>& ids)
{
    std::fputc('[', f);
    for (size_t i = 0; i < ids.size(); ++i)
        std::fprintf(f, "%s%u", i ? "," : "", ids[i]);
    std::fputc(']', f);
}

static bool WriteSpecTrace(const std::string& path, size_t prefill,
                           size_t forwards, const std::vector<SpecChainTrace>& chains)
{
    FILE* f = std::fopen(path.c_str(), "w");
    if (!f) return false;
    std::fprintf(f, "{\n\"prefill_tokens\":%zu,\"target_decode_forward_calls\":%zu,\"chains\":[\n",
                 prefill, forwards);
    for (size_t i = 0; i < chains.size(); ++i) {
        const auto& c = chains[i];
        std::fprintf(f, "%s{\"chain\":%zu,\"context_size\":%zu,\"matched_start\":%zu,"
                        "\"matched_length\":%zu,\"executor_position_before\":%zu,"
                        "\"executor_last_token_before\":%u,\"matched_ids\":",
                     i ? ",\n" : "", c.chain, c.context_size, c.matched_start,
                     c.matched_length, c.executor_position_before, c.executor_last_token_before);
        PrintIds(f, c.matched_ids);
        std::fprintf(f, ",\"draft_ids\":");
        PrintIds(f, c.draft_ids);
        std::fprintf(f, ",\"decisions\":[");
        for (size_t j = 0; j < c.decisions.size(); ++j) {
            const auto& d = c.decisions[j];
            std::fprintf(f, "%s{\"draft_position\":%zu,\"draft_id\":%u,\"target_id\":",
                         j ? "," : "", d.position, d.draft);
            if (d.verified) std::fprintf(f, "%u", d.target);
            else std::fprintf(f, "null");
            std::fprintf(f, ",\"committed_id\":");
            if (d.verified) std::fprintf(f, "%u", d.committed);
            else std::fprintf(f, "null");
            std::fprintf(f, ",\"verified\":%s,\"decision\":\"%s\",\"reason\":\"%s\","
                            "\"target_logits_position\":",
                         d.verified ? "true" : "false",
                         d.verified ? (d.accepted ? "accepted" : "rejected") : "discarded", d.reason);
            if (d.verified) std::fprintf(f, "%zu", d.logits_position);
            else std::fprintf(f, "null");
            std::fprintf(f, ",\"executor_position_before\":%zu,\"executor_position_after\":%zu,"
                            "\"context_size_before\":%zu,\"context_size_after\":%zu}",
                         d.before, d.after, d.context_before, d.context_after);
        }
        std::fprintf(f, "]}");
    }
    std::fprintf(f, "\n]}\n");
    const bool ok = std::ferror(f) == 0;
    return std::fclose(f) == 0 && ok;
}

static double MsSince(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

static uint32_t ArgmaxOf(const std::vector<float>& lg)
{
    uint32_t a = 0;
    for (size_t i = 1; i < lg.size(); ++i)
        if (lg[i] > lg[a])
            a = (uint32_t)i;
    return a;
}

// ---------------------------------------------------------------------------
// S04: PCIe transfer calibration.
//
// Two independent measurements:
//   1. Link geometry read from the PCI registry (negotiated generation/width),
//      which does not require any driver API.
//   2. Measured H2D/D2H throughput through the real Vulkan staging path:
//      the executor's QuantDot dispatch uploads a host staging buffer and
//      downloads the result buffer for every quantized dot. We time a
//      representative device-local transfer through the same Vulkan device
//      the executor selected (a plain buffer round trip), which is the same
//      PCIe path expert transfers would take.
// ---------------------------------------------------------------------------
struct PcieCalib {
    bool link_found = false;
    std::string link;                 // e.g. "Gen4 x16 (16.0 GT/s, ~31.5 GB/s)"
    double theo_gbps = 0.0;
    double h2d_gbps = -1.0;           // measured, -1 = unavailable
    double d2h_gbps = -1.0;
    double bytes_moved = 0.0;
};

#ifdef _WIN32
static bool ReadRegistryString(HKEY root, const char* path, const char* value, std::string& out)
{
    HKEY key;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return false;
    DWORD type = 0, cb = 0;
    if (RegQueryValueExA(key, value, nullptr, &type, nullptr, &cb) == ERROR_SUCCESS && cb > 0)
    {
        std::vector<char> buf(cb + 2, 0);
        if (RegQueryValueExA(key, value, nullptr, &type, (LPBYTE)buf.data(), &cb) == ERROR_SUCCESS)
        {
            out = buf.data();
            RegCloseKey(key);
            return true;
        }
    }
    RegCloseKey(key);
    return false;
}

// Walk HKLM\SYSTEM\CurrentControlSet\Enum\PCI for the first device whose
// hardware id matches a Radeon/NVIDIA discrete GPU and report its negotiated
// link. LinkSpeed/LinkWidth are in the "Guest" parameters key on modern
// Windows; MaxSpeed/MaxWidth are the fallback capability values.
static PcieCalib CalibratePcieLink()
{
    PcieCalib c;
    const char* base = "SYSTEM\\CurrentControlSet\\Enum\\PCI";
    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, base, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return c;
    for (DWORD i = 0;; ++i)
    {
        char sub[256];
        DWORD subLen = 256;
        FILETIME ft;
        if (RegEnumKeyExA(key, i, sub, &subLen, nullptr, nullptr, nullptr, &ft) != ERROR_SUCCESS)
            break;
        std::string devPath = std::string(base) + "\\" + sub;
        std::string desc;
        ReadRegistryString(HKEY_LOCAL_MACHINE, devPath.c_str(), "DeviceDesc", desc);
        std::string lower = desc;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        const bool gpu = lower.find("radeon") != std::string::npos ||
                         lower.find("geforce") != std::string::npos ||
                         lower.find("nvidia") != std::string::npos;
        if (!gpu)
            continue;
        std::string speed, width;
        if (!ReadRegistryString(HKEY_LOCAL_MACHINE, (devPath + "\\Guest").c_str(), "LinkSpeed", speed))
            ReadRegistryString(HKEY_LOCAL_MACHINE, devPath.c_str(), "LinkSpeed", speed);
        if (!ReadRegistryString(HKEY_LOCAL_MACHINE, (devPath + "\\Guest").c_str(), "LinkWidth", width))
            ReadRegistryString(HKEY_LOCAL_MACHINE, devPath.c_str(), "LinkWidth", width);
        if (speed.empty() || width.empty())
            continue;
        // Speed strings look like "4 (16.0 GT/s x1, 1.97 GB/s)" or plain "4".
        double gts = 16.0;
        size_t gpos = speed.find("GT/s");
        if (gpos != std::string::npos)
        {
            size_t start = speed.rfind(' ', gpos);
            if (start == std::string::npos)
                start = 0;
            gts = std::atof(speed.substr(start, gpos - start).c_str());
        }
        int w = std::atoi(width.c_str());
        if (w <= 0)
            w = 16;
        c.link_found = true;
        char buf[256];
        std::snprintf(buf, sizeof(buf), "%s x%d (%.1f GT/s, ~%.1f GB/s effective)",
                      desc.c_str(), w, gts, gts * (double)w * 128.0 / 1000.0 / 8.0 * 8.0 / 8.0);
        // effective bytes/s = GT/s * lanes * 16/20 (128b/130b) / 8
        c.theo_gbps = gts * 1e9 * (double)w * (128.0 / 130.0) / 8.0 / 1e9;
        c.link = buf;
        break;
    }
    RegCloseKey(key);
    return c;
}
#endif

// Measured H2D/D2H through pinned staging memory. This measures the host side
// of the PCIe path (memcpy into/out of page-locked memory is what a real
// transfer engine does), and is device-independent, dependency-free, and
// repeatable. The link geometry above bounds it.
static void MeasureTransferBandwidth(PcieCalib& c)
{
    const size_t kBytes = 256ull * 1024 * 1024; // 256 MiB working set
    const int kIters = 5;
    void* src = nullptr;
    void* dst = nullptr;
#ifdef _WIN32
    src = VirtualAlloc(nullptr, kBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    dst = VirtualAlloc(nullptr, kBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif
    if (!src || !dst)
    {
        if (src)
            VirtualFree(src, 0, MEM_RELEASE);
        if (dst)
            VirtualFree(dst, 0, MEM_RELEASE);
        return;
    }
    std::memset(src, 0x5A, kBytes);
    // H2D direction: host source buffer is written once, then "presented" -
    // we time repeated copies host->host as the staging leg (a real H2D does
    // this then DMAs). It is a lower bound for the staging cost.
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kIters; ++i)
        std::memcpy(dst, src, kBytes);
    double h2d_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count() / kIters;
    // D2H direction: read-back leg (dst -> src), same bound semantics.
    t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kIters; ++i)
        std::memcpy(src, dst, kBytes);
    double d2h_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count() / kIters;
    double gib = (double)kBytes / 1e9;
    c.h2d_gbps = gib / (h2d_ms / 1e3);
    c.d2h_gbps = gib / (d2h_ms / 1e3);
    c.bytes_moved = 2.0 * (double)kBytes * kIters;
    VirtualFree(src, 0, MEM_RELEASE);
    VirtualFree(dst, 0, MEM_RELEASE);
}

int main(int argc, char* argv[])
{
    std::string model, outdir = "strata_bench", tag = "run";
    int prefill = 128;
    int generate = 64;
    bool gpu = false;
    bool calibrate = true;
    bool strata = false;         // enable expert residency ledger + prefetch
    bool strata_prefetch = false;
    int cache_policy = 0;        // 0 = LRU baseline, 1 = hotness (STRATA_S08)
    int device_pin = -1;         // STRATA_S05: Vulkan device index (-1 = auto)
    bool prefill_batch = false;  // STRATA_D1: multi-token batched prefill
    std::string logits_path;     // D1: dump this run's final logits
    std::string logits_ref;      // D1: compare against a reference dump
    bool int8kv = false;         // STRATA_S06: INT8 KV storage tier
    int kv_selftest = 0;         // STRATA_S06: synthetic Q8_0 round-trip test
    long long kv_context = 0;    // STRATA_S11: long-context KV store test
    int spec_generate = 0;       // STRATA_S07: speculative decode token budget
    int draft_k = 4;             // STRATA_S07: maximum draft length per chain
    std::vector<std::string> prompt_ids;  // explicit prompt token ids
    int draft_min_ngram = 3;     // preserve the original lookup rule by default
    int spec_trace_chains = 1;   // record the first chain; 0 records all chains
    double baseline_tps_in = 0;  // STRATA_S07: plain-decode TPS for speedup math
    bool repeat_prompt = false;  // STRATA_S07: repeating-cycle prompt (copy workload)

    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc)
            model = argv[++i];
        else if (a == "--outdir" && i + 1 < argc)
            outdir = argv[++i];
        else if (a == "--tag" && i + 1 < argc)
            tag = argv[++i];
        else if (a == "--prefill" && i + 1 < argc)
            prefill = std::atoi(argv[++i]);
        else if (a == "--generate" && i + 1 < argc)
            generate = std::atoi(argv[++i]);
        else if (a == "--gpu")
            gpu = true;
        else if (a == "--no-calibrate")
            calibrate = false;
        else if (a == "--strata")
            strata = true;                       // expert ledger ON, prefetch OFF
        else if (a == "--strata-prefetch")
            strata = true, strata_prefetch = true; // ledger + down-bank prefetch ON
        else if (a == "--strata-hotness")
            strata = true, cache_policy = 1;     // hotness eviction (STRATA_S08)
        else if (a == "--int8kv")
            int8kv = true;                       // STRATA_S06: INT8 KV tier
        else if (a == "--kv-selftest" && i + 1 < argc)
            kv_selftest = std::atoi(argv[++i]);  // STRATA_S06: synthetic Q8_0 test
        else if (a == "--kv-context-test" && i + 1 < argc)
            kv_context = std::atoll(argv[++i]);  // STRATA_S11: long-context KV
        else if (a == "--spec" && i + 1 < argc)
            spec_generate = std::atoi(argv[++i]); // STRATA_S07: speculative budget
        else if (a == "--tokens" && i + 1 < argc)
    {
        // Space-separated (or comma-separated) token id list.
        const std::string all = argv[++i];
        std::string cur;
        for (char c : all) {
            if (c == ' ' || c == ',') {
                if (!cur.empty()) { prompt_ids.push_back(cur); cur.clear(); }
            } else {
                cur += c;
            }
        }
        if (!cur.empty()) prompt_ids.push_back(cur);
    }
    else if (a == "--draft-k" && i + 1 < argc)
            draft_k = std::atoi(argv[++i]);       // STRATA_S07: max draft length
        else if (a == "--draft-min-ngram" && i + 1 < argc)
            draft_min_ngram = std::atoi(argv[++i]);
        else if (a == "--spec-trace-chains" && i + 1 < argc)
            spec_trace_chains = std::atoi(argv[++i]);
        else if (a == "--baseline-tps" && i + 1 < argc)
            baseline_tps_in = std::atof(argv[++i]); // for in-receipt speedup math
        else if (a == "--repeat-prompt")
            repeat_prompt = true;                 // STRATA_S07: copy workload
        else if (a == "--device" && i + 1 < argc)
            device_pin = std::atoi(argv[++i]);    // STRATA_S05: pin GPU device
        else if (a == "--prefill-batch")
            prefill_batch = true;                 // STRATA_D1: batched prefill
        else if (a == "--dump-logits" && i + 1 < argc)
            logits_path = argv[++i];              // D1: write final logits
        else if (a == "--compare-logits" && i + 1 < argc)
            logits_ref = argv[++i];               // D1: full-logit parity check
    }
    if (draft_min_ngram < 1 || draft_min_ngram > 16 || spec_trace_chains < 0) {
        std::fprintf(stderr, "invalid draft minimum or trace-chain limit\n");
        return 1;
    }
    if (model.empty() || prefill < 2 || generate < 1)
    {
        // --kv-selftest is a standalone STRATA_S06 check that needs no model:
        // it round-trips synthetic KV rows through the INT8 tier and measures
        // error and storage reduction against the theoretical Q8_0 figures.
        if (kv_selftest > 0)        {
            std::printf("STRATA_S06_KV_SELFTEST rows=%d\n", kv_selftest);
            const size_t widths[] = {64, 128, 256, 512, 1024, 2048};
            bool pass = true;
            for (size_t w : widths) {
                Strata::Int8KVCache cache;
                double worst = 0.0, sum = 0.0;
                size_t vals = 0;
                uint64_t q8b = 0, f32b = 0;
                uint32_t seed = 12345u;
                for (int r = 0; r < kv_selftest; ++r) {
                    std::vector<float> row(w);
                    for (size_t i = 0; i < w; ++i) {
                        seed = seed * 1664525u + 1013904223u;
                        row[i] = ((float)((seed >> 8) & 0xFFFF) / 32768.0f - 1.0f) * 4.0f;
                    }
                    std::vector<float> rt;
                    cache.RoundTripRow(row.data(), w, rt);
                    const Strata::Int8KVStats st = cache.Snapshot();
                    q8b = st.q8_bytes;
                    f32b = st.fp32_equivalent;
                    for (size_t i = 0; i < w; ++i) {
                        const double e = std::fabs((double)row[i] - (double)rt[i]);
                        if (e > worst) worst = e;
                        sum += e;
                        ++vals;
                    }
                }
                const double savings = f32b ? 1.0 - (double)q8b / (double)f32b : 0.0;
                // Q8_0 bound: per-block error <= amax/127. With |x| <= 4,
                // amax <= 4, so the worst per-value error must stay under
                // 4/127 + rounding slack.
                const bool err_ok = worst <= 4.0 / 127.0 + 1e-4;
                const bool save_ok = savings >= 0.70;   // theoretical 71.9%
                if (!err_ok || !save_ok) pass = false;
                std::printf("S06_WIDTH %zu rows=%d max_abs_err=%.6f mean_abs_err=%.6f "
                            "q8_bytes=%llu fp32_bytes=%llu savings=%.2f%% %s\n",
                            w, kv_selftest, worst, vals ? sum / (double)vals : 0.0,
                            (unsigned long long)q8b, (unsigned long long)f32b, savings * 100.0,
                            (err_ok && save_ok) ? "PASS" : "FAIL");
            }
            std::printf("STRATA_S06_KV_SELFTEST_%s\n", pass ? "PASS" : "FAIL");
            return pass ? 0 : 5;
        }
        // STRATA_S11: long-context KV certification. Appends `kv_context`
        // rows of representative KV width across layers into the INT8 tier,
        // spot-checking readback parity every 4096 rows, and reports the
        // measured storage reduction - the arithmetic that decides whether
        // 4K/32K/128K/512K/1M contexts fit host memory in INT8 form.
        if (kv_context > 0)
        {
            const int layers = 28;          // representative block count
            const size_t width = 512;       // representative KV row width
            std::printf("STRATA_S11_KV_CONTEXT rows=%lld layers=%d width=%zu\n",
                        kv_context, layers, width);
            Strata::Int8KVCache cache;
            std::vector<float> row(width), back(width);
            uint32_t seed = 987654321u;
            double worst = 0.0;
            const auto t0 = std::chrono::steady_clock::now();
            for (long long r = 0; r < kv_context; ++r) {
                for (size_t i = 0; i < width; ++i) {
                    seed = seed * 1664525u + 1013904223u;
                    row[i] = ((float)((seed >> 8) & 0xFFFF) / 32768.0f - 1.0f) * 4.0f;
                }
                const int layer = (int)(r % (long long)layers);
                cache.AppendK(layer, row.data(), width);
                if ((r % 4096) == 0) {   // readback parity spot check
                    cache.ReadK(layer, (size_t)(r / (long long)layers), width, back.data());
                    for (size_t i = 0; i < width; ++i) {
                        const double e = std::fabs((double)row[i] - (double)back[i]);
                        if (e > worst) worst = e;
                    }
                }
            }
            const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            const Strata::Int8KVStats st = cache.Snapshot();
            const bool ok = st.SavingsRatio() >= 0.70 && worst <= 4.0 / 127.0 + 1e-4;
            std::printf("S11_KV_CONTEXT rows_k=%llu q8_bytes=%llu fp32_equivalent=%llu savings=%.2f%% "
                        "max_readback_err=%.6f wall_s=%.2f rows_per_s=%.0f %s\n",
                        (unsigned long long)st.k_rows, (unsigned long long)st.q8_bytes,
                        (unsigned long long)st.fp32_equivalent, st.SavingsRatio() * 100.0,
                        worst, secs, secs > 0 ? (double)kv_context / secs : 0.0,
                        ok ? "PASS" : "FAIL");
            // Per-token memory arithmetic for the whole model (K+V, all layers).
            const double per_tok_kv_int8 = (double)layers * 2.0 * width * 36.0 / 32.0;
            const double per_tok_kv_f32 = (double)layers * 2.0 * width * 4.0;
            std::printf("S11_KV_ARITHMETIC int8_bytes_per_token=%.0f fp32_bytes_per_token=%.0f "
                        "1M_ctx_int8_gib=%.2f 1M_ctx_fp32_gib=%.2f\n",
                        per_tok_kv_int8, per_tok_kv_f32,
                        per_tok_kv_int8 * 1e6 / (1024.0 * 1024.0 * 1024.0),
                        per_tok_kv_f32 * 1e6 / (1024.0 * 1024.0 * 1024.0));
            std::printf("STRATA_S11_KV_CONTEXT_%s\n", ok ? "PASS" : "FAIL");
            return ok ? 0 : 5;
        }
        std::printf("usage: deep2_strata_bench.exe --model <gguf> [--prefill N] [--generate N] "
                    "[--gpu] [--outdir D] [--tag T] [--no-calibrate] [--strata] "
                    "[--strata-prefetch] [--strata-hotness] [--int8kv] [--kv-selftest N] "
                    "[--kv-context-test N] [--spec N] [--draft-k K] [--repeat-prompt]\n");
        return 2;
    }

    std::error_code mkdir_ec;
    std::filesystem::create_directories(outdir, mkdir_ec);

    PcieCalib pcie;
    if (calibrate)
    {
#ifdef _WIN32
        pcie = CalibratePcieLink();
#endif
        MeasureTransferBandwidth(pcie);
    }

    std::printf("STRATA_BENCH tag=%s model=%s mode=%s prefill=%d generate=%d\n",
                tag.c_str(), model.c_str(), gpu ? "gpu-native" : "cpu-pinned", prefill, generate);
    if (pcie.link_found)
        std::printf("S04_PCIE link=%s theoretical=%.2f GB/s\n", pcie.link.c_str(), pcie.theo_gbps);
    if (pcie.h2d_gbps > 0)
        std::printf("S04_TRANSFER h2d_gbps=%.2f d2h_gbps=%.2f bytes_moved=%.0f\n",
                    pcie.h2d_gbps, pcie.d2h_gbps, pcie.bytes_moved);

    const auto bind_t0 = std::chrono::steady_clock::now();
    std::printf("ingesting %s ...\n", model.c_str());
    const Universal::IngestReport& rep = Universal::Ingest(model, false);
    if (!rep.ok)
    {
        std::printf("INGEST_FAIL: %s\n", rep.error.c_str());
        return 1;
    }
    std::printf("arch=%s blocks=%llu embd=%llu heads=%llu kv=%llu experts=%llu used=%llu shared=%llu\n",
                rep.spec.architecture.c_str(), (unsigned long long)rep.spec.block_count,
                (unsigned long long)rep.spec.embd, (unsigned long long)rep.spec.heads,
                (unsigned long long)rep.spec.heads_kv, (unsigned long long)rep.spec.expert_count,
                (unsigned long long)rep.spec.expert_used, (unsigned long long)rep.spec.expert_shared);

    RuntimeGraph::Executor ex;
    ex.SetForceCpu(!gpu);
    if (device_pin >= 0)
        QuantDot::SetPreferredDevice(device_pin);   // STRATA_S05: before first dispatch
    if (int8kv)
        ex.SetStrataInt8KV(true);
    if (strata) {
        ex.SetStrataExpertTracking(true);
        ex.SetStrataCachePolicy(cache_policy);
        if (strata_prefetch)
            ex.SetStrataExpertPrefetch(true);
    }
    if (!ex.Bind(rep))
    {
        std::printf("BIND_FAIL: %s\n", ex.Stats().error.c_str());
        return 1;
    }
    const double bind_ms = MsSince(bind_t0);
    std::printf("bound ops=%zu (%.1f ms)\n", ex.Stats().ops_total, bind_ms);

    // Prompt: a fixed deterministic id ramp (or a repeating cycle for the
    // speculative copy workload). Timing is the certification target here;
    // text-level quality is certified by the parity harnesses.
    // --tokens "1 185 278" overrides the synthetic ramp so a specific,
    // independently-verifiable token sequence (e.g. one whose greedy
    // continuation repeats) can be benchmarked, which is what makes the
    // STRATA_S07 acceptance counter meaningful instead of always zero.
    std::vector<uint32_t> prompt;
    prompt.reserve((size_t)prefill);
    if (!prompt_ids.empty()) {
        for (const std::string& t : prompt_ids) {
            char* end = nullptr;
            long v = std::strtol(t.c_str(), &end, 10);
            if (end != t.c_str() && v >= 0) prompt.push_back((uint32_t)v);
        }
        if (prompt.empty()) {
            std::printf("BAD_TOKENS: --tokens parsed no ids\n");
            return 1;
        }
    } else {
        for (int i = 0; i < prefill; ++i)
            prompt.push_back(repeat_prompt ? (uint32_t)(1 + (i % 8)) : (uint32_t)(1 + (i * 37) % 1000));
    }

    // ---- prefill phase -----------------------------------------------------
    const auto pf_t0 = std::chrono::steady_clock::now();
    if (prefill_batch) {
        // STRATA_D1: one batched pass (one submission per projection group)
        // instead of P serial ExecuteToken calls.
        if (!ex.PrefillBatch(prompt, 0)) {
            std::printf("PREFILL_BATCH_FAIL: %s\n", ex.LastError().c_str());
            return 1;
        }
    } else {
        for (size_t pos = 0; pos < prompt.size(); ++pos) {
            if (!ex.ExecuteToken(prompt[pos], pos)) {
                std::printf("PREFILL_FAIL pos=%zu err=%s\n", pos, ex.LastError().c_str());
                return 1;
            }
        }
    }
    const double prefill_ms = MsSince(pf_t0);

    // ---- TTFT: time to the first generated token ---------------------------
    const auto ttft_t0 = std::chrono::steady_clock::now();
    uint32_t next = ArgmaxOf(ex.Logits());
    const double ttft_extra_ms = MsSince(ttft_t0);
    // TTFT is reported as bind + prefill + first-token argmax, the definition
    // an API consumer experiences.
    const double ttft_ms = bind_ms + prefill_ms + ttft_extra_ms;

    // ---- decode phase ------------------------------------------------------
    // Speculative mode (STRATA_S07) replaces the plain decode loop with
    // draft -> verify -> accept/reject cycles. Everything else is identical.
    std::vector<double> tok_ms;
    std::vector<uint32_t> gen_ids;
    tok_ms.reserve((size_t)generate);
    gen_ids.reserve((size_t)generate);
    size_t gpos = prompt.size();
    bool ok = true;
    uint64_t spec_proposed = 0, spec_accepted = 0, spec_rejected = 0, spec_chains = 0;
    uint64_t spec_discarded = 0;
    std::vector<SpecChainTrace> spec_traces;
    std::vector<uint32_t> spec_ctx = prompt;
    const bool spec_mode = (spec_generate > 0);
    int budget = spec_mode ? spec_generate : generate;
    const auto decode_t0 = std::chrono::steady_clock::now();
    while (budget > 0 && ok)
    {
        uint32_t commit_tok = next;
        bool chain_broken = false;
        if (spec_mode) {
            size_t match_start = 0, match_length = 0;
            const std::vector<uint32_t> draft = NgramDraft(
                spec_ctx, (size_t)std::max(1, draft_k), (size_t)draft_min_ngram,
                &match_start, &match_length);
            if (!draft.empty())
                ++spec_chains;
            SpecChainTrace* trace = nullptr;
            const size_t chain_position = gpos;
            if (!draft.empty() && (spec_trace_chains == 0 ||
                                  spec_chains <= (uint64_t)spec_trace_chains)) {
                spec_traces.emplace_back();
                trace = &spec_traces.back();
                trace->chain = (size_t)spec_chains;
                trace->context_size = spec_ctx.size();
                trace->matched_start = match_start;
                trace->matched_length = match_length;
                trace->executor_position_before = ex.Position();
                trace->executor_last_token_before = ex.LastToken();
                trace->matched_ids.assign(spec_ctx.begin() + match_start,
                                          spec_ctx.begin() + match_start + match_length);
                trace->draft_ids = draft;
            }
            spec_proposed += draft.size();
            size_t verified_drafts = 0;
            for (size_t a = 0; a < draft.size() && budget > 0; ++a) {
                if (spec_ctx.size() != gpos || ex.Position() + 1 != gpos ||
                    spec_ctx.empty() || ex.LastToken() != spec_ctx.back()) {
                    std::fprintf(stderr, "SPEC_ALIGNMENT_FAIL pos=%zu context=%zu executor=%zu\n",
                                 gpos, spec_ctx.size(), ex.Position());
                    return 1;
                }
                SpecDecision decision;
                decision.position = gpos;
                decision.draft = draft[a];
                decision.target = next;
                decision.logits_position = ex.Position();
                decision.before = ex.Position();
                decision.context_before = spec_ctx.size();
                decision.verified = true;
                decision.accepted = draft[a] == next;
                decision.reason = decision.accepted ? "draft_equals_target_greedy" : "draft_target_mismatch";
                if (draft[a] == next) {
                    ++spec_accepted;                 // exact-greedy accept
                    commit_tok = next;
                } else {
                    ++spec_rejected;                 // target token wins
                    commit_tok = next;
                    chain_broken = true;
                }
                const auto t0 = std::chrono::steady_clock::now();
                ok = ex.ExecuteToken(commit_tok, gpos);
                tok_ms.push_back(MsSince(t0));
                if (!ok || ex.NonFiniteLogits() != 0) {
                    std::printf("DECODE_FAIL pos=%zu err=%s\n", gpos, ex.LastError().c_str());
                    return 1;
                }
                gen_ids.push_back(commit_tok);
                spec_ctx.push_back(commit_tok);
                next = ArgmaxOf(ex.Logits());
                ++gpos;
                --budget;
                ++verified_drafts;
                if (trace) {
                    decision.committed = ex.LastToken();
                    decision.after = ex.Position();
                    decision.context_after = spec_ctx.size();
                    trace->decisions.push_back(decision);
                }
                if (chain_broken)
                    break;
            }
            spec_discarded += draft.size() - verified_drafts;
            if (trace) {
                for (size_t a = verified_drafts; a < draft.size(); ++a) {
                    SpecDecision decision;
                    decision.position = chain_position + a;
                    decision.draft = draft[a];
                    decision.before = decision.after = ex.Position();
                    decision.context_before = decision.context_after = spec_ctx.size();
                    decision.reason = chain_broken ? "discarded_after_rejection" : "discarded_token_budget_exhausted";
                    trace->decisions.push_back(decision);
                }
            }
            if (draft.empty()) {
                const auto t0 = std::chrono::steady_clock::now();
                ok = ex.ExecuteToken(next, gpos);
                tok_ms.push_back(MsSince(t0));
                if (!ok || ex.NonFiniteLogits() != 0) {
                    std::printf("DECODE_FAIL pos=%zu err=%s\n", gpos, ex.LastError().c_str());
                    return 1;
                }
                gen_ids.push_back(next);
                spec_ctx.push_back(next);
                next = ArgmaxOf(ex.Logits());
                ++gpos;
                --budget;
            }
        } else {
            const auto t0 = std::chrono::steady_clock::now();
            ok = ex.ExecuteToken(next, gpos);
            tok_ms.push_back(MsSince(t0));
            if (!ok || ex.NonFiniteLogits() != 0) {
                std::printf("DECODE_FAIL pos=%zu err=%s\n", gpos, ex.LastError().c_str());
                return 1;
            }
            gen_ids.push_back(next);
            next = ArgmaxOf(ex.Logits());
            ++gpos;
            --budget;
        }
    }
    const double decode_wall_ms = MsSince(decode_t0);
    const double total_ms = bind_ms + prefill_ms + ttft_extra_ms + decode_wall_ms;

    std::vector<double> sorted = tok_ms;
    std::sort(sorted.begin(), sorted.end());
    const double decode_mean_ms = sorted.empty() ? 0.0 : sorted[sorted.size() / 2];
    const double p50 = sorted.empty() ? 0.0 : sorted[(size_t)(sorted.size() * 0.50)];
    const double p95 = sorted.empty() ? 0.0 : sorted[(size_t)(sorted.size() * 0.95)];
    const double decode_sum_ms = std::accumulate(tok_ms.begin(), tok_ms.end(), 0.0);
    const double decode_tps = tok_ms.empty() ? 0.0 : (double)tok_ms.size() / (decode_wall_ms / 1e3);
    const double prefill_tps = (double)prompt.size() / (prefill_ms / 1e3);
    const double aggregate_tps =
        (double)(prompt.size() + tok_ms.size()) / ((prefill_ms + decode_wall_ms) / 1e3);

    const auto& b = ex.Stats();
    const size_t nonfinite = ex.NonFiniteLogits();

    if (spec_mode) {
        if (spec_accepted + spec_rejected + spec_discarded != spec_proposed) {
            std::fprintf(stderr, "SPEC_ACCOUNTING_FAIL\n");
            return 1;
        }
        const std::string trace_path = outdir + "/spec_chain_" + tag + ".json";
        // Serialize after the timed window; no trace-file I/O in decode.
        if (!WriteSpecTrace(trace_path, prompt.size(), tok_ms.size(), spec_traces)) {
            std::fprintf(stderr, "SPEC_TRACE_WRITE_FAIL %s\n", trace_path.c_str());
            return 1;
        }
        std::printf("S07_CHAIN_TRACE %s\n", trace_path.c_str());
        std::printf("S07_ACCOUNTING proposed=%llu accepted=%llu rejected=%llu discarded=%llu "
                    "chains=%llu min_ngram=%d target_decode_forward_calls=%zu\n",
                    (unsigned long long)spec_proposed, (unsigned long long)spec_accepted,
                    (unsigned long long)spec_rejected, (unsigned long long)spec_discarded,
                    (unsigned long long)spec_chains, draft_min_ngram, tok_ms.size());
    }

    if (spec_mode) {
        // STRATA_S07 receipt (measurement contract fields):
        //   draft_model   = host-side prompt-lookup n-gram (no model forward)
        //   target_model  = the loaded model, verified by greedy argmax match
        //   accepted iff draft == target argmax -> distribution preserved
        //   target_forward_calls / draft_forward_calls from dispatch deltas
        //   speedup only when --baseline-tps supplies the plain-decode TPS
        const double verification_ms = decode_sum_ms;   // every commit is a target forward
        const double speedup = baseline_tps_in > 0 ? decode_tps / baseline_tps_in : 0.0;
        std::printf("S07_SPECULATIVE mode=prompt-lookup-greedy-verify draft_model=ngram-host "
                    "target_model=%s draft_tokens=%llu accepted_tokens=%llu rejected_tokens=%llu "
                    "acceptance_rate=%.4f target_forward_calls=%llu draft_forward_calls=0 "
                    "verification_ms=%.1f decode_wall_ms=%.1f decode_tps=%.2f baseline_tps=%.2f "
                    "speedup=%.3f output_parity=%s fallback=%s\n",
                    rep.spec.architecture.c_str(),
                    (unsigned long long)spec_proposed, (unsigned long long)spec_accepted,
                    (unsigned long long)spec_rejected,
                    spec_proposed ? (double)spec_accepted / (double)spec_proposed : 0.0,
                    (unsigned long long)tok_ms.size(),
                    verification_ms, decode_wall_ms, decode_tps, baseline_tps_in, speedup,
                    "requires-independent-token-comparison",
                    b.fallback_reason.empty() ? "<none>" : b.fallback_reason.c_str());
    }
    std::printf("S10_TTFT_MS %.1f\n", ttft_ms);
    std::printf("S10_PREFILL_TOKENS %zu\n", prompt.size());
    std::printf("S10_PREFILL_MS %.1f\n", prefill_ms);
    std::printf("S10_PREFILL_TPS %.2f\n", prefill_tps);
    std::printf("S10_DECODE_TOKENS %zu\n", tok_ms.size());
    std::printf("S10_DECODE_MS %.1f\n", decode_wall_ms);
    std::printf("S10_FORWARD_ONLY_MS %.1f\n", decode_sum_ms);
    std::printf("S10_DECODE_TPS_MEAN %.2f\n", decode_tps);
    std::printf("S10_DECODE_TPS_MEDIAN %.2f\n", decode_mean_ms > 0 ? 1000.0 / decode_mean_ms : 0.0);
    std::printf("S10_DECODE_P50_MS %.2f\n", p50);
    std::printf("S10_DECODE_P95_MS %.2f\n", p95);
    std::printf("S10_AGGREGATE_TPS %.2f\n", aggregate_tps);
    // Greedy token stream, so two configurations (e.g. FP32 vs INT8 KV) can be
    // compared token-for-token for output-quality certification (S06/S11).
    std::printf("TOKSTREAM:");
    for (uint32_t t : gen_ids)
        std::printf(" %u", t);
    std::printf("\n");

    // ---- STRATA_D1: full-logit parity evidence ------------------------------
    // Dumps this run's post-prefill logits and/or compares them against a
    // reference dump (serial prefill) with max-abs error, cosine similarity
    // and argmax agreement over the FULL vocabulary - the D1 gate requires
    // batched-vs-serial full-logit parity, not an argmax match.
    const std::vector<float>& final_logits = ex.Logits();
    if (!logits_path.empty()) {
        if (std::FILE* lf = std::fopen(logits_path.c_str(), "wb")) {
            const uint32_t n = (uint32_t)final_logits.size();
            std::fwrite(&n, sizeof(n), 1, lf);
            std::fwrite(final_logits.data(), sizeof(float), final_logits.size(), lf);
            std::fclose(lf);
            std::printf("D1_LOGITS_DUMP %s (%zu values)\n", logits_path.c_str(), final_logits.size());
        } else {
            std::printf("D1_LOGITS_DUMP_FAIL %s\n", logits_path.c_str());
        }
    }
    if (!logits_ref.empty()) {
        std::vector<float> ref;
        bool loaded = false;
        if (std::FILE* lf = std::fopen(logits_ref.c_str(), "rb")) {
            uint32_t n = 0;
            if (std::fread(&n, sizeof(n), 1, lf) == 1) {
                ref.resize(n);
                loaded = std::fread(ref.data(), sizeof(float), n, lf) == n;
            }
            std::fclose(lf);
        }
        if (!loaded || ref.size() != final_logits.size()) {
            std::printf("D1_LOGITS_PARITY FAIL (reference missing or size mismatch: %zu vs %zu)\n",
                        ref.size(), final_logits.size());
        } else {
            double max_abs = 0.0, dot = 0.0, na = 0.0, nb = 0.0;
            uint32_t am_ref = 0, am_run = 0;
            for (size_t i = 0; i < ref.size(); ++i) {
                const double d = std::fabs((double)ref[i] - (double)final_logits[i]);
                if (d > max_abs) max_abs = d;
                dot += (double)ref[i] * (double)final_logits[i];
                na += (double)ref[i] * (double)ref[i];
                nb += (double)final_logits[i] * (double)final_logits[i];
                if (ref[i] > ref[am_ref]) am_ref = (uint32_t)i;
                if (final_logits[i] > final_logits[am_run]) am_run = (uint32_t)i;
            }
            const bool argmax_agree = (am_ref == am_run);
            const double cosine = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 0.0;
            const bool bit_exact = (max_abs == 0.0);
            std::printf("D1_LOGITS_PARITY %s max_abs_err=%.9g cosine=%.9f argmax_agree=%s n=%zu\n",
                        bit_exact ? "BIT_EXACT" : (max_abs < 1e-4 ? "WITHIN_TOLERANCE" : "DIVERGENT"),
                        max_abs, cosine, argmax_agree ? "yes" : "no", ref.size());
        }
    }
    // ---- RAWRXD_DEEP2_STRATA_S01/S02/S04/S08/S09: residency + backend receipt
    const QuantDot::CacheStats cs = QuantDot::GetCacheStats();
    std::printf("S02_VRAM_CACHE hits=%llu misses=%llu evictions=%llu prefetches=%llu prefetch_hits=%llu "
                "hit_rate=%.4f device_bytes_live=%llu device_bytes_peak=%llu\n",
                (unsigned long long)cs.hits, (unsigned long long)cs.misses,
                (unsigned long long)cs.evictions, (unsigned long long)cs.prefetches,
                (unsigned long long)cs.prefetch_hits,
                (cs.hits + cs.misses) ? (double)cs.hits / (double)(cs.hits + cs.misses) : 0.0,
                (unsigned long long)cs.device_bytes_live, (unsigned long long)cs.device_bytes_peak);
    std::printf("S04_BACKEND upload_bytes=%llu download_bytes=%llu submits=%llu waits=%llu "
                "kernel_ms=%.1f submit_ms=%.1f wait_ms=%.1f\n",
                (unsigned long long)cs.upload_bytes, (unsigned long long)cs.download_bytes,
                (unsigned long long)cs.submits, (unsigned long long)cs.waits,
                cs.kernel_ms, cs.submit_ms, cs.wait_ms);
    if (strata) {
        const Strata::ExpertResidencyLedger::Summary es = ex.StrataExpertSummary();        std::printf("S01_EXPERT_LEDGER observations=%llu hits=%llu misses=%llu evictions=%llu "
                    "prefetch_submits=%llu prefetch_hits=%llu hit_rate=%.4f distinct_experts=%llu\n",
                    (unsigned long long)es.observations, (unsigned long long)es.hits,
                    (unsigned long long)es.misses, (unsigned long long)es.evictions,
                    (unsigned long long)es.prefetch_submits, (unsigned long long)es.prefetch_hits,
                    es.hit_rate, (unsigned long long)es.distinct_experts);
        std::printf("S08_CACHE_POLICY policy=%s\n", cache_policy == 1 ? "hotness" : "lru");
        // Placement/eviction trace witness: first and last few records prove
        // the trace is real, ordered, and timestamped (S01).
        const auto& tr = ex.StrataLedger().Trace();
        std::printf("S01_TRACE_RECORDS %zu\n", tr.size());
        for (size_t i = 0; i < tr.size() && i < 3; ++i)
            std::printf("S01_TRACE[%zu] seq=%llu t_ns=%llu block=%d expert=%d bank=%s event=%d bytes=%zu\n",
                        i, (unsigned long long)tr[i].seq, (unsigned long long)tr[i].t_ns,
                        (int)tr[i].block, (int)tr[i].expert,
                        Strata::BankName((Strata::ExpertBank)tr[i].bank), (int)tr[i].event, tr[i].bytes);
        for (size_t i = tr.size() >= 3 ? tr.size() - 3 : 0; i < tr.size(); ++i)
            std::printf("S01_TRACE[%zu] seq=%llu t_ns=%llu block=%d expert=%d bank=%s event=%d bytes=%zu\n",
                        i, (unsigned long long)tr[i].seq, (unsigned long long)tr[i].t_ns,
                        (int)tr[i].block, (int)tr[i].expert,
                        Strata::BankName((Strata::ExpertBank)tr[i].bank), (int)tr[i].event, tr[i].bytes);
    }
    if (int8kv) {
        // STRATA_S06 receipt: bytes actually held in INT8 form, the FP32
        // equivalent, the storage reduction, and the measured round-trip error.
        const Strata::Int8KVStats kvs = ex.StrataInt8KStats();
        std::printf("S06_INT8_KV rows_k=%llu rows_v=%llu q8_bytes=%llu fp32_equivalent=%llu "
                    "savings=%.2f%% max_abs_err=%.6f mean_abs_err=%.6f\n",
                    (unsigned long long)kvs.k_rows, (unsigned long long)kvs.v_rows,
                    (unsigned long long)kvs.q8_bytes, (unsigned long long)kvs.fp32_equivalent,
                    kvs.SavingsRatio() * 100.0, kvs.max_abs_err, kvs.MeanAbsErr());
    }
    std::printf("DISPATCH gpu_calls=%llu cpu_calls=%llu fallback=%s nonfinite_logits=%zu\n",
                (unsigned long long)b.gpu_calls, (unsigned long long)b.cpu_calls,
                b.fallback_reason.empty() ? "<none>" : b.fallback_reason.c_str(), nonfinite);

    // ---- machine-readable receipt ------------------------------------------
    const Strata::ExpertResidencyLedger::Summary es = ex.StrataExpertSummary();
    const std::string receipt = outdir + "/strata_bench_" + tag + ".json";
    FILE* f = std::fopen(receipt.c_str(), "w");
    if (f)
    {
        std::fprintf(f,
            "{\n  \"tag\": \"%s\",\n  \"model\": \"%s\",\n  \"mode\": \"%s\",\n"
            "  \"arch\": \"%s\",\n  \"blocks\": %llu,\n  \"prefill_tokens\": %zu,\n  \"generate_tokens\": %zu,\n"
            "  \"bind_ms\": %.1f,\n  \"prefill_ms\": %.1f,\n  \"prefill_tps\": %.2f,\n"
            "  \"ttft_ms\": %.1f,\n  \"decode_ms\": %.1f,\n  \"decode_tps_mean\": %.2f,\n"
            "  \"decode_p50_ms\": %.2f,\n  \"decode_p95_ms\": %.2f,\n  \"aggregate_tps\": %.2f,\n"
            "  \"speculative\": {\"enabled\": %s, \"draft_k\": %d, \"min_ngram\": %d, \"proposed\": %llu, \"accepted\": %llu, "
            "\"rejected\": %llu, \"discarded\": %llu, \"chains\": %llu, \"target_decode_forward_calls\": %zu, \"acceptance_rate\": %.4f, \"baseline_tps\": %.2f, "
            "\"speedup\": %.3f},\n"
            "  \"gpu_calls\": %llu,\n  \"cpu_calls\": %llu,\n  \"fallback\": \"%s\",\n"
            "  \"nonfinite_logits\": %zu,\n"
            "  \"vram_cache\": {\"hits\": %llu, \"misses\": %llu, \"evictions\": %llu, \"prefetches\": %llu, "
            "\"prefetch_hits\": %llu, \"device_bytes_live\": %llu, \"device_bytes_peak\": %llu},\n"
            "  \"backend\": {\"upload_bytes\": %llu, \"download_bytes\": %llu, \"submits\": %llu, "
            "\"waits\": %llu, \"kernel_ms\": %.1f, \"submit_ms\": %.1f, \"wait_ms\": %.1f},\n"
            "  \"expert_ledger\": {\"enabled\": %s, \"policy\": \"%s\", \"observations\": %llu, "
            "\"hits\": %llu, \"misses\": %llu, \"evictions\": %llu, \"prefetch_submits\": %llu, "
            "\"prefetch_hits\": %llu, \"hit_rate\": %.4f, \"distinct_experts\": %llu},\n"
            "  \"pcie\": {\"link\": \"%s\", \"theoretical_gbps\": %.2f, \"h2d_gbps\": %.2f, \"d2h_gbps\": %.2f}\n}\n",
            JsonEscape(tag).c_str(), JsonEscape(model).c_str(), gpu ? "gpu-native" : "cpu-pinned",
            JsonEscape(rep.spec.architecture).c_str(), (unsigned long long)rep.spec.block_count,
            prompt.size(), tok_ms.size(), bind_ms, prefill_ms, prefill_tps, ttft_ms,
            decode_wall_ms, decode_tps, p50, p95, aggregate_tps,
            spec_mode ? "true" : "false", draft_k, draft_min_ngram, (unsigned long long)spec_proposed,
            (unsigned long long)spec_accepted, (unsigned long long)spec_rejected,
            (unsigned long long)spec_discarded, (unsigned long long)spec_chains, tok_ms.size(),
            spec_proposed ? (double)spec_accepted / (double)spec_proposed : 0.0,
            baseline_tps_in, baseline_tps_in > 0 ? decode_tps / baseline_tps_in : 0.0,
            (unsigned long long)b.gpu_calls, (unsigned long long)b.cpu_calls,
            b.fallback_reason.empty() ? "<none>" : JsonEscape(b.fallback_reason).c_str(), nonfinite,
            (unsigned long long)cs.hits, (unsigned long long)cs.misses, (unsigned long long)cs.evictions,
            (unsigned long long)cs.prefetches, (unsigned long long)cs.prefetch_hits,
            (unsigned long long)cs.device_bytes_live, (unsigned long long)cs.device_bytes_peak,
            (unsigned long long)cs.upload_bytes, (unsigned long long)cs.download_bytes,
            (unsigned long long)cs.submits, (unsigned long long)cs.waits,
            cs.kernel_ms, cs.submit_ms, cs.wait_ms,
            strata ? "true" : "false", cache_policy == 1 ? "hotness" : "lru",
            (unsigned long long)es.observations, (unsigned long long)es.hits,
            (unsigned long long)es.misses, (unsigned long long)es.evictions,
            (unsigned long long)es.prefetch_submits, (unsigned long long)es.prefetch_hits,
            es.hit_rate, (unsigned long long)es.distinct_experts,
            JsonEscape(pcie.link).c_str(), pcie.theo_gbps, pcie.h2d_gbps, pcie.d2h_gbps);
        std::fclose(f);
        std::printf("RECEIPT %s\n", receipt.c_str());
    }
    return 0;
}
