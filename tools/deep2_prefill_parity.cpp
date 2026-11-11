// ============================================================================
// deep2_prefill_parity.cpp -- H11-P1..P4 numerical parity, H11-P6 counters
// ============================================================================
// The batched prefill path may only be optimised (H11-P5 command fusion) once
// it is proven to produce the SAME result as the serial reference for the same
// tokens, weights, device, precision mode and initial KV state.
//
// The reference and the candidate run in SEPARATE PROCESSES on purpose. A
// single process holding two executors shares process-wide device state
// (the quant-dot command-buffer pool and the dot-batch state are documented as
// process-wide), and creating a second executor after the first has run a full
// forward pass was observed to kill the process without output. Two processes
// share nothing: identical GGUF input, identical token sequence, and a byte
// dump of the cache is the only thing compared.
//
//   deep2_prefill_parity.exe --model M --tokens K --role serial --dump a.bin
//   deep2_prefill_parity.exe --model M --tokens K --role batch  --dump b.bin
//   deep2_prefill_parity.exe --compare a.bin b.bin --tokens K
//
// Comparison order is deliberate: raw bytes first (bit-exact is the strict
// target), then max_abs, RMSE and cosine so a legitimate floating-point
// execution difference is recognised as such rather than being reported as
// either "equal" or "garbage".
// ============================================================================

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "deep2_tokenizer.hpp"

using namespace RawrXD::Deep2;
using RawrXD::Deep2::RuntimeGraph::Executor;
using RawrXD::Deep2::Universal::GetTokenizer;
using RawrXD::Deep2::Universal::Ingest;
using RawrXD::Deep2::Universal::IngestReport;
using deep2tools::SpEncoder;

namespace
{

struct Args
{
    std::string model;
    std::string dump;
    std::string compare[2];
    std::string role;         // "serial" or "batch"
    size_t tokens = 0;
    bool verbose = false;
};

Args Parse(int argc, char* argv[])
{
    Args a;
    for (int i = 1; i < argc; ++i)
    {
        const std::string s = argv[i];
        if (s == "--model" && i + 1 < argc) a.model = argv[++i];
        else if (s == "--tokens" && i + 1 < argc) a.tokens = (size_t)std::strtoull(argv[++i], nullptr, 10);
        else if (s == "--role" && i + 1 < argc) a.role = argv[++i];
        else if (s == "--dump" && i + 1 < argc) a.dump = argv[++i];
        else if (s == "--compare" && i + 2 < argc)
        {
            a.compare[0] = argv[++i];
            a.compare[1] = argv[++i];
        }
        else if (s == "-v") a.verbose = true;
    }
    return a;
}

// ---------------------------------------------------------------- dump format
struct DumpHeader
{
    char magic[8] = {'D', '2', 'P', 'A', 'R', 'I', 'T', 'Y'};
    uint32_t version = 1;
    uint32_t blocks = 0;
    uint32_t rows = 0;
    uint32_t width_k = 0;
    uint32_t width_v = 0;
    uint32_t logits_count = 0;
    uint64_t kv_floats = 0;
};

struct Dump
{
    DumpHeader h;
    std::vector<float> k;  // blocks * rows * width_k
    std::vector<float> v;  // blocks * rows * width_v
    std::vector<float> logits;
    bool ok = false;
};

bool WriteDump(const std::string& path, const Dump& d)
{
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    bool ok = std::fwrite(&d.h, sizeof(d.h), 1, f) == 1;
    if (ok && d.h.kv_floats) ok = std::fwrite(d.k.data(), sizeof(float), d.k.size(), f) == d.k.size();
    if (ok && !d.v.empty()) ok = std::fwrite(d.v.data(), sizeof(float), d.v.size(), f) == d.v.size();
    if (ok && d.h.logits_count)
        ok = std::fwrite(d.logits.data(), sizeof(float), d.logits.size(), f) == d.logits.size();
    std::fclose(f);
    return ok;
}

Dump ReadDump(const std::string& path)
{
    Dump d;
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return d;
    if (std::fread(&d.h, sizeof(d.h), 1, f) != 1)
    {
        std::fclose(f);
        return d;
    }
    if (std::memcmp(d.h.magic, "D2PARITY", 8) != 0 || d.h.version != 1)
    {
        std::fclose(f);
        return d;
    }
    const size_t nk = (size_t)d.h.blocks * (size_t)d.h.rows * (size_t)d.h.width_k;
    const size_t nv = (size_t)d.h.blocks * (size_t)d.h.rows * (size_t)d.h.width_v;
    d.k.resize(nk);
    d.v.resize(nv);
    d.logits.resize(d.h.logits_count);
    if (nk && std::fread(d.k.data(), sizeof(float), nk, f) != nk) { std::fclose(f); return {}; }
    if (nv && std::fread(d.v.data(), sizeof(float), nv, f) != nv) { std::fclose(f); return {}; }
    if (d.h.logits_count && std::fread(d.logits.data(), sizeof(float), d.h.logits_count, f) != d.h.logits_count)
    { std::fclose(f); return {}; }
    std::fclose(f);
    d.ok = true;
    return d;
}

Dump Capture(const Executor& ex, const std::vector<float>& logits)
{
    Dump d;
    d.h.blocks = (uint32_t)ex.KvBlocks();
    d.h.rows = 0;
    for (size_t b = 0; b < d.h.blocks; ++b) d.h.rows = std::max<size_t>(d.h.rows, ex.KvRows((int)b));
    d.h.width_k = 0;
    d.h.width_v = 0;
    for (size_t b = 0; b < d.h.blocks; ++b)
    {
        if (d.h.width_k == 0) d.h.width_k = (uint32_t)ex.KvRowWidthK((int)b);
        if (d.h.width_v == 0) d.h.width_v = (uint32_t)ex.KvRowWidthV((int)b);
    }
    const size_t nk = (size_t)d.h.blocks * (size_t)d.h.rows * (size_t)d.h.width_k;
    const size_t nv = (size_t)d.h.blocks * (size_t)d.h.rows * (size_t)d.h.width_v;
    d.k.assign(nk, 0.0f);
    d.v.assign(nv, 0.0f);
    d.h.kv_floats = nk + nv;
    for (size_t b = 0; b < d.h.blocks; ++b)
    {
        const size_t wk = (size_t)ex.KvRowWidthK((int)b);
        const size_t wv = (size_t)ex.KvRowWidthV((int)b);
        for (size_t p = 0; p < (size_t)d.h.rows; ++p)
        {
            const std::vector<float> kr = ex.KvKRow((int)b, p);
            if (!kr.empty()) std::memcpy(&d.k[b * (size_t)d.h.rows * wk + p * wk], kr.data(), wk * sizeof(float));
            const std::vector<float> vr = ex.KvVRow((int)b, p);
            if (!vr.empty()) std::memcpy(&d.v[b * (size_t)d.h.rows * wv + p * wv], vr.data(), wv * sizeof(float));
        }
    }
    d.h.logits_count = (uint32_t)logits.size();
    d.logits = logits;
    d.ok = true;
    return d;
}

int RunRole(const Args& args, const IngestReport& rep, SpEncoder& enc)
{
    // Build a token pool deterministically from the tokenizer so the serial and
    // batch processes derive byte-identical token ids.
    const std::string filler = "int compute() { int x = 0; for (int i = 0; i < 16; ++i) x += i; return x; }\n";
    std::vector<int32_t> pool;
    enc.Encode("int main() { return 0; }\n", pool);
    while (pool.size() < args.tokens)
    {
        std::vector<int32_t> more;
        enc.Encode(filler, more);
        pool.insert(pool.end(), more.begin(), more.end());
    }
    if (args.tokens > pool.size())
    {
        std::printf("TOKENS_EXCEED_POOL\n");
        return 1;
    }
    const std::vector<uint32_t> toks(pool.begin(), pool.begin() + (long)args.tokens);

    Executor ex;
    if (!ex.Bind(rep))
    {
        std::printf("BIND_FAIL: %s\n", ex.LastError().c_str());
        return 1;
    }
    bool ok = false;
    if (args.role == "serial")
    {
        ok = true;
        for (size_t i = 0; i < toks.size(); ++i)
        {
            if (!ex.ExecuteToken(toks[i], i))
            {
                std::printf("SERIAL_FAIL at %zu: %s\n", i, ex.LastError().c_str());
                ok = false;
                break;
            }
        }
    }
    else
    {
        ok = ex.PrefillBatch(toks, 0);
        if (!ok) std::printf("BATCH_FAIL: %s\n", ex.LastError().c_str());
    }
    if (!ok) return 1;

    const Dump d = Capture(ex, ex.Logits());
    if (!WriteDump(args.dump, d))
    {
        std::printf("DUMP_WRITE_FAIL: %s\n", args.dump.c_str());
        return 1;
    }
    std::printf("ROLE=%s TOKENS=%zu BLOCKS=%u ROWS=%u WK=%u WV=%u LOGITS=%u\n", args.role.c_str(),
                toks.size(), d.h.blocks, d.h.rows, d.h.width_k, d.h.width_v, d.h.logits_count);
    std::printf("ROLE_VERDICT=OK\n");
    return 0;
}

int Compare(const Args& args)
{
    const Dump a = ReadDump(args.compare[0]);
    const Dump b = ReadDump(args.compare[1]);
    if (!a.ok || !b.ok)
    {
        std::printf("DUMP_READ_FAIL: %s\n", a.ok ? args.compare[0].c_str() : args.compare[1].c_str());
        return 1;
    }
    std::printf("\n===== H11 PARITY COMPARISON =====\n");
    std::printf("serial: blocks=%u rows=%u wk=%u wv=%u logits=%u\n", a.h.blocks, a.h.rows, a.h.width_k,
                a.h.width_v, a.h.logits_count);
    std::printf("batch : blocks=%u rows=%u wk=%u wv=%u logits=%u\n", b.h.blocks, b.h.rows, b.h.width_k,
                b.h.width_v, b.h.logits_count);

    const bool shape_ok = (a.h.blocks == b.h.blocks) && (a.h.rows == b.h.rows) &&
                          (a.h.width_k == b.h.width_k) && (a.h.width_v == b.h.width_v) &&
                          (a.h.logits_count == b.h.logits_count);
    std::printf("shape_parity=%s\n", shape_ok ? "PASS" : "FAIL");
    if (!shape_ok) return 3;

    const size_t nk = a.k.size();
    const bool k_exact = nk == b.k.size() && std::memcmp(a.k.data(), b.k.data(), nk * sizeof(float)) == 0;
    const bool v_exact = a.v.size() == b.v.size() && std::memcmp(a.v.data(), b.v.data(), a.v.size() * sizeof(float)) == 0;
    const bool l_exact = a.logits.size() == b.logits.size() &&
                         std::memcmp(a.logits.data(), b.logits.data(), a.logits.size() * sizeof(float)) == 0;

    auto stats = [](const std::vector<float>& x, const std::vector<float>& y, double& max_abs, double& rmse,
                    double& cosine, size_t& first)
    {
        const size_t n = std::min(x.size(), y.size());
        double ss = 0.0, dot = 0.0, na = 0.0, nb = 0.0;
        max_abs = 0.0;
        first = (size_t)-1;
        for (size_t i = 0; i < n; ++i)
        {
            const double d = std::fabs((double)x[i] - (double)y[i]);
            if (d > max_abs) max_abs = d;
            if (d != 0.0 && first == (size_t)-1) first = i;
            ss += d * d;
            dot += (double)x[i] * (double)y[i];
            na += (double)x[i] * (double)x[i];
            nb += (double)y[i] * (double)y[i];
        }
        rmse = n ? std::sqrt(ss / (double)n) : 0.0;
        cosine = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 0.0;
    };

    double kmx = 0, krm = 0, kcos = 0, vmx = 0, vrm = 0, vcos = 0, lmx = 0, lrm = 0, lcos = 0;
    size_t kf = 0, vf = 0, lf = 0;
    stats(a.k, b.k, kmx, krm, kcos, kf);
    stats(a.v, b.v, vmx, vrm, vcos, vf);
    stats(a.logits, b.logits, lmx, lrm, lcos, lf);

    std::printf("K_PARITY=%s  (max_abs=%.6g rmse=%.6g cos=%.9f first_diff=%zu)\n",
                k_exact ? "PASS" : (kcos > 0.999999 ? "CLOSE" : "FAIL"), k_exact ? 0.0 : kmx, krm, kcos, kf);
    std::printf("V_PARITY=%s  (max_abs=%.6g rmse=%.6g cos=%.9f first_diff=%zu)\n",
                v_exact ? "PASS" : (vcos > 0.999999 ? "CLOSE" : "FAIL"), v_exact ? 0.0 : vmx, vrm, vcos, vf);
    std::printf("LOGITS_PARITY=%s  (max_abs=%.6g rmse=%.6g cos=%.9f first_diff=%zu)\n",
                l_exact ? "PASS" : (lcos > 0.999999 ? "CLOSE" : "FAIL"), l_exact ? 0.0 : lmx, lrm, lcos, lf);
    std::printf("kv_committed=%s\n", b.h.rows >= args.tokens ? "YES" : "NO");

    const bool pass = shape_ok && k_exact && v_exact && l_exact;
    std::printf("BIT_EXACT_ALL=%s\n", pass ? "YES" : "NO");
    std::printf("PARITY_VERDICT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 3;
}

}  // namespace

int main(int argc, char* argv[])
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    const Args args = Parse(argc, argv);

    if (!args.compare[0].empty()) return Compare(args);

    if (args.model.empty() || args.role.empty() || args.tokens == 0 || args.dump.empty())
    {
        std::printf("usage:\n"
                    "  deep2_prefill_parity.exe --model M --tokens K --role serial|batch --dump f.bin\n"
                    "  deep2_prefill_parity.exe --compare a.bin b.bin --tokens K\n");
        return 1;
    }

    const IngestReport& rep = Ingest(args.model, false);
    if (!rep.ok)
    {
        std::printf("INGEST_FAIL: %s\n", rep.error.c_str());
        return 1;
    }
    SpEncoder enc;
    enc.Build(GetTokenizer());
    if (!enc.ok)
    {
        std::printf("TOKENIZER_FAIL: empty vocabulary\n");
        return 1;
    }
    return RunRole(args, rep, enc);
}
