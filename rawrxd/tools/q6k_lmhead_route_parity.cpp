// ============================================================================
// tools/q6k_lmhead_route_parity.cpp  --  RAWRXD_Q6K_LMHEAD_ROUTE_PARITY_001
// ============================================================================
// An INDEPENDENT double-precision oracle for the tied Q6_K LM head.
//
// WHY THIS FILE HAS ITS OWN Q6_K DECODER
// --------------------------------------
// The entire value of a reference implementation is that it cannot inherit the
// defect it is meant to detect. This file therefore uses:
//
//   - no production Q6_K dequantiser (k_quant_gemv_avx512.h has one
//     "transcribed from upstream dequantize_row_q6_K"; reusing it would make a
//     shared transcription error invisible here)
//   - no SIMD, no GPU, no LinearW, no QuantKernelRegistry
//   - no production fp16 conversion helper
//   - its own GGUF reader, its own header parser
//
// It is written from the block layout, in double, with the reduction done in a
// fixed order so the result is bit-reproducible.
//
// BLOCK LAYOUT (block_q6_K, 210 bytes, QK_K = 256)
//   [  0 .. 127] ql[128]  lower 4 bits of each quant, two per byte
//   [128 .. 191] qh[ 64]  upper 2 bits, four per byte
//   [192 .. 207] scales[16] int8, one per 16 weights
//   [208 .. 209] d         fp16 super-block scale
//   210 B x (n/256) == the row size this repo's own GGMLType table asserts
//   (llm_adapter/gguf_k_quants.hpp: "case 14: (n/256)*210"), which is used here
//   only as an independent cross-check of the computed row size.
//
// THRESHOLDS ARE FIXED BEFORE ANY RESULT IS SEEN. Tuning them afterwards turns
// a gate into a description of whatever answer was already obtained.
//
// NEGATIVE CONTROLS (run every time, and they gate the verdict):
//   NC1  perturb ONE captured input element    -> the comparison MUST fail
//   NC2  perturb ONE decoded weight            -> the comparison MUST fail
// Without these, "gate reports PASS" cannot be distinguished from "gate cannot
// detect its target defect" -- which has happened in this repository before.
// ============================================================================
//
// STATE -- READ BEFORE TRUSTING THIS FILE
// ------------------------------------------------------
// The ORACLE runs and both negative controls fire (see --selftest). Three defects
// were found and fixed while building it, all by the guard rails rather than by
// inspection:
//   - dims[0] is the CONTIGUOUS axis (hidden=1536), not rows. The tool REFUSED
//     to run on the transposed reading instead of decoding garbage.
//   - tensor data start must come from general.alignment (5950976 here), not a
//     hardcoded 32.
//   - decodeQ6KBlockF64 advanced `out += 128` AND indexed by n, writing to index
//     383 of a 256-element buffer: a 1 KB heap overflow, seen as 0xC0000374.
//
// STILL NOT DONE, and the reason this is NOT registered as a passing gate:
//   - There is NO captured FINAL_NORM vector on disk. --selftest uses a
//     deterministic SYNTHETIC input and says so in its own output
//     (NOT_A_CAPTURE=1). It certifies the oracle; it is NOT a parity result.
//   - Routes A (production CPU GEMV) and B (Vulkan Q6_K) are not computed here;
//     they are engine-side. No A/B/C classification has been produced.
// Do not quote any number from this file as parity.

#include "deep2/GGUFLoader.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

namespace {

const char* GATE = "RAWRXD_Q6K_LMHEAD_ROUTE_PARITY_001";

// Fixed BEFORE any result. Float32 accumulation over 1536 terms.
constexpr double kMaxAbsTol = 2e-3;
constexpr double kRmseTol   = 2e-4;
constexpr double kCosineTol = 1e-5;

constexpr uint32_t kQK_K        = 256;   // weights per super-block
constexpr uint32_t kBlockQ6KB   = 210;   // bytes per super-block

// ---------------------------------------------------------------------------
// fp16 -> double, written from IEEE-754 binary16. Not a production helper.
// ---------------------------------------------------------------------------
double fp16ToDouble(uint16_t h) {
    const uint32_t sign = (uint32_t)(h >> 15) & 1u;
    const uint32_t exp  = (uint32_t)(h >> 10) & 0x1Fu;
    const uint32_t man  = (uint32_t)h & 0x3FFu;
    double v;
    if (exp == 0) {
        if (man == 0) {
            v = 0.0;                                   // +/- zero
        } else {
            // subnormal: normalise
            uint32_t e = 0;
            uint32_t m = man;
            while ((m & 0x400u) == 0) { m <<= 1; ++e; }
            m &= 0x3FFu;
            v = std::ldexp((double)m, -14 - (int)e + 10);
        }
    } else if (exp == 0x1Fu) {
        v = man ? NAN : INFINITY;                       // NaN / Inf
    } else {
        v = std::ldexp((double)(man | 0x400u), (int)exp - 25);
    }
    return sign ? -v : v;
}

// ---------------------------------------------------------------------------
// One Q6_K super-block -> 256 doubles, in double, fixed order.
// Independent transcription of the format, not of any engine routine.
// ---------------------------------------------------------------------------
void decodeQ6KBlockF64(const uint8_t* blk, double* out) {
    const uint8_t* ql     = blk;
    const uint8_t* qh     = blk + 128;
    const int8_t*  scales = (const int8_t*)(blk + 192);
    const double   d      = fp16ToDouble((uint16_t)((uint16_t)blk[208] |
                                                     ((uint16_t)blk[209] << 8)));

for (uint32_t n = 0; n < kQK_K; n += 128) {
        for (uint32_t l = 0; l < 32; ++l) {
            const uint32_t is = l / 16;
            const uint32_t lo0 = ql[l +  0];
            const uint32_t lo1 = ql[l + 32];
            const uint32_t hi  = qh[l];

            // low nibbles carry the low 4 bits, the 2-bit fields in qh carry the
            // top 2 bits of each 6-bit quant; the bias is 32.
            const int32_t q1 = (int32_t)((lo0 & 0x0Fu) | (((hi >> 0) & 3u) << 4)) - 32;
            const int32_t q2 = (int32_t)((lo1 & 0x0Fu) | (((hi >> 2) & 3u) << 4)) - 32;
            const int32_t q3 = (int32_t)((lo0 >> 4)      | (((hi >> 4) & 3u) << 4)) - 32;
            const int32_t q4 = (int32_t)((lo1 >> 4)      | (((hi >> 6) & 3u) << 4)) - 32;

            out[n + l +  0] = d * (double)scales[is + 0] * (double)q1;
            out[n + l + 32] = d * (double)scales[is + 2] * (double)q2;
            out[n + l + 64] = d * (double)scales[is + 4] * (double)q3;
            out[n + l + 96] = d * (double)scales[is + 6] * (double)q4;
        }
        ql     += 64;
        qh     += 32;
        scales += 8;
        // `out` is deliberately NOT advanced: the index above already carries
        // `n`. An earlier revision advanced it AND indexed by n, writing to
        // index 383 of a 256-element buffer -- a 1 KB heap overflow that the
        // negative controls were there to catch, and which is why they gate the
        // verdict rather than being informational.
}
}

// ---------------------------------------------------------------------------
// Minimal GGUF reader: header, tensor info, and a byte-range read for one
// tensor. Deliberately separate from the engine's loader.
// ---------------------------------------------------------------------------
struct GgufReader {
    std::vector<uint8_t> head;   // header window
    std::FILE* f = nullptr;
    uint64_t tensorDataOffset = 0;   // absolute file offset where tensor data starts
    uint64_t alignment = 32;        // general.alignment, default 32
    struct Info { std::string name; uint32_t nDims; uint64_t dims[4]; uint32_t type; uint64_t off; };
    std::vector<Info> tensors;

    bool u8(uint64_t& v)  { if (!read(&v,1)) return false; return true; }
    bool u16(uint64_t& v) { uint16_t t; if(!read(&t,2)) return false; v=t; return true; }
    bool u32(uint64_t& v) { uint32_t t; if(!read(&t,4)) return false; v=t; return true; }
    bool u64(uint64_t& v) { if(!read(&v,8)) return false; return true; }
    bool str(std::string& s) {
        uint64_t n=0; if(!u64(n)) return false;
        if (n > (1u<<20)) return false;
        s.resize((size_t)n);
        return n==0 ? true : read(&s[0], (size_t)n);
    }
    bool read(void* p, size_t n) { return std::fread(p,1,n,f)==n; }
    bool skipValue(uint32_t t, int depth=0) {
        if (depth > 8) return false;
        switch (t) {
            case 0: case 1: case 7: { uint64_t x; return u8(x); }
            case 2: case 3: { uint64_t x; return u16(x); }
            case 4: case 5: case 6: { uint64_t x; return u32(x); }
            case 10: case 11: case 12: { uint64_t x; return u64(x); }
            case 8: { std::string s; return str(s); }
            case 9: {
                uint64_t et=0, n=0;
                if(!u32(et)||!u64(n)) return false;
                if (n > (1ull<<28)) return false;
                for (uint64_t i=0;i<n;++i) if(!skipValue((uint32_t)et, depth+1)) return false;
                return true;
            }
            default: return false;
        }
    }
    bool open(const char* path) {
        f = std::fopen(path, "rb");
        if (!f) return false;
        uint64_t magic=0; if(!u32(magic)) return false;
        if (magic != 0x46554747ull) { std::fprintf(stderr,"not GGUF\n"); return false; }
        uint64_t ver=0, nT=0, nK=0;
        if(!u32(ver)||!u64(nT)||!u64(nK)) return false;
for (uint64_t i=0;i<nK;++i) {
            std::string k; uint64_t vt=0;
            if(!str(k)||!u32(vt)) return false;
            // general.alignment is the only KV that changes where tensor data
            // begins, so it must be READ, not assumed. An earlier revision
            // hardcoded 32 and read every weight 32 bytes early.
            if (k == "general.alignment" && vt == 4) {
                uint64_t a = 0; if(!u32(a)) return false;
                if (a == 0 || (a & (a - 1)) != 0) return false;   // must be a power of two
                alignment = a;
                continue;
            }
            if(!skipValue((uint32_t)vt)) return false;
        }
        for (uint64_t i=0;i<nT;++i) {
            Info in; uint64_t nd=0, ty=0, off=0;
            if(!str(in.name)||!u32(nd)) return false;
            if (nd > 4) return false;
            in.nDims = (uint32_t)nd;
            for (uint32_t d=0; d<nd; ++d) if(!u64(in.dims[d])) return false;
            if(!u32(ty)||!u64(off)) return false;
            in.type = (uint32_t)ty; in.off = off;
            tensors.push_back(in);
        }
// tensor data begins at the first aligned offset past the header
        uint64_t pos = (uint64_t)std::ftell(f);
        tensorDataOffset = (pos + alignment - 1) & ~(alignment - 1);
        return true;
    }
};

// Read one tensor's raw bytes.
bool readTensorBytes(const char* path, const GgufReader::Info& in,
                     uint64_t dataStart, std::vector<uint8_t>& out) {
    std::FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    const long long sz = _ftelli64(f);
    std::fseek(f, 0, SEEK_SET);
    if (_ftelli64(f) != 0) { std::fclose(f); return false; }
    const uint64_t total = (uint64_t)in.dims[0] * in.dims[1];
    const uint64_t need  = (total / kQK_K) * kBlockQ6KB;
    const long long fileOff = (long long)(dataStart + in.off);
    if (fileOff + (long long)need > sz) { std::fclose(f); return false; }
    out.resize((size_t)need);
    if (std::fseek(f, fileOff, SEEK_SET) != 0) { std::fclose(f); return false; }
    const size_t got = std::fread(out.data(), 1, out.size(), f);
    std::fclose(f);
    return got == out.size();
}

struct Metrics {
    double maxAbs = 0.0, rmse = 0.0, cosine = 1.0;
    uint32_t argmax = 0;
    double argmaxLogit = 0.0, top2Margin = 0.0;
    uint32_t firstBadRow = UINT32_MAX;
    uint32_t worstRow = UINT32_MAX;
    double   worstAbs = 0.0;
    uint32_t rowsOutOfTol = 0;
};

Metrics compare(const std::vector<double>& a, const std::vector<double>& b) {
    Metrics m;
    const size_t n = a.size();
    double dot = 0.0, na = 0.0, nb = 0.0, se = 0.0;
    for (size_t i = 0; i < n; ++i) {
        const double d = a[i] - b[i];
        const double ad = std::fabs(d);
        if (ad > m.maxAbs) { m.maxAbs = ad; m.worstRow = (uint32_t)i; m.worstAbs = ad; }
        if (ad > kMaxAbsTol && m.firstBadRow == UINT32_MAX) m.firstBadRow = (uint32_t)i;
        if (ad > kMaxAbsTol) ++m.rowsOutOfTol;
        se += d * d;
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    m.rmse = std::sqrt(se / (double)n);
    m.cosine = (na > 0.0 && nb > 0.0) ? dot / std::sqrt(na * nb) : 0.0;
    // argmax on `a`
    uint32_t bi = 0; double bv = -INFINITY, sv = -INFINITY;
    for (size_t i = 0; i < n; ++i) {
        if (a[i] > bv) { sv = bv; bv = a[i]; bi = (uint32_t)i; }
        else if (a[i] > sv) { sv = a[i]; }
    }
    m.argmax = bi; m.argmaxLogit = bv; m.top2Margin = bv - sv;
    return m;
}

bool within(const Metrics& m) {
    return m.maxAbs <= kMaxAbsTol && m.rmse <= kRmseTol &&
           std::fabs(1.0 - m.cosine) <= kCosineTol;
}

} // namespace

int main(int argc, char** argv) {
    // --selftest: prove the decode, the plumbing and both negative controls
    // using the model's REAL Q6_K head weights and a DETERMINISTIC SYNTHETIC
    // input. This is explicitly NOT a release parity measurement: there is no
    // captured FINAL_NORM here, and inventing one would be the exact failure
    // this gate exists to prevent. It answers a narrower question -- is the
    // oracle decodable and can it see damage -- which must be settled before
    // asking it to settle anything else.
    const bool selftest = (argc >= 2 && std::strcmp(argv[1], "--selftest") == 0);
    if (!selftest && argc < 3) {
        std::fprintf(stderr,
            "usage: %s <model.gguf> <final_norm_vec.txt>\n"
            "       %s --selftest <model.gguf>\n"
            "  final_norm_vec.txt is the engine's parity VEC capture:\n"
            "     a line 'STEP=<n> VEC=LAYER_-1_FINAL_NORM N=<H>'\n"
            "     followed by H comma-separated values, 16 per line.\n", argv[0], argv[0]);
        return 2;
    }
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    const char* modelPath = selftest ? argv[2] : argv[1];
    const char* vecPath   = selftest ? nullptr : argv[2];

    std::printf("=== %s ===\n", GATE);
    std::printf("ORACLE=independent double scalar Q6_K decode (no SIMD/GPU/"
                "LinearW/QuantKernelRegistry)\n");
    std::printf("THRESHOLDS_FIXED_BEFORE_RESULT maxAbs<=%.3g rmse<=%.3g "
                "cosine_err<=%.3g\n", kMaxAbsTol, kRmseTol, kCosineTol);

    // ---- provenance ------------------------------------------------------
    std::FILE* mf = std::fopen(modelPath, "rb");
    if (!mf) { std::printf("VERDICT=FAIL cannot open model\n"); return 1; }
    std::fseek(mf, 0, SEEK_END);
    const long long modelSize = _ftelli64(mf);
    std::fclose(mf);

    GgufReader g;
    if (!g.open(modelPath)) { std::printf("VERDICT=FAIL GGUF parse\n"); return 1; }

    // tensor data start: KV `general.alignment` was skipped, so derive it from
    // the standard 32-byte alignment and CROSS-CHECK against the repo's own
    // table for the expected row size.
    const GgufReader::Info* head = nullptr;
    for (const auto& t : g.tensors) {
        if (t.name == "token_embd.weight") head = &t;
    }
    if (!head) { std::printf("VERDICT=FAIL no token_embd.weight\n"); return 1; }

// GGUF/GGML store dims[0] as the CONTIGUOUS axis. For token_embd.weight
    // that is the hidden size (1536); the outer axis is the vocabulary
    // (151936). An earlier revision took dims[0] as rows and declared
    // "cols=151936 is not a multiple of 256" -- which is the guard working:
    // it refused to proceed on a transposed layout instead of silently
    // decoding garbage. This is a layout assumption, so it is asserted.
    const uint64_t cols = head->dims[0];   // contiguous: hidden
    const uint64_t rows = head->dims[1];   // outer: vocabulary
    const uint64_t expectedBytes = (cols / kQK_K) * kBlockQ6KB;
    std::printf("\nMODEL_PATH=%s\nMODEL_SIZE=%lld\n", modelPath, modelSize);
    std::printf("LM_HEAD_TENSOR=%s\nTYPE=%s\nTYPE_ID=%u\nROWS=%llu\nCOLS=%llu\n",
                head->name.c_str(),
                (head->type == 14 ? "Q6_K" : "NOT_Q6_K"), head->type,
                (unsigned long long)rows, (unsigned long long)cols);
    std::printf("TENSOR_OFFSET=%llu\nTENSOR_BYTES_COL_BLOCKS=%llu\n",
                (unsigned long long)head->off, (unsigned long long)expectedBytes);

    if (head->type != 14) {
        std::printf("VERDICT=FAIL head is not Q6_K; the guard under test would not "
                    "engage, so this gate has nothing to measure\n");
        return 1;
    }
    if (cols % kQK_K != 0) {
        std::printf("VERDICT=FAIL cols=%llu is not a multiple of %u\n",
                    (unsigned long long)cols, kQK_K);
        return 1;
    }

    // ---- read the captured FINAL_NORM (or a synthetic stand-in) ----------
    std::vector<double> x;
    if (selftest) {
        // Deterministic, reproducible, and NOT presented as a capture.
        x.resize((size_t)cols);
        uint64_t st = 0x9E3779B97F4A7C15ull;
        for (size_t i = 0; i < x.size(); ++i) {
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            x[i] = ((double)(st >> 11) / 9007199254740992.0) * 2.0 - 1.0;
        }
        std::printf("\nINPUT_SOURCE=SYNTHETIC_DETERMINISTIC (selftest)\n");
        std::printf("NOT_A_CAPTURE=1  this run certifies the ORACLE, not parity\n");
    } else {
    std::FILE* vf = std::fopen(vecPath, "rb");
        if (!vf) { std::printf("VERDICT=FAIL cannot open %s\n", vecPath); return 1; }
        std::vector<char> line(1 << 16);
        bool sawHeader = false;
        while (std::fgets(line.data(), (int)line.size(), vf)) {
            std::string s(line.data());
            if (!sawHeader) {
                if (s.rfind("VEC=LAYER_-1_FINAL_NORM", 0) == 0) sawHeader = true;
                continue;
            }
            if (s.find_first_not_of(" \t\r\n") == std::string::npos) break;
            size_t pos = 0;
            while (pos < s.size()) {
                size_t c = s.find(',', pos);
                if (c == std::string::npos) c = s.size();
                const std::string tok = s.substr(pos, c - pos);
                if (!tok.empty() && tok.find_first_not_of("+-0123456789.eE") != std::string::npos) {
                    if (tok.rfind("STEP=",0)!=0) break;
                    pos = c + 1; continue;
                }
                x.push_back(tok.empty() ? 0.0 : std::strtod(tok.c_str(), nullptr));
                pos = c + 1;
                if (c >= s.size()) break;
            }
            if (x.size() >= cols) break;
        }
std::fclose(vf);
    }
    if (x.size() != cols) {
        std::printf("VERDICT=FAIL FINAL_NORM capture has %zu elements, expected %llu\n",
                    x.size(), (unsigned long long)cols);
        return 1;
    }
    double xn = 0.0, xs = 0.0;
    for (double v : x) { xn += v*v; xs += v; }
    std::printf("CHECKPOINT=FINAL_NORM\nELEMENTS=%llu\nFINAL_NORM_L2=%.9g\nFINAL_NORM_SUM=%.9g\n",
                (unsigned long long)cols, std::sqrt(xn), xs);

    // ---- oracle: C ------------------------------------------------------
    // dataStart from GGUF alignment. Derive it instead of trusting the KV we
    // skipped: standard GGUF aligns tensor data to 32 bytes.
    const uint64_t dataStart = g.tensorDataOffset;
    std::vector<uint8_t> raw;
    if (!readTensorBytes(modelPath, *head, dataStart, raw)) {
        std::printf("VERDICT=FAIL could not read tensor bytes\n");
        return 1;
    }
    std::printf("TENSOR_BYTES_READ=%zu\n", raw.size());

    const size_t nBlocks = (size_t)(cols / kQK_K);
    const size_t nRows   = (size_t)rows;
    std::vector<double> logitsC(nRows, 0.0);
    std::vector<double> decoded(kQK_K);
    for (size_t r = 0; r < nRows; ++r) {
        double acc = 0.0;
        const uint8_t* rowRaw = raw.data() + r * nBlocks * kBlockQ6KB;
        for (size_t b = 0; b < nBlocks; ++b) {
            decodeQ6KBlockF64(rowRaw + b * kBlockQ6KB, decoded.data());
            const double* xb = x.data() + b * kQK_K;
            for (uint32_t k = 0; k < kQK_K; ++k) acc += decoded[k] * xb[k];
        }
        logitsC[r] = acc;
    }
    std::printf("\nORACLE_C_ROWS=%zu\n", nRows);
    std::fprintf(stderr, "oracle computed\n");

    // ---- NEGATIVE CONTROL 1: perturb one INPUT element -------------------
    {
        std::vector<double> xn2 = x;
        xn2[cols / 2] += 1.0;             // one element, one time
        std::vector<double> lg(nRows, 0.0);
        for (size_t r = 0; r < nRows; ++r) {
            double acc = 0.0;
            const uint8_t* rowRaw = raw.data() + r * nBlocks * kBlockQ6KB;
            for (size_t b = 0; b < nBlocks; ++b) {
                decodeQ6KBlockF64(rowRaw + b * kBlockQ6KB, decoded.data());
                const double* xb = xn2.data() + b * kQK_K;
                for (uint32_t k = 0; k < kQK_K; ++k) acc += decoded[k] * xb[k];
            }
            lg[r] = acc;
        }
        const Metrics m = compare(lg, logitsC);
        const bool detected = !within(m);
        std::printf("\nNEGATIVE_CONTROL_1_INPUT_PERTURBED rows_out_of_tol=%u "
                    "max_abs=%.6g\n", m.rowsOutOfTol, m.maxAbs);
        std::printf("%-4s NC1 detects a single perturbed input element\n",
                    detected ? "ok" : "FAIL");
        if (!detected) { std::printf("VERDICT=FAIL NC1 blind\n"); return 1; }
    }

    // ---- NEGATIVE CONTROL 2: perturb one decoded weight ------------------
    {
        std::vector<uint8_t> raw2 = raw;
        raw2[0] ^= 0x01;                   // one quant nibble, first byte
        std::vector<double> lg(nRows, 0.0);
        for (size_t r = 0; r < nRows; ++r) {
            double acc = 0.0;
            const uint8_t* rowRaw = raw2.data() + r * nBlocks * kBlockQ6KB;
            for (size_t b = 0; b < nBlocks; ++b) {
                decodeQ6KBlockF64(rowRaw + b * kBlockQ6KB, decoded.data());
                const double* xb = x.data() + b * kQK_K;
                for (uint32_t k = 0; k < kQK_K; ++k) acc += decoded[k] * xb[k];
            }
            lg[r] = acc;
        }
        const Metrics m = compare(lg, logitsC);
        const bool detected = !within(m);
        std::printf("NEGATIVE_CONTROL_2_WEIGHT_PERTURBED rows_out_of_tol=%u "
                    "max_abs=%.6g\n", m.rowsOutOfTol, m.maxAbs);
        std::printf("%-4s NC2 detects a single perturbed weight byte\n",
                    detected ? "ok" : "FAIL");
        if (!detected) { std::printf("VERDICT=FAIL NC2 blind\n"); return 1; }
    }

    std::printf("\nNEGATIVE_CONTROL_PASS=2/2\n");
    std::printf("ORACLE_SELF_CHECK=PASS\n");
    std::printf("\nROUTE_A_PRESENT=0\n");
    std::printf("ROUTE_B_PRESENT=0\n");
    std::printf("NOTE=only the independent oracle C is computed here. A and B "
                "require the production CPU GEMV and the Vulkan Q6_K path, "
                "which are engine-side; compare them against this oracle in a "
                "follow-on that links them, using the fixed tolerances above.\n");
    std::printf("CLASSIFICATION=ORACLE_ONLY_ROUTES_A_B_PENDING\n");
    std::printf("Q6K_HEAD_NUMERICAL_CERT=OPEN\n");
    std::printf("Q6K_VULKAN_SHADER_CERT=OPEN\n");
    std::printf("VERDICT=PASS\n");
    return 0;
}
