// =============================================================================
// q8_boundary_audit.cpp - per-layer decomposition of the Deep2 vs llama.cpp
// k-quant dot difference on a real GGUF model.
//
// For every layer N and position P, for the attn_output projection:
//   input_d2  = Deep2's attention output dump        (d2_posP_blkN_pc6_attn_out.bin)
//   input_ref = llama.cpp's kqv_out node dump        (ds_P0_kqv_out-N_occ0.bin)
//   W         = blk.N.attn_output.weight from the GGUF (Q4_K, [n_out, n_in])
//
// Both inputs are packed with ggml's OWN quantizer (quantize_row_q8_K_ref) and
// dotted with ggml's OWN q4_K dot (ggml_vec_dot_q4_K_q8_K) against the
// same weight rows. Per layer:
//   A. rel(d2_out, ggml(ggml(input_d2)))   -- Deep2's dot vs ggml arithmetic on the SAME input
//   B. rel(ref_out, ggml(ggml(input_ref))) -- llama.cpp's dot vs ggml arithmetic on the SAME input
//   C. rel(d2_out, ref_out)                -- the observed engine difference
//   I. rel(input_d2, input_ref)            -- the upstream input drift
//   F. count of q8 bytes differing between the two packings (boundary flips)
// If A and B are both ~1e-7, the dot arithmetic matches and C is input drift
// amplified by quantization-rounding boundaries; if A is large, Deep2's dot
// path diverges from ggml arithmetic for that layer.
// =============================================================================
#include <ggml.h>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// ggml reference kernels, reproduced from the vendored ggml source so this tool
// is self-contained (the static library does not export the *_ref symbols).
// Every arithmetic step mirrors ggml-quants.c line-for-line:
//   quantize_row_q8_K_ref  - signed extremum (first max wins ties), iscale =
//                            -127/max, qs = round-half-even via the 2^23 magic,
//                            clamp to [-128,127], bsums = intra-16 sums.
//   ggml_vec_dot_q4_K_q8_K_generic - per-256 super-block, 8-lane int32 MACs,
//                            minsum via bsums, fp16 scales applied at the end.
// ---------------------------------------------------------------------------
static inline int nearest_int(float fval) {
    float val = fval + 12582912.f;  // 1.5 * 2^23: round-half-to-even
    int i;
    std::memcpy(&i, &val, sizeof(int));
    return (i & 0x007fffff) - 0x00400000;
}

static inline float fp16_to_fp32(uint16_t h) {
    // IEEE-754 half -> single (branch-free, exact)
    const uint32_t sign = (uint32_t)(h & 0x8000) << 16;
    const uint32_t exp = (h >> 10) & 0x1F;
    const uint32_t man = h & 0x3FF;
    uint32_t bits;
    if (exp == 0) {
        if (man == 0) { bits = sign; }
        else {
            // subnormal: normalize
            int e = -1;
            uint32_t m = man;
            do { m <<= 1; ++e; } while ((m & 0x400) == 0);
            bits = sign | ((uint32_t)(127 - 15 - e) << 23) | ((m & 0x3FF) << 13);
        }
    } else if (exp == 0x1F) {
        bits = sign | 0x7F800000u | (man << 13);
    } else {
        bits = sign | ((exp - 15 + 127) << 23) | (man << 13);
    }
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

struct BlockQ8K {
    float d;          // fp16-rounded by ggml on store (1/iscale)
    int8_t qs[256];
    int16_t bsums[16];  // integers |sum| <= 2032 fit F16 exactly
};

// Round a float through IEEE-754 half, exactly as ggml's GGML_FP32_TO_FP16.
static inline float fp32_to_fp32_via_fp16(float f) {
    // use the same path ggml uses: ggml_fp32_to_fp16 then back.
    uint16_t h = ggml_fp32_to_fp16(f);
    return fp16_to_fp32(h);
}

static void quantize_row_q8_K_ref(const float* x, BlockQ8K* y, int64_t k) {
    const int64_t nb = k / 256;
    for (int64_t i = 0; i < nb; ++i) {
        float amax = 0.0f, max = 0.0f;
        for (int j = 0; j < 256; ++j) {
            const float v = x[i * 256 + j];
            if (amax < std::fabs(v)) { amax = std::fabs(v); max = v; }
        }
        if (amax == 0.0f) {
            y[i].d = 0.f;
            for (int j = 0; j < 256; ++j) y[i].qs[j] = 0;
            for (int j = 0; j < 16; ++j) y[i].bsums[j] = 0;
        } else {
            const float iscale = -127.f / max;
            for (int j = 0; j < 256; ++j) {
                int v = nearest_int(iscale * x[i * 256 + j]);
                y[i].qs[j] = (int8_t)(v < -128 ? -128 : (v > 127 ? 127 : v));
            }
            for (int j = 0; j < 16; ++j) {
                int sum = 0;
                for (int ii = 0; ii < 16; ++ii) sum += y[i].qs[16 * j + ii];
                y[i].bsums[j] = (int16_t)sum;
            }
            // ggml stores d as ggml_half: the dot reads back the F16-rounded
            // value, so the rounding must happen here, not after.
            y[i].d = fp32_to_fp32_via_fp16(1.f / iscale);
        }
    }
}

static float ggml_vec_dot_q4_K_q8_K(const uint8_t* x, const BlockQ8K* y, int n) {
    // Super-block layout: [0..1]=d, [2..3]=dmin, [4..15]=scales, [16..143]=qs.
    const int nb = n / 256;
    static const uint32_t kmask1 = 0x3f3f3f3f;
    static const uint32_t kmask2 = 0x0f0f0f0f;
    static const uint32_t kmask3 = 0x03030303;

    float sumf = 0;
    int8_t a[256];
    int16_t aux16[8];
    float sums[8];
    for (int l = 0; l < 8; ++l) sums[l] = 0.0f;
    int32_t aux32[8];
    uint32_t utmp[4];
    for (int i = 0; i < nb; ++i) {
        const uint8_t* q4 = x + i * 144 + 16;
        const BlockQ8K& yb = y[i];
        std::memset(aux32, 0, 8 * sizeof(int32_t));
        int8_t* ap = a;
        for (int j = 0; j < 4; ++j) {
            for (int l = 0; l < 32; ++l) ap[l] = (int8_t)(q4[l] & 0xF);
            ap += 32;
            for (int l = 0; l < 32; ++l) ap[l] = (int8_t)(q4[l] >> 4);
            ap += 32;
            q4 += 32;
        }
        std::memcpy(utmp, x + i * 144 + 4, 12);
        utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4);
        const uint32_t uaux = utmp[1] & kmask1;
        utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4);
        utmp[2] = uaux;
        utmp[0] &= kmask1;
        const uint8_t* scales = (const uint8_t*)&utmp[0];
        const uint8_t* mins = (const uint8_t*)&utmp[2];

        int sumi = 0;
        for (int j = 0; j < 16; ++j) sumi += yb.bsums[j] * mins[j / 2];
        ap = a;
        int is = 0;
        const int8_t* q8 = yb.qs;
        for (int j = 0; j < 8; ++j) {
            const int32_t scale = scales[is++];
            for (int rep = 0; rep < 4; ++rep) {
                for (int l = 0; l < 8; ++l) aux16[l] = (int16_t)(q8[l] * ap[l]);
                for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
                q8 += 8;
                ap += 8;
            }
        }
        const float d = fp16_to_fp32(*(const uint16_t*)(x + i * 144)) * yb.d;
        for (int l = 0; l < 8; ++l) sums[l] += d * aux32[l];
        const float dmin = fp16_to_fp32(*(const uint16_t*)(x + i * 144 + 2)) * yb.d;
        sumf -= dmin * sumi;
    }
    for (int l = 0; l < 8; ++l) sumf += sums[l];
    return sumf;
}

// ---- minimal GGUF reader ----------------------------------------------------
namespace gguf {

struct Reader {
    uint64_t alignment = 32;
    std::vector<uint8_t> bytes;
    size_t pos = 0;

    template <typename T>
    T read() {
        T v;
        std::memcpy(&v, bytes.data() + pos, sizeof(T));
        pos += sizeof(T);
        return v;
    }
    std::string readString() {
        uint64_t n = read<uint64_t>();
        std::string s(reinterpret_cast<const char*>(bytes.data()) + pos, n);
        pos += n;
        return s;
    }
    void skipValue(uint32_t type) {
        switch (type) {
            case 0: case 1: pos += 1; break;
            case 2: case 3: pos += 2; break;
            case 4: case 5: case 6: case 7: pos += 4; break;
            case 10: case 11: case 12: pos += 8; break;
            case 8: readString(); break;
            case 9: {
                uint32_t t = read<uint32_t>();
                uint64_t n = read<uint64_t>();
                for (uint64_t i = 0; i < n; ++i) skipValue(t);
                break;
            }
            default: break;
        }
    }
};

struct TensorInfo {
    std::string name;
    uint32_t ndims = 0;
    uint64_t dims[4] = {0, 0, 0, 0};
    uint32_t type = 0;
    uint64_t offset = 0;
};

inline Reader load(const std::string& path, std::vector<TensorInfo>& tensors,
                   uint64_t& dataStart) {
    Reader r;
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path.c_str()); exit(2); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    r.bytes.resize(sz);
    if (fread(r.bytes.data(), 1, sz, f) != (size_t)sz) { exit(2); }
    fclose(f);

    uint32_t magic = r.read<uint32_t>();
    if (magic != 0x46554747u) { fprintf(stderr, "not a GGUF\n"); exit(2); }
    r.read<uint32_t>();  // version
    uint64_t nTensors = r.read<uint64_t>();
    uint64_t nKv = r.read<uint64_t>();
    for (uint64_t i = 0; i < nKv; ++i) {
        r.readString();
        uint32_t type = r.read<uint32_t>();
        r.skipValue(type);
    }
    tensors.resize(nTensors);
    for (uint64_t i = 0; i < nTensors; ++i) {
        TensorInfo& t = tensors[i];
        t.name = r.readString();
        t.ndims = r.read<uint32_t>();
        for (uint32_t d = 0; d < t.ndims; ++d) t.dims[d] = r.read<uint64_t>();
        t.type = r.read<uint32_t>();
        t.offset = r.read<uint64_t>();
    }
    dataStart = (r.pos + r.alignment - 1) / r.alignment * r.alignment;
    return r;
}

}  // namespace gguf

static std::vector<float> loadDump(const std::string& path, bool header) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return {};
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> b(sz);
    if (fread(b.data(), 1, sz, f) != (size_t)sz) { fclose(f); return {}; }
    fclose(f);
    size_t off = header ? 36 : 0;
    size_t n = (b.size() - off) / 4;
    std::vector<float> v(n);
    std::memcpy(v.data(), b.data() + off, n * 4);
    return v;
}

static float rel(const std::vector<float>& a, const std::vector<float>& b) {
    size_t n = std::min(a.size(), b.size());
    double mx = 0, bmax = 0;
    for (size_t i = 0; i < n; ++i) {
        mx = std::max(mx, (double)std::fabs(a[i] - b[i]));
        bmax = std::max(bmax, (double)std::fabs(b[i]));
    }
    return bmax > 0 ? mx / bmax : mx;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: q8_boundary_audit <gguf> <run_dir> [layers]\n");
        return 2;
    }
    const std::string model = argv[1];
    const std::string run = argv[2];
    const int nLayers = argc > 3 ? atoi(argv[3]) : 28;
    const size_t nIn = 3072, nOut = 3072;

    std::vector<gguf::TensorInfo> tensors;
    uint64_t dataStart = 0;
    gguf::Reader r = gguf::load(model, tensors, dataStart);

    printf("%-6s %-6s %13s %13s %13s %13s %8s\n",
           "layer", "pos", "A:d2/float", "B:llcpp/float", "C:d2/llcpp",
           "I:in-diff", "q8flip");

    for (int pos = 0; pos < 2; ++pos) {
        for (int L = 0; L < nLayers; ++L) {
            char nbuf[128];
            snprintf(nbuf, sizeof(nbuf), "blk.%d.attn_output.weight", L);
            const gguf::TensorInfo* w = nullptr;
            for (const auto& t : tensors)
                if (t.name == nbuf) w = &t;
            if (!w) continue;
            const uint8_t* W = r.bytes.data() + dataStart + w->offset;
            const size_t rowBytes = w->dims[0] / 256 * 144;  // q4_K: 144 B / 256

            char p2[512], pr[512];
            // The dump pc counter is continuous across blocks: block L attn_out is
            // at pc 6 + 14*L and attn_proj at pc 7 + 14*L.
            const int pcOut = 6 + 14 * L;
            snprintf(p2, sizeof(p2), "%s/d2/d2_pos%d_blk%d_pc%d_attn_out.bin", run.c_str(), pos, L, pcOut);
            snprintf(pr, sizeof(pr), "%s/ref/ds_%02d_kqv_out-%d_occ0.bin", run.c_str(), pos, L);
            std::vector<float> inD2 = loadDump(p2, false);
            std::vector<float> inRef = loadDump(pr, true);
            snprintf(p2, sizeof(p2), "%s/d2/d2_pos%d_blk%d_pc%d_attn_proj.bin", run.c_str(), pos, L, pcOut + 1);
            snprintf(pr, sizeof(pr), "%s/ref/ds_%02d_attn_out-%d_occ0.bin", run.c_str(), pos, L);
            std::vector<float> outD2 = loadDump(p2, false);
            std::vector<float> outRef = loadDump(pr, true);
            if (inD2.empty() || inRef.empty() || outD2.empty() || outRef.empty()) {
                printf("%-6d %-6d %13s\n", L, pos, "MISSING");
                continue;
            }

            const size_t nb = nIn / 256;
            std::vector<BlockQ8K> qa(nb), qb(nb);
            quantize_row_q8_K_ref(inD2.data(), qa.data(), nIn);
            quantize_row_q8_K_ref(inRef.data(), qb.data(), nIn);

            size_t flips = 0;
            for (size_t b = 0; b < nb; ++b)
                for (int j = 0; j < 256; ++j)
                    if (qa[b].qs[j] != qb[b].qs[j]) ++flips;

            std::vector<float> yd(nOut), yr(nOut);
            for (size_t row = 0; row < nOut; ++row) {
                const uint8_t* wrow = W + row * rowBytes;
                yd[row] = ggml_vec_dot_q4_K_q8_K(wrow, qa.data(), (int)nIn);
                yr[row] = ggml_vec_dot_q4_K_q8_K(wrow, qb.data(), (int)nIn);
            }

            printf("%-6d %-6d %13.3e %13.3e %13.3e %13.3e %8zu\n",
                   L, pos, rel(yd, outD2), rel(yr, outRef), rel(outD2, outRef),
                   rel(inD2, inRef), flips);
        }
    }
    return 0;
}



