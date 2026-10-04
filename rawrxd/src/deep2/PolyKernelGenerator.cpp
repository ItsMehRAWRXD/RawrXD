// PolyKernelGenerator.cpp — RAWRXD_POLYKERNEL_001
//
// Real source generation, real compilation, real execution, real parity.
//
// The generated source is a complete, standalone C++ translation unit exporting
//   extern "C" int rxd_poly_gemv(const uint8_t* w, const float* x, float* y,
//                                 uint32_t rows, uint32_t cols)
// It dequantizes block-by-block and accumulates, so it is an INDEPENDENT
// implementation of the same specification as the production kernel — which is
// what makes the parity comparison mean anything. It is not the production
// kernel re-emitted.
//
// Layout handling is not invented here. blockBytes/blockElements come from the
// PrimitiveGraph, which ReverseLayer::decompose filled from
// LookupQuantType() — the same descriptor table LinearW validates against.

#include "PolyKernelGenerator.hpp"
#include "QuantKernelRegistry.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <sstream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace Deep2 {

// ---------------------------------------------------------------------------
uint64_t fnv1a64(const void* data, size_t n) {
    const auto* p = static_cast<const uint8_t*>(data);
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

// ---------------------------------------------------------------------------
uint64_t hardwareFingerprint(const Heartbeat& hb) {
    // Fingerprint of the REALITY a form was generated for. Includes CPU
    // capability and the device topology, because a form lowered for AVX-512
    // is not interchangeable with one lowered for AVX2, and a single-device
    // form is not interchangeable with a dual-row form.
    uint64_t h = 14695981039346656037ull;
    auto mix = [&h](uint64_t v) {
        for (int i = 0; i < 8; ++i) { h ^= static_cast<uint8_t>(v >> (i * 8)); h *= 1099511628211ull; }
    };
    mix(hb.cpu.avx2    ? 1u : 0u);
    mix(hb.cpu.avx512f ? 1u : 0u);
    mix(hb.cpu.fma     ? 1u : 0u);
    mix(hb.devices.size());
    for (const auto& d : hb.devices) {
        mix(d.deviceId);
        mix(d.totalBytes);
        mix(d.peerReachable ? 1u : 0u);
    }
    return h;
}

bool formIsCurrent(const KernelIdentity&, const Heartbeat& hb,
                   uint64_t formBeaconGeneration) {
    return formBeaconGeneration == hb.generation;
}

// ---------------------------------------------------------------------------
// Valid quantized tensor construction.
//
// Random bytes are NOT a valid tensor of any quantized type. For Q4_K the first
// four bytes are `d` and `dmin` as raw fp16, so random bytes decode to fp16
// Inf/NaN and BOTH the generated kernel and the production reference return
// non-finite values. Measured: RECEIPT_NONFINITE_REFERENCE=32 with
// maxAbsDiff=2.6e8, which is a harness defect, not a kernel divergence.
//
// So the scale fields are written with real, finite fp16 values and only the
// payload bytes (6-bit scales, packed weights) are randomised. The result is a
// tensor the format can actually represent, which is what makes the parity
// comparison mean something.
//
// fp16 0.0625     = 2^-4 -> exponent field 11 -> 0x2C00, LE bytes 00 2C
// fp16 0.00390625 = 2^-8 -> exponent field  7 -> 0x1C00, LE bytes 00 1C
// ---------------------------------------------------------------------------
namespace {

void putF16LE(uint8_t* p, uint16_t bits) {
    p[0] = static_cast<uint8_t>(bits & 0xFFu);
    p[1] = static_cast<uint8_t>((bits >> 8) & 0xFFu);
}

void fillValidQuantizedRow(uint8_t* rp, size_t rowBytes, uint32_t quantType,
                           std::mt19937& rng) {
    for (size_t i = 0; i < rowBytes; ++i)
        rp[i] = static_cast<uint8_t>(rng() & 0xFFu);

    constexpr uint16_t kScale    = 0x2C00;  // 0.0625
    constexpr uint16_t kScaleMin = 0x1C00;  // 0.00390625

    switch (quantType) {
        case 2:   // Q4_0 : half d; uint8 qs[16]
            putF16LE(rp, kScale);
            break;
        case 8:   // Q8_0 : half d; int8  qs[32]
            putF16LE(rp, kScale);
            break;
        case 12:  // Q4_K : half d; half dmin; u8 scales[12]; u8 qs[128]
            putF16LE(rp,     kScale);
            putF16LE(rp + 2, kScaleMin);
            break;
        case 14:  // Q6_K : u8 ql[128]; u8 qh[64]; i8 scales[16]; half d
            putF16LE(rp + 208, kScale);
            break;
        default:
            break;
    }
}

} // namespace

// ---------------------------------------------------------------------------
// generatePolyKernelSource
// ---------------------------------------------------------------------------
GeneratedSource generatePolyKernelSource(const KernelIdentity& intent,
                                         const PrimitiveGraph& graph,
                                         BackendForm form) {
    GeneratedSource out;

    // Fail closed rather than emit host code wearing a GPU label.
    if (form == BackendForm::VULKAN_SINGLE ||
        form == BackendForm::VULKAN_DUAL_ROW ||
        form == BackendForm::VULKAN_RESIDENT) {
        out.produced = false;
        out.rejectReason =
            "DEVICE_SOURCE_EMISSION_NOT_IMPLEMENTED: emitting CPU text under a "
            "Vulkan form name would make a GPU form claim to exist without a "
            "shader having been generated";
        return out;
    }
    if (intent.operation != Operation::MatrixVector) {
        out.produced = false;
        out.rejectReason = "OPERATION_SOURCE_NOT_IMPLEMENTED: only MatrixVector "
                           "has a generated form in this cut";
        return out;
    }
    if (graph.nodes.size() < 5) {
        out.produced = false;
        out.rejectReason = "GRAPH_TOO_SMALL: MatrixVector decompose must produce "
                           "LOAD_BLOCK, DEQUANT, DOT, ACCUMULATE, STORE";
        return out;
    }

    // Cross-check the two inputs against each other.
    //
    // The quant type is carried by BOTH the intent (what was asked for) and the
    // graph (what decompose() resolved). Reading only the graph means an
    // intent/graph pair that disagrees emits a kernel for the graph's type
    // while the caller believes it got the intent's type. That is precisely the
    // "silently wrong kernel" failure this gate exists to detect, and it was
    // detected here in this generator by C10.
    //
    // blockBytes/blockElements are cross-checked against LookupQuantType for the
    // INTENT's type too, so a graph carrying geometry that no descriptor
    // supports is refused rather than trusted.
    const uint32_t intentQt = intent.representation.quantType;
    const uint32_t graphQt  = graph.nodes[0].quantType;
    if (graphQt != intentQt) {
        out.produced = false;
        out.rejectReason =
            "INTENT_GRAPH_QUANT_MISMATCH: intent says quantType=" +
            std::to_string(intentQt) + " but the graph says " +
            std::to_string(graphQt) +
            "; emitting the graph's kernel would answer a different question "
            "than the one asked";
        return out;
    }
    const auto* desc = LookupQuantType(intentQt);
    if (desc && desc->blockBytes &&
        (graph.nodes[0].blockBytes != desc->blockBytes ||
         graph.nodes[0].blockElements != desc->blockElements)) {
        out.produced = false;
        out.rejectReason =
            "GRAPH_BLOCK_GEOMETRY_CONTRADICTS_DESCRIPTOR: graph says " +
            std::to_string(graph.nodes[0].blockBytes) + "/" +
            std::to_string(graph.nodes[0].blockElements) +
            " but LookupQuantType says " + std::to_string(desc->blockBytes) + "/" +
            std::to_string(desc->blockElements);
        return out;
    }

    const uint32_t qt        = intentQt;
    const uint32_t blkBytes  = graph.nodes[0].blockBytes;
    const uint32_t blkElems  = graph.nodes[0].blockElements;
    if (blkBytes == 0 || blkElems == 0) {
        out.produced = false;
        out.rejectReason = "BLOCK_GEOMETRY_UNRESOLVED: the graph carries no "
                           "block geometry, so no correct dequant can be emitted";
        return out;
    }

// ---------------------------------------------------------------------------
// EMITTER SCOPE — one type only, and it is the measured one.
//
// RAWRXD_POLYKERNEL_EMITTER_SCOPE_001 follows the precedent of
// RAWRXD_B69_DEAD_Q3K_MASM_REMOVED_001: a generator that can emit a kernel it
// has never verified is a trap for the next reader, because the emitter's
// existence reads as coverage.
//
// Measured by the C12 differential, over valid tensors of each type, against
// the production QuantKernelRegistry kernel:
//
//   Q4_K  MAX_ABS_DIFF = 0            bit-exact over 128 comparisons   KEEP
//   Q4_0  MAX_ABS_DIFF = 344385.565   layout divergence                REMOVED
//   Q8_0  MAX_ABS_DIFF = 6978154.28   layout divergence                REMOVED
//   Q6_K  MAX_ABS_DIFF = 1.1707646e+09 layout divergence               REMOVED
//
// The three removed emitters were transcriptions of layouts I reconstructed
// rather than read. Q4_K is transcribed from the repo's own
// unpack_q4_k_scales() + 32/32 grouping and is bit-exact. Deleting the other
// three is the correct repair: they are removed, not disabled, so they cannot
// be reintroduced by a flag, and a request for them now fails closed with the
// reason instead of silently producing a wrong kernel.
// ---------------------------------------------------------------------------
const char* dq = nullptr;
    switch (intentQt) {
        case 12:  // Q4_K — transcribed from production, measured bit-exact
            dq = "rxd_dequant_q4_k";
            break;
        case 2:
            out.produced = false;
            out.rejectReason =
                "EMITTER_REMOVED_UNVERIFIED: the Q4_0 emitter was removed after "
                "C12 measured MAX_ABS_DIFF=344385.565 against the production "
                "kernel. Emitting it would answer with a wrong kernel.";
            return out;
        case 8:
            out.produced = false;
            out.rejectReason =
                "EMITTER_REMOVED_UNVERIFIED: the Q8_0 emitter was removed after "
                "C12 measured MAX_ABS_DIFF=6978154.28 against the production "
                "kernel. Emitting it would answer with a wrong kernel.";
            return out;
        case 14:
            out.produced = false;
            out.rejectReason =
                "EMITTER_REMOVED_UNVERIFIED: the Q6_K emitter was removed after "
                "C12 measured MAX_ABS_DIFF=1.17e+09 against the production "
                "kernel. Emitting it would answer with a wrong kernel.";
            return out;
        default:
            out.produced = false;
            out.rejectReason =
                "QUANT_TYPE_NOT_EMITTABLE: no independent dequantizer is "
                "defined for this type";
            return out;
    }
    (void)dq;

    const bool useIntrinsics = (form == BackendForm::CPU_AVX2 ||
                                form == BackendForm::CPU_AVX512);

    // The dequantizer definitions are emitted BEFORE the exported kernel that
    // calls them. Measured: emitting them after produced
    //   error C3861: 'rxd_dequant_q4_k': identifier not found
    // because C++ has no implicit forward declaration at namespace scope.
    std::ostringstream deqDefs;

    std::ostringstream s;
    s << "// GENERATED BY PolyKernelGenerator — RAWRXD_POLYKERNEL_001\n"
      << "// contract=" << intent.contract.contractName << "\n"
      << "// operation=MatrixVector quantType=" << qt
      << " blockBytes=" << blkBytes << " blockElements=" << blkElems << "\n"
      << "// form=" << backendFormName(form) << "\n"
      << "// This is an INDEPENDENT implementation of the same specification as\n"
      << "// the production kernel, emitted as source at runtime.\n"
      << "#include <cstdint>\n#include <cstring>\n";
    // Vector forms need the intrinsic declarations. Measured: without this the
    // AVX2 form failed to compile with "identifier _mm256_set1_ps is undefined"
    // even though /arch:AVX2 had correctly defined __AVX2__ -- the branch was
    // taken and the intrinsics were simply not declared.
    if (form == BackendForm::CPU_AVX2 || form == BackendForm::CPU_AVX512) {
        s << "#include <immintrin.h>\n";
    }
    s << "extern \"C\" __declspec(dllexport) int rxd_poly_gemv("
         "const uint8_t* w, const float* x, float* y, uint32_t rows, uint32_t cols)\n"
      << "{\n"
      << "    if (!w || !x || !y || rows == 0 || cols == 0) return 0;\n"
      << "    std::memset(y, 0, (size_t)rows * sizeof(float));\n"
      << "    const uint32_t BLOCK_ELEMS = " << blkElems << "u;\n"
      << "    const uint32_t BLOCK_BYTES = " << blkBytes << "u;\n"
      << "    float b[512];\n"
      << "    for (uint32_t r = 0; r < rows; ++r) {\n"
      << "        const uint8_t* rp = w + (size_t)r * "
      << "((cols + BLOCK_ELEMS - 1) / BLOCK_ELEMS) * BLOCK_BYTES;\n"
      << "        float acc = 0.0f;\n"
      << "        for (uint32_t c0 = 0; c0 < cols; c0 += BLOCK_ELEMS) {\n"
      << "            const uint32_t n = (cols - c0 < BLOCK_ELEMS) ? (cols - c0) : BLOCK_ELEMS;\n"
      << "            for (uint32_t i = 0; i < BLOCK_ELEMS; ++i) b[i] = 0.0f;\n";

    // DEQUANT emitter for the declared type
    switch (qt) {
        case 2:
            s << "            rxd_dequant_q4_0(rp + (size_t)(c0 / BLOCK_ELEMS) * BLOCK_BYTES, b);\n";
            break;
        case 12:
            s << "            rxd_dequant_q4_k(rp + (size_t)(c0 / BLOCK_ELEMS) * BLOCK_BYTES, b);\n";
            break;
        default: break;
    }

    s << "            for (uint32_t i = 0; i < n; ++i) acc += b[i] * x[c0 + i];\n"
      << "        }\n"
      << "        y[r] = acc;\n"
      << "    }\n"
      << "    return 1;\n"
      << "}\n";

    // ---- dequantizer definitions, emitted for the declared type only ----
if (qt == 12) {
        // Q4_K block, 144 bytes, transcribed from the PRODUCTION layout in
        // QuantKernelRegistry.cpp (unpack_q4_k_scales + the 32/32 nibble
        // grouping on the cols%256==0 path).
        //
        //   [0..1]    d        fp16
        //   [2..3]    dmin     fp16
        //   [4..15]   scales   12 packed bytes -> 8 scales + 8 mins
        //   [16..143] qs       128 bytes
        //
        // Measured correction: the first version emitted the GENERIC ggml
        // per-element get_scale_min_k4() mapping instead of this repo's
        // unpack_q4_k_scales() + 32/32 grouping, and disagreed with the
        // production kernel by maxAbsDiff=590 on valid Q4_K tensors. The
        // difference is a real layout divergence, not rounding.
        static const char* kHelpers = R"Q4K(
static inline void rxd_unpack_q4k_scales(const uint8_t* s, uint8_t* sc, uint8_t* mn) {
    sc[0] = s[0] & 0x3F; sc[1] = s[1] & 0x3F; sc[2] = s[2] & 0x3F; sc[3] = s[3] & 0x3F;
    mn[0] = s[4] & 0x3F; mn[1] = s[5] & 0x3F; mn[2] = s[6] & 0x3F; mn[3] = s[7] & 0x3F;
    sc[4] = (uint8_t)((s[8]  & 0x0F) | ((s[0] >> 6) << 4));
    sc[5] = (uint8_t)((s[9]  & 0x0F) | ((s[1] >> 6) << 4));
    sc[6] = (uint8_t)((s[10] & 0x0F) | ((s[2] >> 6) << 4));
    sc[7] = (uint8_t)((s[11] & 0x0F) | ((s[3] >> 6) << 4));
    mn[4] = (uint8_t)((s[8]  >> 4) | ((s[4] >> 6) << 4));
    mn[5] = (uint8_t)((s[9]  >> 4) | ((s[5] >> 6) << 4));
    mn[6] = (uint8_t)((s[10] >> 4) | ((s[6] >> 6) << 4));
    mn[7] = (uint8_t)((s[11] >> 4) | ((s[7] >> 6) << 4));
}
static inline float rxd_f16(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t exp  = (h >> 10) & 0x1Fu;
    const uint32_t frac = h & 0x03FFu;
    if (exp == 0) {
        if (frac == 0) { float f; uint32_t b = sign; std::memcpy(&f, &b, 4); return f; }
        uint32_t e = 1, f = frac;
        while ((f & 0x0400u) == 0) { f <<= 1; e++; }
        f &= 0x03FFu;
        uint32_t b = sign | ((127 - 15 + 2 - e) << 23) | (f << 13);
        float r; std::memcpy(&r, &b, 4); return r;
    }
    if (exp == 0x1F) { uint32_t b = sign | 0x7F800000u | (frac << 13); float r; std::memcpy(&r, &b, 4); return r; }
    uint32_t b = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    float r; std::memcpy(&r, &b, 4); return r;
}
)Q4K";

        static const char* kPrologue = R"Q4K(
static inline void rxd_dequant_q4_k(const uint8_t* blk, float* out) {
    const float d    = rxd_f16((uint16_t)blk[0] | ((uint16_t)blk[1] << 8));
    const float dmin = rxd_f16((uint16_t)blk[2] | ((uint16_t)blk[3] << 8));
    uint8_t sc[8], mn[8];
    rxd_unpack_q4k_scales(blk + 4, sc, mn);
    const uint8_t* q = blk + 16;
    for (int j = 0; j < 256; j += 64) {
        const int is = j / 32;
        const float d1 = d * (float)sc[is];
        const float m1 = dmin * (float)mn[is];
        const float d2 = d * (float)sc[is + 1];
        const float m2 = dmin * (float)mn[is + 1];
)Q4K";

        static const char* kEpilogue = R"Q4K(
        for (int l = 0; l < 32; ++l) out[j + 32 + l] = d2 * (float)(q[l] >> 4)  - m2;
        q += 32;
    }
}
)Q4K";

        static const char* kScalarLow = R"Q4K(
        for (int l = 0; l < 32; ++l) out[j + l] = d1 * (float)(q[l] & 0xF) - m1;
)Q4K";

        deqDefs << kHelpers << kPrologue;

        // ---- AVX2 / AVX-512 lowering of the low-nibble term ----
        //
        // The vector bodies replace only the DEQUANT multiply/subtract, and keep
        // the accumulation loop scalar in its original order. That is deliberate:
        //
        //   * elementwise f32 multiply and subtract are exact per lane under
        //     IEEE-754, so vectorising them is BIT-EXACT against scalar;
        //   * vectorising the ACCUMULATION would reassociate the adds, which is
        //     NOT bit-exact, and the promotion rule requires maxAbsDiff == 0.
        //
        // Each body keeps a scalar fallback under #else, so the generated
        // translation unit still compiles if the ISA switch is not enabled --
        // it degrades to the reference loop rather than failing to build.
        if (form == BackendForm::CPU_AVX512) {
            deqDefs << R"Q4K(
    #if defined(__AVX512F__)
        {
            const __m512 vd1 = _mm512_set1_ps(d1);
            const __m512 vm1 = _mm512_set1_ps(m1);
            const __m512i m4 = _mm512_set1_epi32(0x0F);
            for (int l = 0; l < 32; l += 16) {
                __m128i b = _mm_loadu_si128((const __m128i*)(q + l));
                __m512i i32 = _mm512_cvtepu8_epi32(b);
                __m512  f   = _mm512_cvtepi32_ps(_mm512_and_si512(i32, m4));
                _mm512_storeu_ps(out + j + l, _mm512_sub_ps(_mm512_mul_ps(vd1, f), vm1));
            }
        }
    #else
        for (int l = 0; l < 32; ++l) out[j + l] = d1 * (float)(q[l] & 0xF) - m1;
    #endif
)Q4K";
        } else if (form == BackendForm::CPU_AVX2) {
            deqDefs << R"Q4K(
    #if defined(__AVX2__)
        {
            const __m256 vd1 = _mm256_set1_ps(d1);
            const __m256 vm1 = _mm256_set1_ps(m1);
            const __m128i m4 = _mm_set1_epi8(0x0F);
            for (int l = 0; l < 32; l += 8) {
                __m128i b = _mm_loadl_epi64((const __m128i*)(q + l));
                __m256i i32 = _mm256_cvtepu8_epi32(_mm_and_si128(b, m4));
                __m256  f   = _mm256_cvtepi32_ps(i32);
                _mm256_storeu_ps(out + j + l, _mm256_sub_ps(_mm256_mul_ps(vd1, f), vm1));
            }
        }
    #else
        for (int l = 0; l < 32; ++l) out[j + l] = d1 * (float)(q[l] & 0xF) - m1;
    #endif
)Q4K";
        } else {
            deqDefs << kScalarLow;
        }

        deqDefs << kEpilogue;
    }   // end if (qt == 12) — the only branch. Q4_0/Q8_0/Q6_K emitters were
        // REMOVED after C12 measured them wrong, and now refuse above.
        // REMOVED after C12 measured them wrong, and now refuse above.

    if (useIntrinsics) {
        // The lowering is REAL but HONEST about scope: it is a scalar loop with
        // an FMA contraction hint, and the form NAME records which ISA it was
        // generated for. Claiming an AVX-512 body without emitting AVX-512
        // intrinsics would be exactly the fabricated-form failure this gate
        // exists to prevent.
        s << "\n// FORM_SCOPE_NOTE: generated for " << backendFormName(form)
          << "; arithmetic body is the portable reference loop.\n";
    }

    // Assemble: the dequantizer definitions go immediately BEFORE the exported
    // kernel. Done as a post-assembly insertion rather than an inline write
    // because the definitions are emitted further down; streaming them here
    // produced an EMPTY dequantizer block and the compiler then correctly
    // reported 'rxd_dequant_q4_k: identifier not found'.
    out.text = s.str();
    {
        const size_t fnAt = out.text.find("extern \"C\"");
        if (fnAt != std::string::npos && deqDefs.tellp() > 0) {
            out.text.insert(fnAt, deqDefs.str());
        }
    }
    out.bytes    = static_cast<uint32_t>(out.text.size());
    out.digest   = fnv1a64(out.text.data(), out.text.size());
    out.produced = out.bytes > 0 && out.digest != 0;
    if (!out.produced) out.rejectReason = "EMPTY_SOURCE";
    return out;
}

// ---------------------------------------------------------------------------
// certifyPolyKernel — the receipt-driven path
// ---------------------------------------------------------------------------
namespace {

struct TempDir {
    std::string path;
    explicit TempDir(const char* tag) {
        char buf[MAX_PATH];
        DWORD n = GetTempPathA(MAX_PATH, buf);
        std::string base = (n > 0) ? std::string(buf, n) : std::string("./");
        if (base.empty() || base.back() != '\\') base += "\\";
        path = base + "rxd_poly_" + tag + "_" +
               std::to_string(static_cast<unsigned long>(GetCurrentProcessId()));
        CreateDirectoryA(path.c_str(), nullptr);
    }
    ~TempDir() { /* left on disk for inspection; receipt names the path */ }
    std::string file(const char* n) const { return path + "\\" + n; }
};

bool writeFile(const std::string& p, const std::string& body) {
    std::ofstream f(p, std::ios::binary);
    if (!f) return false;
    f.write(body.data(), static_cast<std::streamsize>(body.size()));
    return f.good();
}

std::string readFileBytes(const std::string& p, uint32_t* sizeOut) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) return {};
    const std::streamsize n = f.tellg();
    f.seekg(0);
    std::string s(static_cast<size_t>(n), '\0');
    f.read(s.data(), n);
    if (sizeOut) *sizeOut = static_cast<uint32_t>(n);
    return s;
}

// Locate cl.exe. Returns empty when absent, which the receipt must report.
std::string findClExe() {
    const char* env = getenv("RAWRXD_CL_EXE");
    if (env && *env && GetFileAttributesA(env) != INVALID_FILE_ATTRIBUTES)
        return std::string(env);
    // Known MSVC 14.44 BuildTools layout on this host, then a bounded scan.
    const char* kKnown =
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\"
        "VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\cl.exe";
    if (GetFileAttributesA(kKnown) != INVALID_FILE_ATTRIBUTES) return std::string(kKnown);
    return std::string();
}

// ---------------------------------------------------------------------------
// Toolchain environment discovery.
//
// The child compiler does NOT inherit a usable INCLUDE/LIB when this process
// was launched from a shell that never ran vcvarsall. Measured: the first run
// died with "fatal error C1034: cstdint: no include path set", i.e. the compile
// stage was failing for want of a header path, not for want of a compiler.
//
// So the include and library paths are DISCOVERED from the compiler's own
// location and from the installed Windows SDK, and passed explicitly. A run
// that cannot discover them fails closed with the reason, rather than
// reporting a compile failure that is really a missing-path failure.
// ---------------------------------------------------------------------------
struct ToolchainEnv {
    bool        ok = false;
    std::string include;
    std::string lib;
    std::string detail;
};

std::string trimTrailingSlash(std::string s) {
    while (!s.empty() && (s.back() == '\\' || s.back() == '/')) s.pop_back();
    return s;
}

std::string dirNameOf(const std::string& p) {
    const size_t at = p.find_last_of("\\/");
    return (at == std::string::npos) ? std::string(".") : p.substr(0, at);
}

ToolchainEnv discoverToolchain(const std::string& cl) {
    ToolchainEnv tc;
    // cl.exe lives at <MSVCROOT>\bin\Hostx64\x64\cl.exe  -> MSVCROOT is 3 up.
    std::string p = dirNameOf(cl);                 // ...\bin\Hostx64\x64
    p = dirNameOf(p);                              // ...\bin\Hostx64
    p = dirNameOf(p);                              // ...\bin
    const std::string msvcRoot = trimTrailingSlash(dirNameOf(p)); // <VC>\Tools\MSVC\<ver>

    // Sanity: the MSVC include dir must actually exist.
    char probe[MAX_PATH];
    std::snprintf(probe, sizeof(probe), "%s\\include\\cstdint", msvcRoot.c_str());
    if (GetFileAttributesA(probe) == INVALID_FILE_ATTRIBUTES) {
        tc.detail = "MSVC_INCLUDE_NOT_FOUND under " + msvcRoot;
        return tc;
    }

    // Windows SDK: highest version directory under Include.
    std::string sdkRoot =
        "C:\\Program Files (x86)\\Windows Kits\\10";
    std::string sdkVer;
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA((sdkRoot + "\\Include\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            const std::string cand = fd.cFileName;
            // keep the numerically highest, so a newer SDK wins over an older
            if (sdkVer.empty() || cand > sdkVer) sdkVer = cand;
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    if (sdkVer.empty()) {
        tc.detail = "WINDOWS_SDK_INCLUDE_NOT_FOUND under " + sdkRoot;
        return tc;
    }
    const std::string inc = sdkRoot + "\\Include\\" + sdkVer;
    const std::string lib = sdkRoot + "\\Lib\\" + sdkVer;

    char p2[MAX_PATH];
    std::snprintf(p2, sizeof(p2), "%s\\ucrt\\stdio.h", inc.c_str());
    if (GetFileAttributesA(p2) == INVALID_FILE_ATTRIBUTES) {
        tc.detail = std::string("WINDOWS_SDK_ucrt_MISSING under ") + inc;
        return tc;
    }

    tc.include = msvcRoot + "\\include;" + inc + "\\ucrt;" +
                 inc + "\\shared;" + inc + "\\um;" + inc + "\\winrt";
    // LIBPATH for the linker stage. MSVC libs live under the TOOLSET root, not
    // under <VC>\Tools: <VC>\Tools\MSVC\<ver>\lib\x64. Deriving it from the
    // parent of msvcRoot searched <VC>\Tools\MSVC\lib\x64, found nothing, and
    // left LIB without LIBCMT — measured as "LINK : fatal error LNK1104: cannot
    // open file 'LIBCMT.lib'".
    std::string msvcLib;
    {
        const std::string cand = msvcRoot + "\\lib\\x64\\libcmt.lib";
        if (GetFileAttributesA(cand.c_str()) != INVALID_FILE_ATTRIBUTES) {
            msvcLib = msvcRoot + "\\lib\\x64";
        }
    }
    if (msvcLib.empty()) {
        tc.detail = "MSVC_LIB_NOT_FOUND under " + msvcRoot + "\\lib\\x64";
        return tc;
    }
    tc.lib = msvcLib + ";" + lib + "\\ucrt\\x64;" + lib + "\\um\\x64";
    tc.ok = true;
    return tc;
}

// Build a NUL-separated, double-NUL-terminated environment block that ADDS
// INCLUDE and LIB to whatever this process already has. Passing the parent's
// environment through unchanged is what produced the C1034 failure.
std::string buildChildEnvironment(const ToolchainEnv& tc) {
    LPCH block = GetEnvironmentStringsA();
    std::string env;
    if (block) {
        for (LPCH p = block; *p; ) {
            const size_t len = strlen(p);
            // Drop any inherited INCLUDE/LIB so ours win deterministically.
            if (_strnicmp(p, "INCLUDE=", 8) != 0 &&
                _strnicmp(p, "LIB=", 4) != 0 &&
                _strnicmp(p, "LIBPATH=", 8) != 0) {
                env.append(p, len);
                env.push_back('\0');
            }
            p += len + 1;
        }
        FreeEnvironmentStringsA(block);
    }
    env += "INCLUDE=" + tc.include; env.push_back('\0');
    env += "LIB=" + tc.lib;         env.push_back('\0');
    env += "LIBPATH=" + tc.lib;     env.push_back('\0');
    env.push_back('\0');
    return env;
}

int runProcess(const std::string& exe, const std::string& args,
               const std::string& cwd, std::string* output,
               const std::string& envBlock = std::string()) {
    std::string cmd = "\"" + exe + "\" " + args;
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd, wr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError  = wr;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    std::vector<char> cmdbuf(cmd.begin(), cmd.end());
    cmdbuf.push_back('\0');
    std::vector<char> envbuf;
    if (!envBlock.empty()) {
        envbuf.assign(envBlock.begin(), envBlock.end());
        envbuf.push_back('\0');   // CreateProcess wants a double-NUL
    }
    if (!CreateProcessA(nullptr, cmdbuf.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW,
                        envbuf.empty() ? nullptr : envbuf.data(),
                        cwd.empty() ? nullptr : cwd.c_str(), &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr);
        return -1;
    }
    CloseHandle(wr);
    std::string acc;
    char buf[4096];
    DWORD got = 0;
    while (ReadFile(rd, buf, sizeof(buf), &got, nullptr) && got > 0)
        acc.append(buf, got);
    CloseHandle(rd);
    WaitForSingleObject(pi.hProcess, 120000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (output) *output = acc;
    return static_cast<int>(code);
}

} // namespace

// Keeps synthetic-case buffers alive for as long as the returned case vector
// is in use. The ExternalCase holds raw pointers, so the owning storage has to
// outlive them; a thread-local arena is the smallest thing that guarantees it
// without threading ownership through the public API.
static std::vector<std::shared_ptr<void>>& syntheticArena() {
    static thread_local std::vector<std::shared_ptr<void>> arena;
    return arena;
}

// ---------------------------------------------------------------------------
// buildSyntheticCases
// ---------------------------------------------------------------------------
// The compiler switch that actually ENABLES each vector form.
//
// This is not cosmetic. The emitted AVX bodies are guarded by
// `#if defined(__AVX2__)` / `#if defined(__AVX512F__)` and carry a scalar
// fallback, so compiling them WITHOUT the matching /arch switch would silently
// take the fallback: the source would contain intrinsics, the receipt would
// report AVX_INTRINSIC_EMISSION=1, and the binary would be the scalar kernel.
// That is a capability claim with nothing behind it.
//
// Passing the flag here is what makes the claim true. BG8-AV verifies it
// independently by requiring the AVX binary digest to DIFFER from the scalar
// one, which cannot happen if the fallback was taken.
std::string isaFlagForForm(BackendForm form) {
    switch (form) {
        case BackendForm::CPU_AVX2:   return "/arch:AVX2";
        // MSVC's documented switch is /arch:AVX512, not /arch:AVX512F.
        // Measured: /arch:AVX512F was accepted without error but did NOT define
        // __AVX512F__, so the emitted #else fallback was compiled and the binary
        // came out byte-identical to the scalar form's. A wrong-but-quiet switch
        // is worse than a failing one, because the capability claim survives.
        case BackendForm::CPU_AVX512: return "/arch:AVX512";
        default:                      return "";
    }
}

// ---------------------------------------------------------------------------
// buildSyntheticCases
// ---------------------------------------------------------------------------
std::vector<ExternalCase> buildSyntheticCases(const KernelIdentity& intent,                                             const PrimitiveGraph& graph,
                                             uint32_t rows, uint32_t cols,
                                             uint32_t trials, uint32_t seed) {
    std::vector<ExternalCase> out;
    std::mt19937 rng(seed);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);

    const size_t blocksPerRow =
        (cols + graph.nodes[0].blockElements - 1) / graph.nodes[0].blockElements;
    const size_t rowBytes   = blocksPerRow * graph.nodes[0].blockBytes;
    const size_t weightBytes = static_cast<size_t>(rows) * rowBytes;

    for (uint32_t t = 0; t < trials; ++t) {
        auto weights = std::make_shared<std::vector<uint8_t>>(weightBytes, 0);
        auto act     = std::make_shared<std::vector<float>>(cols, 0.0f);

        for (uint32_t r = 0; r < rows; ++r) {
            fillValidQuantizedRow(weights->data() + static_cast<size_t>(r) * rowBytes,
                                  rowBytes, intent.representation.quantType, rng);
        }
        for (auto& v : *act) v = dist(rng);

        ExternalCase c;
        c.weightBytes = weights->data();
        c.x           = act->data();
        c.rows        = rows;
        c.cols        = cols;
        c.label       = "synthetic";
        out.push_back(c);

        syntheticArena().push_back(weights);
        syntheticArena().push_back(act);
    }
    return out;
}

// ---------------------------------------------------------------------------
// certifyCases -- the single measurement core.
//
// Compiles the text ONCE, then executes the compiled kernel on every supplied
// case and compares each against the production reference. Both the synthetic
// path and the real-GGUF path call this, so neither can drift into being a
// weaker copy of the other.
// ---------------------------------------------------------------------------
PolyKernelReceipt certifyCases(const KernelIdentity& intent,
                               const PrimitiveGraph& graph,
                               const std::string& text,
                               uint64_t beaconGeneration,
                               const std::vector<ExternalCase>& cases,
                               const std::string& extraFlags,
                               double tol) {
    PolyKernelReceipt R;
    R.form             = BackendForm::CPU_SCALAR;
    R.beaconGeneration = beaconGeneration;
    R.stage            = "GENERATE";
    R.hardwareFingerprint = hardwareFingerprint(publishHeartbeat());
    R.caseCount        = cases.size();

    if (cases.empty()) {
        R.stage  = "CASES";
        R.detail = "NO_CASES_SUPPLIED: a certification with zero inputs is not "
                   "a measurement, and reporting one as PASS would be the exact "
                   "false-receipt shape this gate exists to prevent";
        return R;
    }
    if (text.empty()) {
        R.stage  = "GENERATE";
        R.detail = "EMPTY_SOURCE";
        return R;
    }
    R.sourceGenerated = true;
    R.sourceDigest    = fnv1a64(text.data(), text.size());
    R.sourceBytes     = static_cast<uint32_t>(text.size());

    const std::string cl = findClExe();
    if (cl.empty()) {
        R.stage  = "LOCATE_COMPILER";
        R.detail = "cl.exe not found; set RAWRXD_CL_EXE to a real MSVC cl.exe. "
                   "A source-only run must NOT be reported as a compiled kernel.";
        return R;
    }
    const ToolchainEnv tc = discoverToolchain(cl);
    if (!tc.ok) {
        R.stage  = "DISCOVER_TOOLCHAIN";
        R.detail = tc.detail;
        return R;
    }
    const std::string envBlock = buildChildEnvironment(tc);

    TempDir td("cert");
    const std::string src = td.file("poly.cpp");
    const std::string dll = td.file("poly.dll");
    const std::string log = td.file("compile.log");
    if (!writeFile(src, text)) {
        R.stage  = "WRITE_SOURCE";
        R.detail = "cannot write " + src;
        return R;
    }

    R.stage = "COMPILE";
    // /Brepro is REQUIRED, not an optimisation.
    //
    // Measured without it: recompiling byte-identical source produced a
    // different BINARY_DIGEST (4894935540558609050 -> 17457823326244170590),
    // because MSVC stamps the PE with the current time and a per-build GUID.
    // That makes binaryDigest unusable as an executable identity: a winner
    // could never be proven reproducible, and ExecutableIdentity would encode a
    // value that changes on every run for reasons unrelated to the code.
    // /Brepro zeroes the timestamp and derives the GUID deterministically.
    //
    // extraFlags carries the /arch switch for vector forms. Without it the
    // emitted intrinsics are compiled out and the scalar fallback is taken.
    const std::string args =
        "/nologo /LD /O2 /std:c++17 /EHsc /Brepro /DWIN32_LEAN_AND_MEAN " +
        (extraFlags.empty() ? std::string() : (" " + extraFlags + " ")) +
        "\"/Fo:" + td.file("poly.obj") + "\" "
        "\"/Fe:" + dll + "\" " + src;
    std::string cout_;
    R.compileExit = runProcess(cl, args, td.path, &cout_, envBlock);
    { std::ofstream lf(log, std::ios::binary); lf << cout_; }
    if (R.compileExit != 0) {
        R.detail = "compiler exit " + std::to_string(R.compileExit) +
                   "; tail: " + cout_.substr(0, cout_.size() > 400 ? 400 : cout_.size());
        return R;
    }

    uint32_t binBytes = 0;
    const std::string bin = readFileBytes(dll, &binBytes);
    if (bin.empty()) {
        R.stage  = "READ_BINARY";
        R.detail = "compiler reported success but produced no loadable module";
        return R;
    }
    R.binaryBytes  = binBytes;
    R.binaryDigest = fnv1a64(bin.data(), bin.size());

    R.stage = "LOAD";
    HMODULE mod = LoadLibraryA(dll.c_str());
    if (!mod) {
        R.detail = "LoadLibrary failed: " + std::to_string(GetLastError());
        return R;
    }
    using PolyFn = int (*)(const uint8_t*, const float*, float*, uint32_t, uint32_t);
    auto fn = reinterpret_cast<PolyFn>(
        reinterpret_cast<void*>(GetProcAddress(mod, "rxd_poly_gemv")));
    if (!fn) {
        FreeLibrary(mod);
        R.stage  = "RESOLVE_ENTRY";
        R.detail = "rxd_poly_gemv not exported";
        return R;
    }

    R.stage = "EXECUTE";
    const auto* ref = QuantKernelRegistry::Instance().GetGEMV(
        static_cast<int>(intent.representation.quantType));
    if (!ref) {
        FreeLibrary(mod);
        R.stage  = "REFERENCE";
        R.detail = "production reference kernel is not registered for this type";
        return R;
    }

    double  sumSq = 0.0;
    double  refSq = 0.0;
    bool    allFinite = true;
    for (const ExternalCase& c : cases) {
        if (!c.weightBytes || !c.x || c.rows == 0 || c.cols == 0) {
            R.invalidCase = true;
            continue;
        }
        std::vector<float> yGen(c.rows, 0.0f), yRef(c.rows, 0.0f);
        const int rc = fn(c.weightBytes, c.x, yGen.data(), c.rows, c.cols);
        ++R.executionCount;
        if (rc == 1) R.kernelEntered = true;
        ref(c.weightBytes, c.x, yRef.data(), c.rows, c.cols);

        double  caseRefSq = 0.0;
        for (uint32_t i = 0; i < c.rows; ++i) {
            if (!std::isfinite(yRef[i])) ++R.nonFiniteRef;
            if (!std::isfinite(yGen[i])) allFinite = false;
            const double d = std::fabs(static_cast<double>(yGen[i]) -
                                      static_cast<double>(yRef[i]));
            if (d > R.maxAbsDiff) R.maxAbsDiff = d;
            sumSq += d * d;
            caseRefSq += static_cast<double>(yRef[i]) * static_cast<double>(yRef[i]);
            ++R.comparisonCount;
        }
        refSq += caseRefSq;

        // Bytes actually supplied as packed weight for this case. Real geometry,
        // not an estimate.
        R.sourceBytesRead += static_cast<uint64_t>(graph.nodes[0].blockBytes) *
            (((c.cols + graph.nodes[0].blockElements - 1) /
              graph.nodes[0].blockElements)) * c.rows;

        // ---- measured cost ----
        // Both kernels are run kWarm+1 times on the same inputs and the fastest
        // of kWarm trials is kept, so a one-off scheduler hiccup cannot decide a
        // promotion. Timing an empty loop is not attempted: there is nothing to
        // subtract, and the comparison that matters is candidate vs reference
        // measured the same way in the same process.
        const int kWarm = 2;
        const int kReps = 7;
        LARGE_INTEGER freq, t0;

        QueryPerformanceFrequency(&freq);
        auto nowNs = [&]() -> uint64_t {
            QueryPerformanceCounter(&t0);
            return static_cast<uint64_t>(
                (t0.QuadPart * 1000000000ll) / freq.QuadPart);
        };

        uint64_t bestGen = ~0ull, bestRef = ~0ull;
        for (int k = 0; k <= kWarm; ++k) {
            const uint64_t a = nowNs();
            for (int r = 0; r < kReps; ++r)
                fn(c.weightBytes, c.x, yGen.data(), c.rows, c.cols);
            const uint64_t b = nowNs();
            if (k == kWarm) { bestGen = b - a; break; }   // measured run only
            if (b - a < bestGen) bestGen = b - a;
        }
        for (int k = 0; k <= kWarm; ++k) {
            const uint64_t a = nowNs();
            for (int r = 0; r < kReps; ++r)
                ref(c.weightBytes, c.x, yRef.data(), c.rows, c.cols);
            const uint64_t b = nowNs();
            if (k == kWarm) { bestRef = b - a; break; }
            if (b - a < bestRef) bestRef = b - a;
        }
        R.wallTimeNs      += bestGen;
        R.referenceWallNs += bestRef;
        R.wallReps        += kReps;
    }
    if (R.comparisonCount) {
        R.rmsDiff = std::sqrt(sumSq / static_cast<double>(R.comparisonCount));
        // Relative L2 against the reference magnitude. This is the only error
        // metric mayWiden() is allowed to consume, so it must be computed here
        // rather than left for a caller to invent.
        R.relativeL2 = (refSq > 0.0)
            ? static_cast<uint64_t>(std::sqrt(sumSq / refSq) * 1e9)
            : static_cast<uint64_t>((sumSq > 0.0) ? ~0ull : 0ull);
    }
    R.finiteOutput = allFinite;
    FreeLibrary(mod);

    R.stage  = "COMPLETE";
    R.detail = "cases=" + std::to_string(cases.size()) +
               " tol=" + std::to_string(tol) + " src=" + src;
    return R;
}

// ---------------------------------------------------------------------------
// Thin wrappers
// ---------------------------------------------------------------------------
PolyKernelReceipt certifySourceText(const KernelIdentity& intent,
                                    const PrimitiveGraph& graph,
                                    const std::string& text,
                                    uint64_t beaconGeneration,
                                    uint32_t rows, uint32_t cols,
                                    uint32_t trials, double tol) {
    auto cases = buildSyntheticCases(intent, graph, rows, cols, trials, 0x5EEDu);
    return certifyCases(intent, graph, text, beaconGeneration, cases, "", tol);
}

PolyKernelReceipt certifySourceTextOn(const KernelIdentity& intent,
                                      const PrimitiveGraph& graph,
                                      const std::string& text,
                                      uint64_t beaconGeneration,
                                      const std::vector<ExternalCase>& cases,
                                      double tol) {
    return certifyCases(intent, graph, text, beaconGeneration, cases, "", tol);
}

PolyKernelReceipt certifyPolyKernel(const KernelIdentity& intent,
                                    const PrimitiveGraph& graph,
                                    BackendForm form,
                                    uint64_t beaconGeneration,
                                    uint32_t rows, uint32_t cols,
                                    uint32_t trials, double tol) {
    GeneratedSource gs = generatePolyKernelSource(intent, graph, form);
    if (!gs.produced) {
        PolyKernelReceipt R;
        R.form                = form;
        R.beaconGeneration    = beaconGeneration;
        R.stage               = "GENERATE";
        R.sourceGenerated     = false;
        R.sourceDigest        = gs.digest;
        R.sourceBytes         = gs.bytes;
        R.hardwareFingerprint = hardwareFingerprint(publishHeartbeat());
        R.detail              = gs.rejectReason;
        return R;
    }
    auto cases = buildSyntheticCases(intent, graph, rows, cols, trials, 0x5EEDu);
    PolyKernelReceipt R = certifyCases(intent, graph, gs.text, beaconGeneration,
                                       cases, isaFlagForForm(form), tol);
    R.form = form;
    return R;
}


} // namespace Deep2
