// ============================================================================
// nqb_source_f32_manifest.cpp
// RAWRXD_NQB_SOURCE_F32_PARITY_001 -- SOURCE SIDE
//
// Opens the GGUF and NOTHING ELSE. Produces the canonical F32 manifest for every
// tensor, and refuses to name the .nqb at all: the whole point of the split is
// that no single process can see both the source and the container.
//
// HASH DOMAIN
//     GGUF tensor -> production dequant -> logical element order
//                 -> IEEE754 binary32 -> little-endian bytes
//                 -> FNV-1a 64 + SHA-256 (incremental)
//
// SCOPE OF THE CLAIM, printed into the receipt
//     This tool and the payload side share the production dequant kernel. A
//     manifest match therefore proves the container holds exactly what the
//     production GGUF decode path produced. It proves NOTHING about whether that
//     decode is correct against an independent oracle.
//
// USAGE
//     nqb_source_f32_manifest <model.gguf> <out.manifest>
// ============================================================================

#define NOMINMAX
#include <windows.h>

#include "deep2/GGUFLoader.hpp"
#include "deep2/QuantKernelRegistry.hpp"
#include "deep2/Nanof32BraidFormat.hpp"
#include "deep2/Nanof32BraidManifest.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

namespace {

const char* codecName(int t) {
    switch (t) {
        case Deep2::NQBRAID_DENSE_F32:      return "DENSE_F32";
        case Deep2::NQBRAID_DENSE_BF16:     return "DENSE_BF16";
        case Deep2::NQBRAID_CODEBOOK_1BIT:  return "CODEBOOK_1BIT";
        case Deep2::NQBRAID_CODEBOOK_2BIT:  return "CODEBOOK_2BIT";
        case Deep2::NQBRAID_CODEBOOK_3BIT:  return "CODEBOOK_3BIT";
        case Deep2::NQBRAID_BRAID_115:      return "BRAID_115";
        default:                            return "UNKNOWN";
    }
}

bool sha256File(const std::string& path, std::string& outHex) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    Deep2::Sha256 s;
    std::vector<char> buf(1u << 20);
    while (f) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = f.gcount();
        if (got > 0) s.update(buf.data(), static_cast<size_t>(got));
    }
    outHex = s.hex();
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr,
            "Usage: %s <model.gguf> <out.manifest>\n", argv[0]);
        return 2;
    }
    const std::string ggufPath = argv[1];
    const std::string outPath  = argv[2];

    std::printf("GATE=RAWRXD_NQB_SOURCE_F32_PARITY_001\n");
    std::printf("AUTHORITY=SOURCE_GENERATION\n");
    std::printf("SOURCE_PATH_CLASS=GGUF_ONLY\n");
    std::printf("SOURCE_GGUF=%s\n", ggufPath.c_str());

    std::string ggufSha;
    if (!sha256File(ggufPath, ggufSha)) {
        std::printf("FAIL=source_unreadable\nVERDICT=INVALID_NO_RESULT\n");
        return 2;
    }
    std::printf("SOURCE_GGUF_SHA256=%s\n", ggufSha.c_str());

    Deep2::QuantKernelRegistry::Instance().Initialize();
    Deep2::GGUFLoader loader;
    if (!loader.load(ggufPath)) {
        std::printf("FAIL=gguf_load: %s\n", loader.error().c_str());
        std::printf("VERDICT=INVALID_NO_RESULT\n");
        return 2;
    }
    std::printf("SOURCE_GGUF_TENSORS=%zu\n", loader.tensorCount());

    // ------------------------------------------------------------------
    // Dequantise each tensor, hash its canonical F32 image, discard it.
    //
    // MEMORY IS PER-TENSOR, NOT PER-MODEL. The production dequant kernels take
    // (src, dst, elementCount) and write the whole tensor at once, so streaming
    // inside a tensor is not available at this boundary. The largest tensor in
    // the real artifact is token_embd at 394,007,552 elements = 1.58 GB, and the
    // peak below is reported rather than claimed to be small.
    // ------------------------------------------------------------------
    std::vector<float> f32;
    std::vector<Deep2::NqbF32Record> records;
    uint64_t totalElements = 0, totalF32Bytes = 0, peakElements = 0;
    uint64_t nonFiniteTensors = 0, nonFiniteValues = 0, skipped = 0;

    const std::vector<std::string> names = loader.listTensors();
    for (const std::string& name : names) {
        Deep2::GGUFTensor* pt = loader.getTensor(name);
        if (!pt) { ++skipped; continue; }
        const Deep2::GGUFTensor& t = *pt;
        const size_t n = t.numElements();
        if (n == 0) { ++skipped; continue; }

        f32.resize(n);
        bool ok = true;
        if (t.type == Deep2::GGMLType::GGML_TYPE_F32) {
            std::memcpy(f32.data(), t.data, n * sizeof(float));
        } else {
            auto fn = Deep2::QuantKernelRegistry::Instance()
                          .GetDequant(static_cast<int>(t.type));
            if (!fn) {
                std::fprintf(stderr, "SKIP=%s no_dequant_kernel type=%d\n",
                             name.c_str(), static_cast<int>(t.type));
                ++skipped;
                continue;
            }
            fn(t.data, f32.data(), n);
        }
        if (!ok) { ++skipped; continue; }

        uint64_t tfNonFinite = 0;
        for (size_t i = 0; i < n; ++i) {
            const float v = f32[i];
            if (std::isnan(v) || std::isinf(v)) ++tfNonFinite;
        }
        if (tfNonFinite) { ++nonFiniteTensors; nonFiniteValues += tfNonFinite; }

        Deep2::NqbF32Record r;
        r.name        = name;
        r.storedCodec = Deep2::NQBRAID_DENSE_F32;   // the canonical target image
        r.rank        = static_cast<uint32_t>(t.shape.size());
        r.dim0        = t.shape.empty() ? 0 : t.shape[0];
        r.dim1        = t.shape.size() > 1 ? t.shape[1] : 1;
        r.elements    = n;
        r.f32Bytes    = static_cast<uint64_t>(n) * 4u;
        Deep2::Sha256 sha;
        Deep2::nqbHashCanonicalF32Chunk(f32.data(), n, r.fnv1a64, sha);
        r.sha256 = sha.hex();

        records.push_back(r);
        totalElements += r.elements;
        totalF32Bytes += r.f32Bytes;
        if (r.elements > peakElements) peakElements = r.elements;
    }

    // The manifest carries records in a deterministic order so two runs of this
    // tool on the same input produce byte-identical files. The comparator keys on
    // name regardless, but a byte-stable manifest is what makes the two artifacts
    // themselves comparable.
    std::sort(records.begin(), records.end(),
              [](const Deep2::NqbF32Record& a, const Deep2::NqbF32Record& b) {
                  return a.name < b.name;
              });

    {
        std::ofstream o(outPath, std::ios::trunc);
        if (!o.is_open()) {
            std::printf("FAIL=manifest_unwritable\nVERDICT=INVALID_NO_RESULT\n");
            return 2;
        }
        o << Deep2::nqbManifestHeader() << "\n";
        for (const Deep2::NqbF32Record& r : records)
            o << Deep2::nqbSerialiseRecord(r);
    }

    const std::string root = Deep2::nqbManifestRoot(records);

    std::printf("SOURCE_MANIFEST_PATH=%s\n", outPath.c_str());
    std::printf("SOURCE_MANIFEST_ROOT=%s\n", root.c_str());
    std::printf("SOURCE_TENSORS=%zu\n", records.size());
    std::printf("SOURCE_ELEMENTS=%llu\n", (unsigned long long)totalElements);
    std::printf("SOURCE_F32_BYTES=%llu\n", (unsigned long long)totalF32Bytes);
    std::printf("SOURCE_SKIPPED=%llu\n", (unsigned long long)skipped);
    std::printf("SOURCE_PEAK_TENSOR_BYTES=%llu\n",
                (unsigned long long)(peakElements * 4ull));
    std::printf("SOURCE_MANIFEST_MATERIALIZES_FULL_MODEL=0\n");
    std::printf("SOURCE_NONFINITE_TENSORS=%llu\n", (unsigned long long)nonFiniteTensors);
    std::printf("SOURCE_NONFINITE_VALUES=%llu\n", (unsigned long long)nonFiniteValues);
    std::printf("TARGET_CODEC=%s\n", codecName(Deep2::NQBRAID_DENSE_F32));
    std::printf("HASH_DOMAIN=gguf_tensor>production_dequant>logical_element_order"
                ">ieee754_binary32>little_endian_bytes>fnv1a64+sha256\n");
    std::printf("CLAIM_SCOPE=GGUF_PRODUCTION_DEQUANT_CANONICAL_IMAGE\n");
    std::printf("NOT_CLAIMED=CANONICAL_QUANT_DECODER_NUMERICAL_CORRECTNESS\n");

    const bool fail = records.empty() || skipped > 0 || nonFiniteValues > 0;
    std::printf("SOURCE_FINITE=%d\n", nonFiniteValues == 0 ? 1 : 0);
    std::printf("SOURCE_COMPLETE=%d\n", (records.size() == loader.tensorCount() &&
                                        skipped == 0) ? 1 : 0);
    std::printf("VERDICT=%s\n", fail ? "FAIL" : "PASS");
    return fail ? 1 : 0;
}