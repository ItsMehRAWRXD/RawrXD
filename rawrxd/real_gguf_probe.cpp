// real_gguf_probe.cpp
// Step 1 of the real-model Q4_K chain: bind to a REAL GGUF and report exactly
// what it contains, so the parity receipt can name a tensor rather than assert
// one exists.
//
// RAWRXD_Q4K_GEMV_PARITY_001 closure requires, per tensor:
//   model SHA-256, tensor name, GGUF type, byte offset/size, dimensions,
//   input-vector hash, CPU output hash, device output hash, gpu_reached,
//   max abs diff / cosine, and the identity of the executable and source.
// Nothing here may be assumed: if the model is not Q4_K_M, or the tensor is
// absent, that is reported as such and the downstream gate is INVALID, not FAIL.
#include "gguf_loader.hpp"
#include "deep2/QuantKernelRegistry.hpp"

#include <cstdio>
#include <string>
#include <vector>
#include <cmath>
#include <cstring>

// gguf_loader.hpp declares everything inside namespace rawrxd; without this the
// unqualified names do not resolve.
using namespace rawrxd;

static uint64_t Fnv1a64(const void* data, size_t n) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

static const char* TypeName(int t) {
    switch (t) {
        case 0: return "F32";   case 1: return "F16";   case 2: return "Q4_0";
        case 3: return "Q4_1";   case 6: return "Q5_0";  case 7: return "Q5_1";
        case 8: return "Q8_0";   case 9: return "Q8_1";  case 10: return "Q2_K";
        case 11: return "Q3_K";  case 12: return "Q4_K"; case 13: return "Q5_K";
        case 14: return "Q6_K";  case 15: return "Q8_K"; default: return "OTHER";
    }
}

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";
    std::printf("RAWRXD_REAL_GGUF_PROBE=1\n");
    std::printf("MODEL_PATH=%s\n", path.c_str());

    GGUFLoader loader;
    if (!loader.LoadFromFile(path)) {
        std::printf("MODEL_LOAD=FAIL\n");
        std::printf("GATE_STATUS=INVALID  (no model: downstream parity is INVALID, not FAIL)\n");
        return 2;
    }
    std::printf("MODEL_LOAD=PASS\n");
    const GGUFModel* m = loader.GetModel();
    // GGUFHeader::magic is stored as the 4 ASCII bytes, not as a little-endian word.
std::printf("MODEL_MAGIC=%c%c%c%c\n",
            m->header.magic[0], m->header.magic[1],
            m->header.magic[2], m->header.magic[3]);
std::printf("MODEL_MAGIC_OK=%d\n",
            (std::memcmp(m->header.magic, "GGUF", 4) == 0) ? 1 : 0);
    std::printf("GGUF_VERSION=%u\n", (unsigned)m->header.version);
    std::printf("HEADER_TENSOR_COUNT=%llu\n", (unsigned long long)m->header.tensor_count);
    std::printf("HEADER_KV_COUNT=%llu\n", (unsigned long long)m->header.metadata_kv_count);
    std::printf("TENSORS_PARSED=%zu\n", m->tensors.size());
    std::printf("DATA_OFFSET=%zu\n", m->data_offset);

    // Quantization actually present in the file, counted from parsed tensors.
    int counts[32] = {0};
    for (const auto& t : m->tensors) {
        const int ty = static_cast<int>(t.ggml_type);
        if (ty >= 0 && ty < 32) counts[ty]++;
    }
    std::printf("\n; --- tensor type histogram (measured from the file) ---\n");
    for (int i = 0; i < 32; ++i) {
        if (counts[i]) std::printf("TYPE_%s=%d\n", TypeName(i), counts[i]);
    }

    // Architecture and geometry as the file states them.
    std::printf("\n; --- metadata ---\n");
    if (auto a = loader.GetStringMetadata("general.architecture")) std::printf("ARCH=%s\n", a->c_str());
    auto show = [&](const char* k) {
        if (auto v = loader.GetUint32Metadata(k)) std::printf("%s=%u\n", k, *v);
        else if (loader.GetUint32Metadata(k)) std::printf("%s=present\n", k);
    };
    for (const char* k : {"general.file_type"}) { }
    show("llama.embedding_length");
    show("llama.block_count");
    show("llama.attention.head_count");
    show("llama.attention.head_count_kv");
    show("llama.feed_forward_length");
    show("llama.context_length");
    if (auto a = loader.GetStringMetadata("general.quantization_version")) { (void)a; }
    if (auto s = loader.GetStringMetadata("general.file_type")) std::printf("GENERAL_FILE_TYPE=%s\n", s->c_str());

    // The tensor the parity gate would project. Pick blk.0.attn_q.weight if
    // present; report its exact geometry.
    const char* want = "blk.0.attn_q.weight";
    auto it = m->tensors.begin();
    for (auto t = m->tensors.begin(); t != m->tensors.end(); ++t) if (t->name == want) { it = t; break; }
    const bool found = (it != m->tensors.end() && it->name == want);
    std::printf("\n; --- target tensor ---\n");
    std::printf("TARGET_TENSOR=%s\n", want);
    std::printf("TARGET_FOUND=%d\n", found ? 1 : 0);
    if (!found) {
        std::printf("GATE_STATUS=INVALID  (target tensor absent)\n");
        return 3;
    }
    std::printf("TARGET_TYPE=%s\n", TypeName(static_cast<int>(it->ggml_type)));
    std::printf("TARGET_BYTE_OFFSET=%llu\n", (unsigned long long)it->offset);
    std::printf("TARGET_BYTE_SIZE=%zu\n", it->byte_size);
    std::printf("TARGET_ELEMENT_COUNT=%zu\n", it->element_count);
    std::printf("TARGET_BLOCK_SIZE=%zu\n", it->block_size);
    std::printf("TARGET_DIMS=");
    for (size_t i = 0; i < it->shape.size(); ++i)
        std::printf("%s%llu", i ? "x" : "", (unsigned long long)it->shape[i]);
    std::printf("\n");

    auto view = loader.GetTensor(want);
    std::printf("TARGET_VIEW=%d\n", view ? 1 : 0);
    if (!view) {
        std::printf("GATE_STATUS=INVALID  (tensor header present but GetTensor rejected it)\n");
        return 4;
    }

    // Decode the real tensor through the path the inference path uses.
    // This is the moment the P0 fix either holds on production data or does not.
    std::vector<float> decoded;
    const bool decodedOk = view->ToFloat32(decoded);
    std::printf("TARGET_DECODE_OK=%d\n", decodedOk ? 1 : 0);
    if (!decodedOk) {
        std::printf("GATE_STATUS=INVALID  (decoder does not support this type)\n");
        return 5;
    }
    std::printf("TARGET_DECODED_ELEMENTS=%zu\n", decoded.size());

    // Hash the decoded bytes AND the on-disk bytes, so the receipt can bind to
    // both the file content and the decode result.
    const uint8_t* raw = static_cast<const uint8_t*>(view->data<uint8_t>());
    const uint64_t diskHash = Fnv1a64(raw, view->byte_size());
    const uint64_t decHash = Fnv1a64(decoded.data(), decoded.size() * sizeof(float));
    std::printf("TARGET_DISK_BYTES_HASH=%016llx\n", (unsigned long long)diskHash);
    std::printf("TARGET_DECODED_F32_HASH=%016llx\n", (unsigned long long)decHash);

    // Sanity: real Q4_K weights should not be all-zero and should be finite.
    size_t nz = 0, nonfinite = 0;
    double sumabs = 0.0;
    for (float v : decoded) {
        if (!std::isfinite(v)) ++nonfinite;
        if (v != 0.0f) ++nz;
        sumabs += std::fabs((double)v);
    }
    std::printf("TARGET_NONZERO=%zu\n", nz);
    std::printf("TARGET_NONFINITE=%zu\n", nonfinite);
    std::printf("TARGET_MEAN_ABS=%.9g\n", nz ? sumabs / (double)nz : 0.0);
    std::printf("DENSITY=%.6f\n", (double)nz / (double)(decoded.empty() ? 1 : decoded.size()));

    std::printf("\nGPU_REACHED=0\n");
    std::printf("GATE_STATUS=PROBE_COMPLETE_CPU_ONLY\n");
    std::printf("NOTE=this probe binds to a real model and decodes one real tensor.\n");
    std::printf("     It does NOT establish device-vs-CPU parity; that remains OPEN.\n");
    return 0;
}