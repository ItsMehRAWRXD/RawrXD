// ============================================================================
// tools/gguf_head_type.cpp  --  read-only GGUF header probe
// ============================================================================
// One measurement: what is the quant type of the final output projection?
//
// This exists because the tree already carries a warning about exactly this
// question. Deep2Engine.cpp records that a previous probe read lm_head's type and
// reported the MODEL as Q6_K when the histogram was Q4_K=168 / Q6_K=30 -- i.e. a
// single tensor was generalised into a model-wide claim. So the type is read
// per tensor here, and the full histogram is printed alongside it.
//
// TYPE TABLE -- THIS FILE HAS NO TABLE OF ITS OWN.
// An earlier revision kept a local ggml_type list and got it wrong twice,
// "disproving" a correct claim both times: first by listing only live quant
// types, then by "fixing" the comment while leaving the array wrong. The real
// hazard is structural -- this tree declares GGMLType in at least five places
// (src/gguf_loader.hpp, src/llm_adapter/gguf_k_quants.hpp,
// src/deep2/GGUFLoader.hpp, src/core/sovereign_gguf_loader.h, and the engine's
// own switch). The tool therefore includes the engine's canonical enum and
// static_asserts against it, so the diagnostic and production code cannot drift
// apart again.
//
// Reads the header only. The payload is never touched.
// ============================================================================
#include "deep2/GGUFLoader.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>

// The engine's canonical mapping is the authority for everything below.
static_assert(static_cast<uint32_t>(Deep2::GGMLType::GGML_TYPE_Q4_K) == 12,
              "GGML type table drift: Q4_K must be 12");
static_assert(static_cast<uint32_t>(Deep2::GGMLType::GGML_TYPE_Q5_K) == 13,
              "GGML type table drift: Q5_K must be 13");
static_assert(static_cast<uint32_t>(Deep2::GGMLType::GGML_TYPE_Q6_K) == 14,
              "GGML type table drift: Q6_K must be 14");
static_assert(static_cast<uint32_t>(Deep2::GGMLType::GGML_TYPE_Q8_K) == 15,
              "GGML type table drift: Q8_K must be 15");

namespace {

struct R {
    const uint8_t* p; const uint8_t* end;
    bool ok = true;
    bool need(size_t n) { if ((size_t)(end - p) < n) { ok = false; return false; } return true; }
    uint32_t u32() { if (!need(4)) return 0; uint32_t v; memcpy(&v, p, 4); p += 4; return v; }
    uint64_t u64() { if (!need(8)) return 0; uint64_t v; memcpy(&v, p, 8); p += 8; return v; }
    // Fixed-width readers. GGUF value widths differ by type: reading everything
    // as 4 bytes desynchronises the KV stream at the first uint8 or uint16 and
    // makes every later field garbage.
    uint8_t  u8v() { if (!need(1)) return 0; uint8_t v = *p++; return v; }
    uint16_t u16v() { if (!need(2)) return 0; uint16_t v; memcpy(&v, p, 2); p += 2; return v; }
    std::string str() {
        const uint64_t n = u64();
        if (!need((size_t)n)) return {};
        std::string s((const char*)p, (size_t)n);
        p += n;
        return s;
    }
    void skip(int type) {
        switch (type) {
            case 0: u8v(); break;                          // UINT8
            case 1: u8v(); break;                          // INT8
            case 2: u16v(); break;                         // UINT16
            case 3: u16v(); break;                         // INT16
            case 4: case 5: u32(); break;                  // UINT32 / INT32
            case 6: u32(); break;                          // FLOAT32
            case 7: u8v(); break;                          // BOOL
            case 8: str(); break;                         // STRING
            case 9: {                                     // ARRAY
                const uint32_t et = u32();
                const uint64_t n = u64();
                for (uint64_t i = 0; i < n && ok; ++i) skip(et);
                break;
            }
            case 10: case 11: case 12: u64(); break;       // UINT64/INT64/FLOAT64
            default: ok = false; break;
        }
    }
};

// Type naming is derived from the ENGINE'S enum, never from a local list. The
// only name written out by hand is the one the routing decision turns on, and it
// is asserted against the enum above.
const char* typeName(uint32_t t) {
    if (t == static_cast<uint32_t>(Deep2::GGMLType::GGML_TYPE_Q6_K)) return "Q6_K";
    switch (static_cast<Deep2::GGMLType>(t)) {
        case Deep2::GGMLType::GGML_TYPE_F32:  return "F32";
        case Deep2::GGMLType::GGML_TYPE_F16:  return "F16";
        case Deep2::GGMLType::GGML_TYPE_Q4_0: return "Q4_0";
        case Deep2::GGMLType::GGML_TYPE_Q4_1: return "Q4_1";
        case Deep2::GGMLType::GGML_TYPE_Q5_0: return "Q5_0";
        case Deep2::GGMLType::GGML_TYPE_Q5_1: return "Q5_1";
        case Deep2::GGMLType::GGML_TYPE_Q8_0: return "Q8_0";
        case Deep2::GGMLType::GGML_TYPE_Q2_K: return "Q2_K";
        case Deep2::GGMLType::GGML_TYPE_Q3_K: return "Q3_K";
        case Deep2::GGMLType::GGML_TYPE_Q4_K: return "Q4_K";
        case Deep2::GGMLType::GGML_TYPE_Q5_K: return "Q5_K";
        case Deep2::GGMLType::GGML_TYPE_Q8_K: return "Q8_K";
        case Deep2::GGMLType::GGML_TYPE_I8:   return "I8";
        case Deep2::GGMLType::GGML_TYPE_I16:  return "I16";
        case Deep2::GGMLType::GGML_TYPE_I32:  return "I32";
        case Deep2::GGMLType::GGML_TYPE_I64:  return "I64";
        case Deep2::GGMLType::GGML_TYPE_F64:  return "F64";
        case Deep2::GGMLType::GGML_TYPE_BF16: return "BF16";
        default: return nullptr;
    }
}

// Human label, or an explicit UNKNOWN rather than a silent index lookup.
std::string typeLabel(uint32_t t) {
    const char* n = typeName(t);
    return n ? std::string(n) : ("UNKNOWN_TYPE_" + std::to_string(t));
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: gguf_head_type <model.gguf>\n"); return 2; }
    FILE* f = std::fopen(argv[1], "rb");
    if (!f) { std::fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }
    std::fseek(f, 0, SEEK_END);
    const long long sz = _ftelli64(f);
    std::fseek(f, 0, SEEK_SET);
    // Header is small; read a generous prefix. Payload is never mapped.
    const size_t want = 8u * 1024u * 1024u;
    std::vector<uint8_t> buf((size_t)(sz < (long long)want ? sz : (long long)want));
    if (std::fread(buf.data(), 1, buf.size(), f) != buf.size()) { std::fclose(f); return 2; }
    std::fclose(f);

    R r{buf.data(), buf.data() + buf.size()};
    const uint32_t magic = r.u32();
    if (magic != 0x46554747u) { std::fprintf(stderr, "not a GGUF file\n"); return 2; }
    const uint32_t ver = r.u32();
    const uint64_t nTensors = r.u64();
    const uint64_t nKv = r.u64();
    std::printf("=== GGUF HEADER PROBE ===\n");
    std::printf("file=%s\nversion=%u tensors=%llu kv=%llu\n", argv[1], ver,
                (unsigned long long)nTensors, (unsigned long long)nKv);

    for (uint64_t i = 0; i < nKv && r.ok; ++i) { const std::string k = r.str(); (void)k; r.skip(r.u32()); }
    if (!r.ok) { std::fprintf(stderr, "KV parse failed\n"); return 2; }

    std::map<uint32_t, uint64_t> hist;
    struct Hit { std::string name; uint32_t type; std::string dims; };
    std::vector<Hit> hits;

    for (uint64_t i = 0; i < nTensors && r.ok; ++i) {
        const std::string name = r.str();
        const uint32_t nd = r.u32();
        std::string dims;
        for (uint32_t d = 0; d < nd; ++d) {
            const uint64_t v = r.u64();
            if (d) dims += "x";
            dims += std::to_string(v);
        }
        const uint32_t ty = r.u32();
        (void)r.u64();   // offset
        ++hist[ty];
        // Exact names only. A substring test for "output.weight" also matches
        // every "blk.N.attn_output.weight", which made a 28-layer model look like
        // it had 28 separate output projections.
        const bool isFinalProjection =
            (name == "output.weight" || name == "lm_head.weight" ||
             name == "output" || name == "lm_head");
        if (isFinalProjection || name == "token_embd.weight") {
            hits.push_back(Hit{name, ty, dims});
        }
    }
    if (!r.ok) { std::fprintf(stderr, "tensor-info parse failed (file may exceed the read window)\n"); return 2; }

    std::printf("\n--- type histogram over ALL %llu tensors ---\n",
                (unsigned long long)nTensors);
    for (const auto& kv : hist) {
        std::printf("  %-16s %6llu\n", typeLabel(kv.first).c_str(), (unsigned long long)kv.second);
    }

    std::printf("\n--- final projection / embedding tensors ---\n");
    for (const auto& h : hits) {
        std::printf("  %-28s type=%u (%s) dims=%s\n", h.name.c_str(), h.type,
                    typeLabel(h.type).c_str(), h.dims.c_str());
    }

    bool sawOutput = false, outputIsQ6K = false, embedIsQ6K = false;
    for (const auto& h : hits) {
        if (h.name == "token_embd.weight") embedIsQ6K = (h.type == 14);
        if (h.name == "output.weight" || h.name == "lm_head.weight") {
            sawOutput = true;
            outputIsQ6K = (h.type == 14);
        }
    }
    std::printf("\nKNOWN_TYPE_14_NAME=Q6_K (asserted against Deep2::GGMLType)\n");
    std::printf("OUTPUT_WEIGHT_PRESENT=%d\n", sawOutput ? 1 : 0);
    std::printf("OUTPUT_WEIGHT_IS_Q6K=%d\n", outputIsQ6K ? 1 : 0);
    std::printf("TOKEN_EMBD_IS_Q6K=%d\n", embedIsQ6K ? 1 : 0);
    // With no output.weight the head is tied to the embedding, so the head's type
    // IS the embedding's type. That is the whole claim: the tied head is Q6_K
    // while the model as a whole is overwhelmingly Q4_K/F32.
    const bool tiedHeadIsQ6K = (!sawOutput) && embedIsQ6K;
    std::printf("LM_HEAD_IS_TIED=%d\n", sawOutput ? 0 : 1);
    std::printf("EFFECTIVE_LM_HEAD_IS_Q6K=%d\n", (sawOutput ? outputIsQ6K : embedIsQ6K) ? 1 : 0);
    std::printf("VERDICT=%s\n", (sawOutput ? outputIsQ6K : embedIsQ6K)
                                       ? "Q6K_HEAD_CONFIRMED"
                                       : "Q6K_HEAD_NOT_CONFIRMED");
    if (tiedHeadIsQ6K) {
        std::printf("NOTE=single tensor is Q6_K while the model histogram above is"
                    " not; do NOT generalise this to a model-wide quant claim\n");
    }
    return 0;
}
