// ============================================================================
// gguf_layout_probe.cpp
//   RAWRXD_MLA_LOAD_AUTHORITY_001 — classify a GGUF's MLA tensor layout without
//   downloading the whole file.
//
// Why this exists
//   The MLA tensor layout varies by converter vintage. llama.cpp treats
//   attn_k_b + attn_v_b as current and attn_kv_b as "only old legacy GGUF files
//   will have the unsplit wkv_b tensor"; attn_q is valid only when
//   q_lora_rank == 0, otherwise the model carries attn_q_a + attn_q_b.
//
//   Downloading 9.6 GB to discover which layout a file uses is the wrong way to
//   learn that. GGUF stores its header, KV metadata and the entire tensor
//   directory at the front of the file, so a few MB of an HTTP range request
//   answers it.
//
// Usage: gguf_layout_probe <file-or-range-partial.gguf>
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace {

struct Reader {
    const std::vector<uint8_t>& d;
    std::size_t p = 0;
    explicit Reader(const std::vector<uint8_t>& v) : d(v) {}
    bool ok(std::size_t n) const { return p + n <= d.size(); }
    uint8_t u8() { return ok(1) ? d[p++] : (p = d.size(), 0); }
    uint32_t u32() { uint32_t v = 0; if (ok(4)) { std::memcpy(&v, &d[p], 4); p += 4; } else p = d.size(); return v; }
    uint64_t u64() { uint64_t v = 0; if (ok(8)) { std::memcpy(&v, &d[p], 8); p += 8; } else p = d.size(); return v; }
    std::string str() {
        const uint64_t n = u64();
        if (n > d.size() || !ok(static_cast<std::size_t>(n))) { p = d.size(); return {}; }
        std::string s(reinterpret_cast<const char*>(&d[p]), static_cast<std::size_t>(n));
        p += static_cast<std::size_t>(n);
        return s;
    }
};

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: gguf_layout_probe <file>\n");
        return 2;
    }
    std::FILE* f = std::fopen(argv[1], "rb");
    if (!f) {
        std::fprintf(stderr, "cannot open %s\n", argv[1]);
        return 3;
    }
    std::fseek(f, 0, SEEK_END);
    const long fsz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    const std::size_t want = static_cast<std::size_t>(fsz);
    std::vector<uint8_t> buf(want);
    const std::size_t got = std::fread(buf.data(), 1, want, f);
    std::fclose(f);
    buf.resize(got);

    std::printf("FILE=%s\nPREFIX_BYTES=%zu of %ld%s\n", argv[1], got, fsz,
                got < static_cast<std::size_t>(fsz) ? "  (PARTIAL)" : "");

    Reader r(buf);
    char magic[5] = {};
    for (int i = 0; i < 4; ++i) magic[i] = static_cast<char>(r.u8());
    if (std::strncmp(magic, "GGUF", 4) != 0) {
        std::printf("VERDICT=NOT_GGUF magic=%.4s\n", magic);
        return 4;
    }
    const uint32_t version = r.u32();
    const uint64_t tensorCount = r.u64();
    const uint64_t kvCount = r.u64();
    std::printf("GGUF_VERSION=%u TENSOR_COUNT=%llu KV_COUNT=%llu\n", version,
                (unsigned long long)tensorCount, (unsigned long long)kvCount);

    // Skip the KV section. Each value's byte length depends on its type, so
    // walk it properly rather than guessing.
    // GGUF value types: 0..7 fixed-width <=8B, 8 STRING, 9 ARRAY, 10..12 <=8B.
    std::function<bool(uint32_t)> skipScalar = [&](uint32_t type) -> bool {
        switch (type) {
        case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
        case 10: case 11: case 12:
            r.u64();
            return r.p <= r.d.size();
        case 8: {  // STRING
            const uint64_t n = r.u64();
            if (n > r.d.size() || !r.ok(static_cast<std::size_t>(n))) return false;
            r.p += static_cast<std::size_t>(n);
            return true;
        }
        case 9: {  // ARRAY: elem type, count, then elements
            const uint32_t elem = r.u32();
            const uint64_t count = r.u64();
            if (elem == 8) {
                for (uint64_t i = 0; i < count; ++i) {
                    const uint64_t n = r.u64();
                    if (n > r.d.size() || !r.ok(static_cast<std::size_t>(n))) return false;
                    r.p += static_cast<std::size_t>(n);
                }
                return true;
            }
            if (!skipScalar(elem)) return false;
            const std::size_t width =
                (elem == 0 || elem == 1) ? 1 : (elem == 2 || elem == 3) ? 2 :
                (elem == 8) ? 0 : 4;
            if (width == 0) return false;
            const uint64_t bytes = count * width;
            if (bytes > r.d.size() || !r.ok(static_cast<std::size_t>(bytes))) return false;
            r.p += static_cast<std::size_t>(bytes);
            return true;
        }
        default: return false;
        }
    };
    bool kvOk = true;
    for (uint64_t i = 0; i < kvCount && kvOk; ++i) {
        r.str();  // key
        const uint32_t t = r.u32();
        if (!skipScalar(t)) kvOk = false;
    }
    if (!kvOk) {
        std::printf("VERDICT=HEADER_TRUNCATED_DURING_KV  (fetch a larger prefix)\n");
        return 5;
    }

    std::vector<std::string> names;
    bool tensorOk = true;
    for (uint64_t i = 0; i < tensorCount && tensorOk; ++i) {
        const std::string name = r.str();
        const uint32_t ndims = r.u32();
        std::vector<int64_t> dims(ndims);
        for (uint32_t k = 0; k < ndims; ++k) dims[k] = static_cast<int64_t>(r.u64());
        r.u32();  // ggml type
        r.u64();  // offset
        if (r.p > r.d.size()) { tensorOk = false; break; }
        names.push_back(name);
        if (name.rfind("blk.0.", 0) == 0 && name.find("attn") != std::string::npos) {
            std::printf("  %-34s dims=[", name.c_str());
            for (std::size_t k = 0; k < dims.size(); ++k) {
                std::printf("%s%lld", k ? "," : "", (long long)dims[k]);
            }
            std::printf("]\n");
        }
    }
    if (!tensorOk) {
        std::printf("VERDICT=HEADER_TRUNCATED_DURING_TENSORS  (fetch a larger prefix)\n");
        return 6;
    }
    std::printf("TENSOR_NAMES_READ=%zu\n", names.size());

    auto has = [&](const char* leaf) {
        const std::string k = std::string("blk.0.") + leaf;
        for (const auto& n : names) if (n == k) return true;
        return false;
    };
    const bool splitQ  = has("attn_q_a.weight") && has("attn_q_b.weight");
    const bool splitKV = has("attn_k_b.weight") && has("attn_v_b.weight");
    const bool fusedKV = has("attn_kv_b.weight");
    const bool mqa     = has("attn_kv_a_mqa.weight");

    std::printf("MLA_KV_A_MQA_PRESENT=%d\n", mqa ? 1 : 0);
    std::printf("MLA_SPLIT_Q_PRESENT=%d\n", splitQ ? 1 : 0);
    std::printf("MLA_SPLIT_KV_PRESENT=%d\n", splitKV ? 1 : 0);
    std::printf("MLA_FUSED_KV_B_PRESENT=%d\n", fusedKV ? 1 : 0);

    const bool consumerReady = mqa && splitQ && splitKV && has("attn_kv_a_norm.weight");
    std::printf("CONSUMER_SPLIT_LAYOUT_READY=%d\n", consumerReady ? 1 : 0);
    std::printf("LAYOUT=%s\n", consumerReady ? "split" : (fusedKV ? "legacy-fused" : "unknown"));
    std::printf("VERDICT=%s\n", consumerReady ? "USABLE" : "NOT_USABLE_BY_SPLIT_CONSUMER");
    return consumerReady ? 0 : 7;
}