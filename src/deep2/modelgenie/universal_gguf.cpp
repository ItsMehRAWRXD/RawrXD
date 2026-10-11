

// ============================================================================
// universal_gguf.cpp  --  RAWRXD_DEEP2_UNIVERSAL_INGEST
// ============================================================================
#include "universal_gguf.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <mutex>

#include "ggml.h"

namespace RawrXD { namespace Deep2 { namespace Universal {

namespace {
// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), self-contained. Used only to fingerprint the model so a
// run can be audited after the fact.
// ---------------------------------------------------------------------------
struct Sha256 {
    uint32_t h[8];
    uint64_t len = 0;
    uint8_t buf[64];
    size_t bufn = 0;

    Sha256() {
        static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
        for (int i = 0; i < 8; ++i) h[i] = iv[i];
    }
    static uint32_t ror(uint32_t x, int c) { return (x >> c) | (x << (32 - c)); }
    void block(const uint8_t* p) {
        static const uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(p[i*4]) << 24) | (uint32_t(p[i*4+1]) << 16) |
                   (uint32_t(p[i*4+2]) << 8) | uint32_t(p[i*4+3]);
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = ror(w[i-15],7) ^ ror(w[i-15],18) ^ (w[i-15] >> 3);
            const uint32_t s1 = ror(w[i-2],17) ^ ror(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            const uint32_t S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
            const uint32_t ch = (e & f) ^ (~e & g);
            const uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            const uint32_t S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
            const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    void update(const uint8_t* p, size_t n) {
        len += n;
        while (n) {
            const size_t k = std::min<size_t>(n, 64 - bufn);
            std::memcpy(buf + bufn, p, k);
            bufn += k; p += k; n -= k;
            if (bufn == 64) { block(buf); bufn = 0; }
        }
    }
    std::string hex() const {
        Sha256 cp = *this;
        const uint64_t bits = cp.len * 8;
        uint8_t pad = 0x80;
        cp.update(&pad, 1);
        const uint8_t z = 0;
        while (cp.bufn != 56) cp.update(&z, 1);
        uint8_t lb[8];
        for (int i = 0; i < 8; ++i) lb[i] = (uint8_t)(bits >> (56 - 8*i));
        cp.update(lb, 8);
        char out[65];
        for (int i = 0; i < 8; ++i) std::snprintf(out + i*8, 9, "%08X", cp.h[i]);
        out[64] = 0;
        std::string s(out);
        for (auto& ch : s) ch = (char)std::tolower((unsigned char)ch);
        return s;
    }
};

std::string Sha256FileImpl(const std::string& path) {
#ifdef _WIN32
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    HANDLE m = CreateFileMappingA(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!m) { CloseHandle(h); return {}; }
    const uint8_t* base = (const uint8_t*)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    Sha256 s;
    if (base) {
        const uint8_t* p = base;
        size_t left = (size_t)sz.QuadPart;
        while (left) {
            const size_t k = std::min<size_t>(left, 8u << 20);
            s.update(p, k);
            p += k; left -= k;
        }
        UnmapViewOfFile(base);
    }
    CloseHandle(m);
    CloseHandle(h);
    return s.hex();
#else
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return {};
    Sha256 s;
    uint8_t tmp[1 << 20];
    ssize_t r;
    while ((r = ::read(fd, tmp, sizeof(tmp))) > 0) s.update(tmp, (size_t)r);
    ::close(fd);
    return s.hex();
#endif
}

Tokenizer g_tokenizer;
Provenance g_prov;


// ---------------------------------------------------------------------------
// Generic GGUF v3 reader. Correct handling of every metadata value type,
// including the one that trips most parsers up: GGUF BOOL is a 1-byte C++ bool.
// ---------------------------------------------------------------------------
struct Reader {
    const uint8_t* base = nullptr;
    size_t size = 0;
    size_t pos = 0;
    uint32_t geom = 32;   // general.alignment, default 32

#ifdef _WIN32
    HANDLE map_ = nullptr;
#else
    int fd_ = -1;
#endif

    bool Open(const std::string& path) {
#ifdef _WIN32
        HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return false; }
        HANDLE m = CreateFileMappingA(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!m) { CloseHandle(h); return false; }
        base = static_cast<const uint8_t*>(
            MapViewOfFile(m, FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(sz.QuadPart)));
        map_ = m;
        size = static_cast<size_t>(sz.QuadPart);
#else
        fd_ = ::open(path.c_str(), O_RDONLY);
        if (fd_ < 0) return false;
        struct stat st{};
        if (::fstat(fd_, &st) != 0) return false;
        size = static_cast<size_t>(st.st_size);
        base = static_cast<const uint8_t*>(
            ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd_, 0));
#endif
        return base != nullptr;
    }

    void Close() {
#ifdef _WIN32
        if (base) UnmapViewOfFile(base);
        if (map_) CloseHandle(map_);
#else
        if (base && base != MAP_FAILED)
            ::munmap(const_cast<uint8_t*>(base), size);
        if (fd_ >= 0) ::close(fd_);
#endif
        base = nullptr;
    }

    bool Need(size_t n) const { return pos + n <= size; }
    uint32_t U32() { if (!Need(4)) return 0; uint32_t v; std::memcpy(&v, base + pos, 4); pos += 4; return v; }
    uint64_t U64() { if (!Need(8)) return 0; uint64_t v; std::memcpy(&v, base + pos, 8); pos += 8; return v; }
    int64_t I64() { if (!Need(8)) return 0; int64_t v; std::memcpy(&v, base + pos, 8); pos += 8; return v; }
    float F32() { if (!Need(4)) return 0; float v; std::memcpy(&v, base + pos, 4); pos += 4; return v; }
    std::string Str() {
        const uint64_t n = U64();
        if (!Need(static_cast<size_t>(n))) { pos = size; return {}; }
        std::string s(reinterpret_cast<const char*>(base + pos), static_cast<size_t>(n));
        pos += static_cast<size_t>(n);
        return s;
    }

    // Scalar type sizes. BOOL is 1 byte - the detail most GGUF parsers get wrong.
    static size_t ScalarBytes(uint32_t t) {
        switch (t) {
            case 0: case 1: return 1;                       // u8 / i8
            case 2: case 3: return 2;                       // u16 / i16
            case 4: case 5: case 6: return 4;               // u32 / i32 / f32
            case 7: return 1;                               // BOOL -> 1 byte
            case 10: case 11: case 12: return 8;            // u64 / i64 / f64
            default: return 0;
        }
    }

    // Skip one metadata value, recursing through arrays.
    bool SkipValue(uint32_t t, int depth) {
        if (depth > 10) return false;
        if (t == 8) { Str(); return true; }
        if (t == 9) {
            const uint32_t et = U32();
            const uint64_t n = U64();
            for (uint64_t i = 0; i < n; ++i)
                if (!SkipValue(et, depth + 1)) return false;
            return true;
        }
        const size_t b = ScalarBytes(t);
        if (b == 0) return false;
        if (!Need(b)) { pos = size; return true; }
        pos += b;
        return true;
    }

    // Read every metadata key as a string (values skipped), so the caller can
    // pick the ones it needs without a full value model.
    bool ParseHeader(std::map<std::string, std::string>& meta,
                     uint64_t& tensor_count, uint64_t& kv_count) {
        if (!Need(24)) return false;
        if (U32() != 0x46554747u) return false;      // "GGUF"
        const uint32_t version = U32();
        (void)version;
        tensor_count = U64();
        kv_count = U64();

        for (uint64_t i = 0; i < kv_count; ++i) {
            if (!Need(8)) return false;
            std::string key = Str();
            const uint32_t t = U32();
            const std::string v = ReadScalar(t);
            if (!meta.emplace(key, v).second) meta[key] = v;
            if (t == 8 || t == 9) { if (!FinishComplex(t)) return false; }
            else if (ScalarBytes(t) == 0) {
                // Unknown type: try to skip as a scalar of 4, else bail.
                if (!SkipValue(t, 0)) return false;
            }
        }
        return true;
    }

    // Read the scalar value (string/array values are consumed by FinishComplex).
    std::string ReadScalar(uint32_t t) {
        switch (t) {
            case 0: { uint8_t v = base[pos]; pos += 1; return std::to_string((int)v); }
            case 1: { int8_t v; std::memcpy(&v, base + pos, 1); pos += 1; return std::to_string((int)v); }
            case 2: { uint16_t v; std::memcpy(&v, base + pos, 2); pos += 2; return std::to_string((int)v); }
            case 3: { int16_t v; std::memcpy(&v, base + pos, 2); pos += 2; return std::to_string((int)v); }
            case 4: { uint32_t v; std::memcpy(&v, base + pos, 4); pos += 4; return std::to_string(v); }
            case 5: { int32_t v; std::memcpy(&v, base + pos, 4); pos += 4; return std::to_string(v); }
            case 6: { float v; std::memcpy(&v, base + pos, 4); pos += 4; return std::to_string(v); }
            case 7: { uint8_t v; std::memcpy(&v, base + pos, 1); pos += 1; return std::to_string((int)v); }
            case 8: return Str();
            case 10: { uint64_t v; std::memcpy(&v, base + pos, 8); pos += 8; return std::to_string(v); }
            case 11: { int64_t v; std::memcpy(&v, base + pos, 8); pos += 8; return std::to_string(v); }
            case 12: { double v; std::memcpy(&v, base + pos, 8); pos += 8; return std::to_string(v); }
            default: return {};
        }
    }

    // After ReadScalar for string/array, consume the remaining structure.
    bool FinishComplex(uint32_t t) {
        if (t == 8) return true;                    // string fully consumed by ReadScalar
        if (t == 9) {
            const uint32_t et = U32();
            const uint64_t n = U64();
            std::map<uint32_t, size_t> counts;
            for (uint64_t i = 0; i < n; ++i) {
                const std::string v = ReadScalar(et);
                counts[et] += v.size();
            }
            (void)counts;
            return true;
        }
        return true;
    }

    // Tensor directory. Bounded by the declared tensor_count: walking until
    // end-of-file would run off the directory into the tensor payload and
    // read the weight bytes as if they were names.
    bool ParseTensors(size_t tensor_count, std::vector<TensorRec>& out, std::string& err) {
        uint64_t max_end = 0;
        std::vector<TensorRec> ordered;   // directory order, before offset fixup
        for (uint64_t i = 0; i < tensor_count; ++i) {
            if (!Need(4)) { err = "tensor directory truncated"; return false; }
            TensorRec t;
            t.name = Str();
            if (t.name.empty()) { err = "empty tensor name"; return false; }
            const uint32_t nd = U32();
            if (nd == 0 || nd > 4) { err = "bad n_dims for " + t.name; return false; }
            t.dims.resize(nd);
            for (auto& d : t.dims) d = U64();
            t.gguf_type = U32();
            t.rel_offset = U64();

            t.ggml_type = static_cast<ggml_type>(t.gguf_type);
            const ggml_type_traits* tr = ggml_get_type_traits(t.ggml_type);
            if (!tr || tr->blck_size == 0) {
                // Preserve the record (so the histogram shows the type) but the
                // caller cannot dequantise it.
                //
                // This used to `break`, which truncated the directory walk and
                // dropped every remaining tensor: a model whose third tensor is
                // an unknown type ended up with 2 tensors and failed Bind() with
                // "missing token_embd.weight". Continuing is correct because each
                // directory entry carries its own rel_offset, so advancing the
                // walk does not depend on knowing this tensor's byte size.
                t.bytes = 0;
                ordered.push_back(t);
                continue;
            }
            // Byte sizes are DERIVED FROM THE FILE, not from the block table.
            //
            // Estimating bytes as ceil(dims[0]/blck)*prod(dims[1..])*type_size
            // is wrong for packed expert tensors: blk.52.ffn_down_exps.weight
            // estimates 21.7 GB against a 23.7 GB file (32x too large), and the
            // ingest then refuses the model outright. The directory already gives
            // every tensor its own rel_offset, so the gap to the NEXT tensor
            // offset is the exact byte span - measured, with no block-size guess.
            t.bytes = 0;   // provisional; fixed from offset deltas below
            ordered.push_back(t);
        }

        // ---- Byte spans from on-disk offset deltas ----
        // Sort by rel_offset, then each tensor's span is the gap to the next.
        // The final tensor runs to the end of the data section, so it is bounded
        // by the file size rather than a nonexistent successor. This is what makes
        // the inventory exact without any per-type table.
        const size_t data_start = (pos + (geom - 1)) & ~static_cast<size_t>(geom - 1);
        std::vector<size_t> order(ordered.size());
        for (size_t k = 0; k < ordered.size(); ++k) order[k] = k;
        std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
            return ordered[a].rel_offset < ordered[b].rel_offset;
        });
        const uint64_t payloadEstimate = (size > data_start) ? (size - data_start) : 0;
        for (size_t k = 0; k < order.size(); ++k) {
            TensorRec& t = ordered[order[k]];
            if (k + 1 < order.size()) {
                const uint64_t next = ordered[order[k + 1]].rel_offset;
                t.bytes = (next > t.rel_offset) ? (size_t)(next - t.rel_offset) : 0;
            } else {
                t.bytes = (payloadEstimate > t.rel_offset)
                    ? (size_t)(payloadEstimate - t.rel_offset) : 0;
            }
            if (t.rel_offset + t.bytes > max_end) max_end = t.rel_offset + t.bytes;
        }
        out = ordered;
        if (data_start + max_end > size) {
            // Name the offending tensor rather than only refusing: a wrong
            // blck_size for a type inflates the byte estimate, and the only way
            // to identify the type is to report the worst offender.
            std::string worstName;
            uint64_t worstEnd = 0;
            for (const auto& t : out) {
                const uint64_t e = t.rel_offset + (uint64_t)t.bytes;
                if (e > worstEnd) {
                    worstEnd = e;
                    worstName = t.name + " type=" + std::to_string(t.gguf_type) +
                                " bytes=" + std::to_string(t.bytes) +
                                " rel=" + std::to_string(t.rel_offset);
                }
            }
            err = "payload exceeds file size: data_start=" + std::to_string(data_start) +
                  " max_end=" + std::to_string(max_end) + " file=" + std::to_string(size) +
                  " worst=" + worstName;
            return false;
        }
        for (auto& t : out) {
            if (t.data == nullptr && t.bytes > 0)
                t.data = base + data_start + t.rel_offset;
        }
        return true;
    }
};

// ---------------------------------------------------------------------------
// Name -> role classification. Pure function of the GGUF tensor name.
// ---------------------------------------------------------------------------
Role ClassifyRole(const std::string& n, int32_t& block) {
    block = -1;
    // Per-block prefix: "blk.<idx>."
    if (n.size() > 4 && n.compare(0, 4, "blk.") == 0) {
        const size_t dot = n.find('.', 4);
        if (dot != std::string::npos) {
            try {
                block = static_cast<int32_t>(std::stoul(n.substr(4, dot - 4)));
            } catch (...) {
                block = -1;
            }
        }
    }
    if (n == "token_embd.weight") return Role::TokenEmbedding;
    if (n == "output.weight") return Role::OutputWeight;
    if (n == "output_norm.weight") return Role::OutputNorm;

    if (n.find(".attn_qkv.weight") != std::string::npos) return Role::AttnQKV;
    if (n.find(".attn_kv_a_norm.weight") != std::string::npos) return Role::AttnKNorm;
    if (n.find(".attn_kv_a_mqa.weight") != std::string::npos) return Role::AttnKvAMqa;
    if (n.find(".attn_kv_b.weight") != std::string::npos) return Role::AttnKvB;
    if (n.find(".attn_k_norm.weight") != std::string::npos) return Role::AttnKNorm;
    if (n.find(".attn_q_norm.weight") != std::string::npos) return Role::AttnKNorm;
    if (n.find(".attn_norm.weight") != std::string::npos ||
        n.find(".attn_norm.bias") != std::string::npos) return Role::AttnNorm;
    if (n.find(".attn_q.bias") != std::string::npos) return Role::AttnQ;
    if (n.find(".attn_k.bias") != std::string::npos) return Role::AttnK;
    if (n.find(".attn_v.bias") != std::string::npos) return Role::AttnV;
    if (n.find(".attn_q.weight") != std::string::npos) return Role::AttnQ;
    if (n.find(".attn_k.weight") != std::string::npos) return Role::AttnK;
    if (n.find(".attn_v.weight") != std::string::npos) return Role::AttnV;
    if (n.find(".attn_output.weight") != std::string::npos) return Role::AttnOutput;
    if (n.find(".ffn_norm.weight") != std::string::npos ||
        n.find(".post_attention_norm.weight") != std::string::npos) return Role::FfnNorm;
    if (n.find(".ffn_gate_inp.weight") != std::string::npos ||
        n.find(".exp_probs_b.bias") != std::string::npos) return Role::RouterGate;
    if (n.find(".ffn_gate_exps.weight") != std::string::npos) return Role::ExpFfnGate;
    if (n.find(".ffn_up_exps.weight") != std::string::npos) return Role::ExpFfnUp;
    if (n.find(".ffn_down_exps.weight") != std::string::npos) return Role::ExpFfnDown;
    if (n.find(".ffn_gate.weight") != std::string::npos) return Role::FfnGate;
    if (n.find(".ffn_up.weight") != std::string::npos) return Role::FfnUp;
    if (n.find(".ffn_down.weight") != std::string::npos) return Role::FfnDown;
    if (n.find(".ssm_a") != std::string::npos) return Role::SsmA;
    if (n.find(".ssm_conv1d.weight") != std::string::npos) return Role::SsmConv1dW;
    if (n.find(".ssm_conv1d.bias") != std::string::npos) return Role::SsmConv1dB;
    if (n.find(".ssm_dt.bias") != std::string::npos) return Role::SsmDtB;
    if (n.find(".ssm_d") != std::string::npos) return Role::SsmD;
    if (n.find(".ssm_in.weight") != std::string::npos) return Role::SsmIn;
    if (n.find(".ssm_out.weight") != std::string::npos) return Role::SsmOut;
    if (n.find(".ssm_norm.weight") != std::string::npos) return Role::SsmNorm;
    if (n.find("rope_freqs.weight") != std::string::npos) return Role::RopeFreqs;
    if (n.find("rope_factors") != std::string::npos) return Role::RopeFactors;
    return Role::Other;
}


// Capture the tokenizer and the model's own identity from the metadata.
// ParseHeader deliberately skips array values (they can be 100k+ elements), so
// this walks the metadata a second time and reads only what it needs.
bool ReadTokenizerAndIdentity(const std::string& path, ModelSpec& spec) {
    g_tokenizer = Tokenizer{};
    Reader r;
    if (!r.Open(path)) return false;
    if (r.U32() != 0x46554747u) { r.Close(); return false; }
    (void)r.U32();
    (void)r.U64();                       // tensor count
    const uint64_t kv_count = r.U64();

    for (uint64_t i = 0; i < kv_count; ++i) {
        if (!r.Need(8)) break;
        const std::string key = r.Str();
        const uint32_t t = r.U32();
        if (key == "tokenizer.ggml.tokens" && t == 9) {
            const uint32_t et = r.U32();
            const uint64_t n = r.U64();
            g_tokenizer.tokens.reserve((size_t)std::min<uint64_t>(n, 1u << 20));
            for (uint64_t k = 0; k < n; ++k) {
                if (et == 8) g_tokenizer.tokens.push_back(r.Str());
                else if (!r.SkipValue(et, 0)) break;
            }
        } else if (key == "tokenizer.ggml.token_type" && t == 9) {
            const uint32_t et = r.U32();
            const uint64_t n = r.U64();
            g_tokenizer.types.reserve((size_t)std::min<uint64_t>(n, 1u << 20));
            for (uint64_t k = 0; k < n; ++k) {
                if (et == 5) { int32_t v; std::memcpy(&v, r.base + r.pos, 4); r.pos += 4; g_tokenizer.types.push_back(v); }
                else if (!r.SkipValue(et, 0)) break;
            }
        } else if (key == "tokenizer.ggml.merges" && t == 9) {
            const uint32_t et = r.U32();
            const uint64_t n = r.U64();
            g_tokenizer.merges.reserve((size_t)std::min<uint64_t>(n, 1u << 21));
            for (uint64_t k = 0; k < n; ++k) {
                if (et == 8) g_tokenizer.merges.push_back(r.Str());
                else if (!r.SkipValue(et, 0)) break;
            }
        } else if (key == "tokenizer.ggml.bos_token_id" && t == 4) {
            uint32_t v; std::memcpy(&v, r.base + r.pos, 4); r.pos += 4;
            g_tokenizer.bos_id = (int32_t)v;
        } else if (key == "tokenizer.ggml.eos_token_id" && t == 4) {
            uint32_t v; std::memcpy(&v, r.base + r.pos, 4); r.pos += 4;
            g_tokenizer.eos_id = (int32_t)v;
        } else if (key == "tokenizer.chat_template" && t == 8) {
            g_tokenizer.chat_template = r.Str();
        } else {
            // Skip anything else, including arrays.
            if (!r.SkipValue(t, 0)) break;
        }
    }
    r.Close();

    g_tokenizer.ok = !g_tokenizer.tokens.empty();
    (void)spec;
    return g_tokenizer.ok;
}
std::string Get(const std::map<std::string, std::string>& m, const std::string& k,
                const std::string& dflt = "") {
    auto it = m.find(k);
    return it == m.end() ? dflt : it->second;
}
uint64_t GetU(const std::map<std::string, std::string>& m, const std::string& k, uint64_t dflt = 0) {
    auto it = m.find(k);
    if (it == m.end()) return dflt;
    try { return std::stoull(it->second); } catch (...) { return dflt; }
}
double GetD(const std::map<std::string, std::string>& m, const std::string& k, double dflt = 1e-5) {
    auto it = m.find(k);
    if (it == m.end()) return dflt;
    try { return std::stod(it->second); } catch (...) { return dflt; }
}

// Which arch string maps to which family + graph.
void DetectArch(ModelSpec& s, const std::vector<TensorRec>& tensors) {
    const std::string& a = s.architecture;
    auto hasAny = [&](const char* sub) {
        for (const auto& t : tensors)
            if (t.name.find(sub) != std::string::npos) return true;
        return false;
    };

    s.has_bias = hasAny(".attn_q.bias");

    if (a == "clip") { s.kind = ArchKind::Encoder; return; }

    if (a == "deepseek2" || a == "deepseek4" || a == "deepseek3" || a == "deepseek") {
        s.kind = ArchKind::DeepSeekMLA;
        return;
    }
    if (a == "phi3") { s.kind = ArchKind::Phi3Fused; return; }
    if (a == "nemotron_h" || a == "nemotron_h_moe") { s.kind = ArchKind::SsmHybrid; return; }
    if (a == "qwen3next") { s.kind = ArchKind::Qwen3Next; return; }

    // SSM-driven hybrids may expose the same decoder graph plus ssm_* tensors.
    if (hasAny(".ssm_in.weight")) {
        s.kind = (s.expert_count > 0) ? ArchKind::SsmHybrid : ArchKind::SsmHybrid;
        s.notes.push_back("ssm tensors present; Deep2 has no SSM scan primitive yet");
        return;
    }
    if (s.expert_count > 0) { s.kind = ArchKind::MoeOnly; return; }
    s.kind = ArchKind::LlamaLike;
}

void FillSpec(ModelSpec& s, const std::map<std::string, std::string>& m) {
    s.model_name = Get(m, "general.name");
    s.architecture = Get(m, "general.architecture");
    const std::string p = s.architecture + ".";

    auto pick = [&](const char* key, uint64_t& dst) {
        dst = GetU(m, p + key, GetU(m, key, 0));
    };
    pick("block_count", s.block_count);
    pick("embedding_length", s.embd);
    pick("feed_forward_length", s.ffn);
    pick("attention.head_count", s.heads);
    pick("attention.head_count_kv", s.heads_kv);
    pick("rope.dimension_count", s.rope_dim);
    pick("rope.freq_base", s.rope_freq_base);
    pick("vocab_size", s.vocab);
    pick("context_length", s.context_length);
    pick("expert_count", s.expert_count);
    pick("expert_used_count", s.expert_used);
    pick("expert_shared_count", s.expert_shared);
    pick("expert_feed_forward_length", s.expert_ffn);
    pick("attention.kv_lora_rank", s.kv_lora_rank);
    pick("attention.key_length", s.key_length);
    pick("attention.value_length", s.value_length);
    pick("leading_dense_block_count", s.leading_dense);
    // Mamba2 SSM geometry. Read from the model's own metadata and never
    // defaulted: a wrong state size silently corrupts every scan step.
    pick("ssm.state_size", s.ssm_state_size);
    pick("ssm.inner_size", s.ssm_inner_size);
    pick("ssm.time_step_rank", s.ssm_dt_rank);
    pick("ssm.group_count", s.ssm_group_count);
    pick("ssm.conv_kernel", s.ssm_conv_kernel);
    if (s.ssm_state_size == 0 && (s.kind == ArchKind::SsmHybrid || s.kind == ArchKind::Qwen3Next)) {
        // Deliberately NOT guessed. An absent state size means the scan cannot
        // be shaped and must fail loudly rather than run with a wrong size.
        s.notes.push_back("WARNING: ssm.state_size missing; selective scan cannot be shaped");
    }
    s.rms_eps = GetD(m, p + "attention.layer_norm_rms_epsilon", 1e-5);
    if (s.heads_kv == 0) s.heads_kv = s.heads;   // MHA default
}

// Build the runtime op graph for the families Deep2 can execute.
OpGraph BuildGraph(const ModelSpec& s, const std::vector<TensorRec>& tensors) {
    OpGraph g;
    if (s.kind == ArchKind::Unknown || s.kind == ArchKind::Encoder) {
        GraphOp u;
        u.op = Op::Unsupported;
        u.detail = "no decoder graph for this architecture";
        g.ops.push_back(u);
        g.unsupported = 1;
        return g;
    }

    // op 0: embedding lookup (token id -> hidden vector)
    {
        GraphOp o;
        o.op = Op::EmbeddingLookup;
        o.a = "<token_id>";
        o.out = "token_embd.weight";
        g.ops.push_back(o);
    }
    // The output norm and final projection are appended AFTER the per-block
    // ops below, so they consume the fully-layered hidden state. Emitting them
    // here (before any block) would norm and project the raw embedding.

    // Per-block classification: map role -> tensor name, so the graph uses only
    // what the model actually has.
    std::map<int32_t, std::map<Role, std::string>> per;
    for (const auto& t : tensors) {
        if (t.block >= 0) per[t.block][t.role] = t.name;
    }

    for (uint64_t b = 0; b < s.block_count; ++b) {
        const auto it = per.find(static_cast<int32_t>(b));
        if (it == per.end()) continue;
        const auto& roles = it->second;
        auto name = [&](Role r) -> std::string {
            auto f = roles.find(r);
            return f == roles.end() ? std::string() : f->second;
        };

        // attn norm
        {
            GraphOp o;
            o.op = Op::RmsNorm;
            o.block = static_cast<int32_t>(b);
            o.a = "<hidden>";
            o.b = name(Role::AttnNorm);
            o.out = "attn_norm";
            g.ops.push_back(o);
        }

        // Publish the BLOCK INPUT as resid_in, BEFORE any attention op runs.
        // Publish copies the *current* hidden vector, so emitting it after the
        // attention projection (the earlier order) published attn_proj instead:
        // ResidualAdd then computed attn_proj + attn_proj and dropped the block
        // input entirely. That annihilated input information every block, which
        // is why logits came out bit-identical across positions while the
        // embedding L2 still varied. The gate/up pair consumes this stream.
        {
            GraphOp o;
            o.op = Op::Publish;
            o.block = static_cast<int32_t>(b);
            o.a = "<hidden>";
            o.out = "resid_in";
            g.ops.push_back(o);
        }

        // ---- Mamba2 selective scan (nemotron_h, qwen3-next) ----
        // The SSM is the ONLY missing primitive for these families. It is not
        // an optimisation of an attention kernel: SSMs have no attention-style
        // parallel form to fall back to, so the block either has a real scan or
        // the model cannot run. The scan consumes the model's own SSM tensors,
        // so no data is invented here.
        if (s.kind == ArchKind::SsmHybrid || s.kind == ArchKind::Qwen3Next) {
            GraphOp o;
            o.op = Op::SsmScan;
            o.block = (int32_t)b;
            o.a = "attn_norm";              // input to the scan
            o.b = name(Role::SsmIn);         // in projection
            o.c = name(Role::SsmConv1dW);    // causal depthwise conv weights
            o.out = "ssm_out";
            // Companion SSM tensors, resolved by role at bind time.
            o.detail = "A=" + name(Role::SsmA) +
                       ";D=" + name(Role::SsmD) +
                       ";dtB=" + name(Role::SsmDtB) +
                       ";convB=" + name(Role::SsmConv1dB) +
                       ";norm=" + name(Role::SsmNorm) +
                       ";proj=" + name(Role::SsmOut);
            g.ops.push_back(o);

            GraphOp p;
            p.op = Op::Linear;
            p.block = (int32_t)b;
            p.a = "ssm_out";
            p.b = name(Role::SsmOut);
            p.out = "ssm_proj";
            g.ops.push_back(p);
        }

        if (s.kind == ArchKind::DeepSeekMLA) {
            // q projection
            {
                GraphOp o;
                o.op = Op::Linear; o.block = (int32_t)b;
                o.a = "attn_norm"; o.b = name(Role::AttnQ); o.out = "q";
                g.ops.push_back(o);
            }
            // kv_a_mqa -> (norm) -> kv_b -> MlaDecompress
            {
                GraphOp o;
                o.op = Op::MlaDecompress; o.block = (int32_t)b;
                o.a = name(Role::AttnKvAMqa);
                o.b = name(Role::AttnKNorm);
                o.c = name(Role::AttnKvB);
                o.out = "kv";
                g.ops.push_back(o);
            }
            {
                GraphOp o;
                o.op = Op::Attention; o.block = (int32_t)b;
                o.a = "q"; o.b = "kv"; o.out = "attn_out";
                g.ops.push_back(o);
            }
            {
                GraphOp o;
                o.op = Op::Linear; o.block = (int32_t)b;
                o.a = "attn_out"; o.b = name(Role::AttnOutput); o.out = "attn_proj";
                g.ops.push_back(o);
            }
        } else if (s.kind == ArchKind::Phi3Fused) {
            GraphOp o;
            o.op = Op::Linear; o.block = (int32_t)b;
            o.a = "attn_norm"; o.b = name(Role::AttnQKV); o.out = "qkv";
            g.ops.push_back(o);
            // The fused tensor is split into q/k/v inside the attention core.
            o = GraphOp{};
            o.op = Op::Attention; o.block = (int32_t)b;
            o.a = "qkv"; o.b = "qkv(split)"; o.out = "attn_out";
            o.detail = "fused qkv -> attention core (split internally)";
            g.ops.push_back(o);
        } else {
            for (Role r : {Role::AttnQ, Role::AttnK, Role::AttnV}) {
                GraphOp o;
                o.op = Op::Linear; o.block = (int32_t)b;
                o.a = "attn_norm"; o.b = name(r);
                o.out = (r == Role::AttnQ) ? "q" : (r == Role::AttnK) ? "k" : "v";
                g.ops.push_back(o);
            }
            {
                GraphOp o;
                o.op = Op::Attention; o.block = (int32_t)b;
                o.a = "q"; o.b = "k,v"; o.out = "attn_out";
                g.ops.push_back(o);
            }
            {
                GraphOp o;
                o.op = Op::Linear; o.block = (int32_t)b;
                o.a = "attn_out"; o.b = name(Role::AttnOutput); o.out = "attn_proj";
                g.ops.push_back(o);
            }
        }

        // Residual add. resid_in was published above, before the attention
        // ops, so it holds the block input.
        {
            GraphOp o = GraphOp{};
            o.op = Op::ResidualAdd; o.block = (int32_t)b;
            o.a = "resid_in"; o.b = "attn_proj"; o.out = "resid1";
            g.ops.push_back(o);
        }
        // ffn norm
        {
            GraphOp o;
            o.op = Op::RmsNorm; o.block = (int32_t)b;
            o.a = "resid1"; o.b = name(Role::FfnNorm); o.out = "ffn_norm";
            g.ops.push_back(o);
        }

        // DeepSeek-family models keep `leading_dense_block_count` blocks fully
        // dense before MoE begins, so a block with no router must get the dense
        // FFN path, not a Router/TopK/MoE triple that cannot bind.
        const bool hasRouter = !name(Role::RouterGate).empty();
        if (hasRouter && s.expert_count > 0) {
            GraphOp o;
            o.op = Op::Router; o.block = (int32_t)b;
            o.a = "ffn_norm"; o.b = name(Role::RouterGate); o.out = "router_logits";
            g.ops.push_back(o);
            o = GraphOp{};
            o.op = Op::TopK; o.block = (int32_t)b;
            o.a = "router_logits"; o.out = "expert_choice";
            g.ops.push_back(o);
            o = GraphOp{};
            o.op = Op::MoEExecute; o.block = (int32_t)b;
            o.a = "ffn_norm"; o.b = "expert_choice";
            o.c = name(Role::ExpFfnGate);
            o.out = "moe_out";
            o.detail = "experts: " + name(Role::ExpFfnUp) + "," + name(Role::ExpFfnDown); // gate slot is in .c
            g.ops.push_back(o);
        } else {
            const bool hasShared = s.kind == ArchKind::DeepSeekMLA;
            // Dense FFN: gate/up projections, then SwiGLU, then down.
            for (Role r : {Role::FfnGate, Role::FfnUp}) {
                GraphOp o;
                o.op = Op::Linear; o.block = (int32_t)b;
                o.a = "ffn_norm"; o.b = name(r);
                o.out = (r == Role::FfnGate) ? "gate" : "up";
                g.ops.push_back(o);
            }
            {
                GraphOp o;
                o.op = Op::SwiGLU; o.block = (int32_t)b;
                o.a = "gate"; o.b = "up"; o.out = "swiglu";
                g.ops.push_back(o);
            }
            {
                GraphOp o;
                o.op = Op::Linear; o.block = (int32_t)b;
                o.a = "swiglu"; o.b = name(Role::FfnDown); o.out = "ffn_out";
                g.ops.push_back(o);
            }
            (void)hasShared;
        }

        // residual add
        {
            GraphOp o;
            o.op = Op::ResidualAdd; o.block = (int32_t)b;
            o.a = "resid1";
            o.b = (hasRouter && s.expert_count > 0) ? "moe_out" : "ffn_out";
            o.out = "resid2";
            g.ops.push_back(o);
        }
    }

    // Final norm and output projection. These MUST come after every block:
    // the norm is applied to the layered hidden state and the projection
    // produces the vocabulary logits that choose the next token.
    {
        GraphOp o;
        o.op = Op::RmsNorm;
        o.block = -1;
        o.a = "<hidden>";
        o.b = "output_norm.weight";
        o.out = "out_norm";
        g.ops.push_back(o);
        o = GraphOp{};
        o.op = Op::LmHead;
        o.a = "out_norm";
        o.b = "output.weight";
        o.out = "logits";
        g.ops.push_back(o);
    }

    // Anything the family needs but has no primitive is recorded, not hidden.
    if (false) {
        GraphOp u;
        u.op = Op::Unsupported;
        u.detail = "SSM/linear-attention scan primitive not implemented in Deep2";
        g.ops.push_back(u);
        g.unsupported++;
    }
    return g;
}

IngestReport g_last;   // last report (single-threaded tool usage)
std::mutex g_mu;

}  // namespace

const char* ArchKindName(ArchKind k) {
    switch (k) {
        case ArchKind::LlamaLike: return "llama-like";
        case ArchKind::Phi3Fused: return "phi3-fused-qkv";
        case ArchKind::DeepSeekMLA: return "deepseek-MLA-MoE";
        case ArchKind::SsmHybrid: return "ssm-hybrid";
        case ArchKind::Qwen3Next: return "qwen3next-hybrid";
        case ArchKind::MoeOnly: return "moe-dense-attn";
        case ArchKind::Encoder: return "encoder";
        default: return "unknown";
    }
}

const IngestReport& Ingest(const std::string& path, bool want_weights) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_last = IngestReport{};

    // The returned report holds raw pointers INTO the memory mapping, so the
    // mapping must outlive the report. Keep the reader in a retained holder and
    // only release it when a different model is ingested. Closing it here (as
    // an earlier version did) left every TensorRec::data pointing at unmapped
    // memory, which crashes the first kernel that tries to read a weight.
    static Reader* g_reader = nullptr;
    if (g_reader) { g_reader->Close(); delete g_reader; g_reader = nullptr; }
    g_reader = new Reader();
    Reader& r = *g_reader;
    if (!r.Open(path)) { delete g_reader; g_reader = nullptr; g_last.error = "cannot open"; return g_last; }

    std::map<std::string, std::string> meta;
    uint64_t tensor_count = 0, kv_count = 0;
    if (!r.ParseHeader(meta, tensor_count, kv_count)) {
        g_last.error = "GGUF header/metadata parse failed";
                return g_last;
    }
    if (!r.ParseTensors(static_cast<size_t>(tensor_count), g_last.tensors, g_last.error)) {
        return g_last;
    }

    FillSpec(g_last.spec, meta);

    // Provenance: the file's SHA-256, size, tensor count and type histogram.
    g_prov = Provenance{};
    g_prov.path = path;
    g_prov.sha256 = Sha256FileImpl(path);
    g_prov.file_bytes = static_cast<uint64_t>(r.size);
    g_prov.tensor_count = g_last.tensors.size();
    g_prov.architecture = g_last.spec.architecture;
    g_prov.model_name = g_last.spec.model_name;
    for (const auto& t : g_last.tensors) g_prov.type_histogram[t.gguf_type]++;

    // Tokenizer + the model's own identity, read from metadata.
    ReadTokenizerAndIdentity(path, g_last.spec);

    // Some models (phi3, gemma3, ...) do not declare <arch>.vocab_size. The
    // authoritative value is the embedding table's second dimension, so derive
    // it from the tensor directory rather than reporting 0.
    if (g_last.spec.vocab == 0) {
        for (const auto& t : g_last.tensors) {
            if (t.name == "token_embd.weight" && t.dims.size() >= 2) {
                g_last.spec.vocab = t.dims[1];
                g_last.spec.notes.push_back("vocab_size derived from token_embd.weight dims[1]");
                break;
            }
        }
    }
    // Likewise, some models omit embedding_length only when a fused tensor
    // implies it; keep the declared value but fall back to the embedding row.
    if (g_last.spec.embd == 0) {
        for (const auto& t : g_last.tensors) {
            if (t.name == "token_embd.weight" && !t.dims.empty()) {
                g_last.spec.embd = t.dims[0];
                break;
            }
        }
    }

    DetectArch(g_last.spec, g_last.tensors);

    for (auto& t : g_last.tensors) {
        t.role = ClassifyRole(t.name, t.block);
        const ggml_type_traits* tr = ggml_get_type_traits(t.ggml_type);
        // F32/F16/BF16 have no to_float in ggml because they need no
        // dequantisation - they are raw-loadable. Everything else must be
        // dequantised, so a missing to_float is a genuine gap.
        const bool raw_loadable =
            (t.ggml_type == GGML_TYPE_F32 || t.ggml_type == GGML_TYPE_F16 ||
             t.ggml_type == GGML_TYPE_BF16);
        t.has_dequant = (tr && (tr->to_float || raw_loadable));
        t.gpu_quant_capable = (t.ggml_type == GGML_TYPE_Q4_K || t.ggml_type == GGML_TYPE_Q6_K);
        g_last.type_histogram[t.gguf_type]++;
        if (t.has_dequant) g_last.dequant_capable++;
        else g_last.no_dequant++;
        if (t.gpu_quant_capable) g_last.gpu_quant_capable++;
        if (!t.has_dequant && tr)
            g_last.unsupported_types.push_back(std::string(tr->type_name));
    }
    std::sort(g_last.unsupported_types.begin(), g_last.unsupported_types.end());
    g_last.unsupported_types.erase(
        std::unique(g_last.unsupported_types.begin(), g_last.unsupported_types.end()),
        g_last.unsupported_types.end());

    g_last.total = g_last.tensors.size();
    g_last.resolved = g_last.total;   // every tensor is resolved by name+data
    g_last.graph = BuildGraph(g_last.spec, g_last.tensors);
    g_last.ok = true;

    if (want_weights) {
        for (auto& t : g_last.tensors) {
            if (!t.data) continue;
            // Keep only a bounded prefix of each tensor. Retaining a fully
            // dequantised copy of a 9 GB model would be ~38 GB of f32 and
            // exhaust memory; a prefix is enough to prove the dequant path
            // and gives callers something numerically checkable.
            const size_t kCap = 1u << 20;   // 1M floats per tensor
            std::vector<float> v;
            if (t.ggml_type == GGML_TYPE_F32) {
                // F32 needs no dequantisation; element count is bytes/4.
                const size_t n = std::min(t.bytes / sizeof(float), kCap);
                if (n == 0) continue;
                v.assign(n, 0.0f);
                std::memcpy(v.data(), t.data, v.size() * sizeof(float));
            } else if (t.ggml_type == GGML_TYPE_F16 || t.ggml_type == GGML_TYPE_BF16) {
                const size_t n = std::min(t.bytes / 2, kCap);
                if (n == 0) continue;
                v.assign(n, 0.0f);
                for (size_t i = 0; i < n; ++i) {
                    uint16_t h;
                    std::memcpy(&h, t.data + i * 2, 2);
                    if (t.ggml_type == GGML_TYPE_F16) {
                        const ggml_fp16_t p = static_cast<ggml_fp16_t>(h);
                        v[i] = ggml_fp16_to_fp32(p);
                    } else {
                        const uint32_t bits = static_cast<uint32_t>(h) << 16;
                        float f; std::memcpy(&f, &bits, 4);
                        v[i] = f;
                    }
                }
            } else {
                const ggml_type_traits* tr = ggml_get_type_traits(t.ggml_type);
                if (!tr || !tr->to_float) continue;
                const size_t n = t.bytes / static_cast<size_t>(tr->type_size) *
                                 static_cast<size_t>(tr->blck_size);
                if (n == 0) continue;
                const size_t keep = std::min(n, kCap);
                v.assign(keep, 0.0f);
                // ggml's to_float takes an int count, so dequantise in bounded
                // chunks. Casting a multi-hundred-million-element count to int
                // would overflow and corrupt the output buffer.
                const size_t chunk = 1u << 22;   // 4M floats per call
                for (size_t off = 0; off < keep; off += chunk) {
                    const int cnt = static_cast<int>(std::min(chunk, keep - off));
                    tr->to_float(t.data + off / static_cast<size_t>(tr->blck_size) *
                                             static_cast<size_t>(tr->type_size),
                                 v.data() + off, cnt);
                }
            }
            g_last.weights[t.name] = std::move(v);
        }
    }
        return g_last;
}

const IngestReport& IngestWeights(const std::string& path,
                                  const std::vector<std::string>& only_names) {
    const IngestReport& rep = Ingest(path, false);
    // g_last is the same object; fill just the requested tensors.
    for (const auto& name : only_names) {
        if (g_last.weights.count(name)) continue;
        for (const auto& t : g_last.tensors) {
            if (t.name != name) continue;
            const ggml_type_traits* tr = ggml_get_type_traits(t.ggml_type);
            if (!tr || !tr->to_float || !t.data) break;
            const size_t n = t.bytes / static_cast<size_t>(tr->type_size) *
                             static_cast<size_t>(tr->blck_size);
            if (n == 0) break;
            std::vector<float> v(n, 0.0f);
            tr->to_float(t.data, v.data(), static_cast<int>(n));
            g_last.weights[name] = std::move(v);
            break;
        }
    }
    return rep;
}


const Tokenizer& GetTokenizer() { return g_tokenizer; }

std::string Sha256File(const std::string& path) { return Sha256FileImpl(path); }

const Provenance& GetProvenance() { return g_prov; }

} } }  // namespace
