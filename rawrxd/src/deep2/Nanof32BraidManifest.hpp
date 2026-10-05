// ============================================================================
// Nanof32BraidManifest.hpp
// RAWRXD_NQB_SOURCE_F32_PARITY_001
//
// ONE manifest schema, shared by three independent authorities.
//
//   SOURCE SIDE   tools/nqb_source_f32_manifest.cpp   opens the GGUF ONLY
//   PAYLOAD SIDE  tools/nqb_production_reopen.cpp     opens the .nqb ONLY
//   COMPARATOR    tools/nqb_manifest_compare.cpp      opens NEITHER
//
// WHY A SHARED SCHEMA FILE EXISTS
// ------------------------------
// The previous manifest was already wrong once. The writer emitted
//     reverseIndex <TAB> name <TAB> hash ...
// and the reader parsed
//     name <TAB> hash
// so column 0 became the name and a tensor name was handed to strtoull, which
// silently returned 0. Every digest was compared against zero and the clean
// baseline reported mismatches=3 of 3.
//
// That bug class is structural, not incidental: two hand-maintained copies of a
// schema will drift. So the schema lives here once, both sides serialise through
// the same serialiser, and both sides parse through the same parser. A schema
// change is one edit and cannot desynchronise.
//
// HASH DOMAIN (explicit, because it is the whole claim)
// ----------------------------------------------------
//     GGUF tensor
//       -> production dequant
//       -> logical tensor element order
//       -> IEEE754 binary32
//       -> little-endian bytes of that value sequence
//       -> FNV-1a 64 and SHA-256, both incremental
//
// The float bytes are re-encoded through uint32_t and emitted byte by byte rather
// than by hashing a float* directly. On x64 those are the same bytes today; making
// the encoding explicit means the claim does not depend on that remaining true.
//
// WHAT THIS SCHEMA DOES NOT CLAIM
// -------------------------------
// That the production Q2_K decoder is numerically canonical. Both sides use it,
// so a manifest match proves the .nqb holds exactly what the production GGUF
// decode path produced -- and nothing about whether that decode is correct
// against an independent oracle. Those are two separate gates and conflating them
// is how a self-certifying loop gets built.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <string>
#include <vector>

namespace Deep2 {

// ----------------------------------------------------------------------------
// SHA-256
//
// Moved here from the reopen probe so all three tools hash identically. If two
// authorities used two implementations and one had a bug, a MANIFEST_ROOT_MATCH
// would be meaningless.
// ----------------------------------------------------------------------------
struct Sha256 {
    uint32_t h[8];
    uint64_t total;
    uint8_t  buf[64];
    size_t   bl;

    Sha256() {
        h[0]=0x6a09e667u; h[1]=0xbb67ae85u; h[2]=0x3c6ef372u; h[3]=0xa54ff53au;
        h[4]=0x510e527fu; h[5]=0x9b05688cu; h[6]=0x1f83d9abu; h[7]=0x5be0cd19u;
        total = 0; bl = 0;
    }
    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void block(const uint8_t* p) {
        static const uint32_t K[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
            0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
            0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
            0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
            0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
            0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
            0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
            0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
            0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u };
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(p[i*4])<<24)|(uint32_t(p[i*4+1])<<16)|
                   (uint32_t(p[i*4+2])<<8)|uint32_t(p[i*4+3]);
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
            const uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19)  ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            const uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            const uint32_t ch = (e & f) ^ ((~e) & g);
            const uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            const uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    void update(const void* d, size_t n) {
        const uint8_t* p = static_cast<const uint8_t*>(d);
        total += n;
        if (bl) {
            const size_t take = (std::min)(n, size_t(64) - bl);
            std::memcpy(buf + bl, p, take);
            bl += take; p += take; n -= take;
            if (bl == 64) { block(buf); bl = 0; }
        }
        while (n >= 64) { block(p); p += 64; n -= 64; }
        if (n) { std::memcpy(buf, p, n); bl = n; }
    }

    // Finalises a COPY so the caller can keep appending. Standard SHA-256
    // padding, computed on total BEFORE any padding byte is added.
    std::string hex() const {
        Sha256 c = *this;
        const uint64_t bits = c.total * 8;
        uint8_t pad = 0x80;
        c.update(&pad, 1);
        pad = 0;
        while (c.bl != 56) c.update(&pad, 1);
        uint8_t lenb[8];
        for (int i = 0; i < 8; ++i) lenb[i] = uint8_t(bits >> (56 - 8*i));
        c.update(lenb, 8);
        static const char* hexd = "0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (int i = 0; i < 8; ++i)
            for (int b = 3; b >= 0; --b) {
                const uint8_t v = uint8_t(c.h[i] >> (8*b));
                out.push_back(hexd[v >> 4]);
                out.push_back(hexd[v & 15]);
            }
        return out;
    }
};

// ----------------------------------------------------------------------------
// FNV-1a 64. Kept because the existing tooling and manifests already speak it.
// ----------------------------------------------------------------------------
constexpr uint64_t NQB_FNV_BASIS = 1469598103934665603ULL;
constexpr uint64_t NQB_FNV_PRIME = 1099511628211ULL;

inline uint64_t nqbFnv1a64(uint64_t h, const void* p, size_t n) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= NQB_FNV_PRIME; }
    return h;
}
inline uint64_t nqbFnvBegin() { return NQB_FNV_BASIS; }

// ----------------------------------------------------------------------------
// Canonical element encoding
//
// Hashes the byte sequence of IEEE754 binary32 values in logical tensor element
// order, little-endian. Exposed so both sides call ONE function: an authority
// that hashed a float* directly would depend on the host's float layout, and a
// mismatch between the two would then be a platform bug rather than a fidelity
// failure.
//
// RAWRXD_NQB_SOURCE_F32_PARITY_001 -- defect found by the gate this feeds.
//
// The first version opened with `fnvOut = nqbFnvBegin();`, which silently makes
// the helper single-call-only. The source side calls it once per tensor and was
// correct. The payload side calls it once per 8 MiB chunk, so every tensor larger
// than one chunk had its FNV-1a RESET at each chunk and only the final chunk
// survived. Measured consequence:
//
//     SHA256_MATCH=255/255   PASS
//     FNV1A64_MATCH=58/255   FAIL
//     TOTAL_MISMATCHES=197
//
// 58 is the number of tensors that fit in one chunk. SHA-256 was unaffected
// because its state is a member object rather than a reset-on-entry value.
//
// Two hashes over one byte stream cannot disagree, so that split result was not a
// fidelity failure at all: it was the instrument reporting itself. The
// accumulator is now initialised by the CALLER and never reset here, which is the
// only correct streaming semantic.
inline void nqbHashCanonicalF32Chunk(const float* values, size_t elements,
                                     uint64_t& fnvInOut, Sha256& shaOut) {
    // Chunked so a 394M-element tensor needs no second 1.5 GB buffer.
    constexpr size_t CHUNK_ELEMS = 1u << 16;
    std::vector<uint8_t> le(CHUNK_ELEMS * 4);
    size_t done = 0;
    while (done < elements) {
        const size_t n = (std::min)(CHUNK_ELEMS, elements - done);
        for (size_t i = 0; i < n; ++i) {
            uint32_t u;
            std::memcpy(&u, values + done + i, 4);
            le[i*4+0] = uint8_t(u);
            le[i*4+1] = uint8_t(u >> 8);
            le[i*4+2] = uint8_t(u >> 16);
            le[i*4+3] = uint8_t(u >> 24);
        }
        fnvInOut = nqbFnv1a64(fnvInOut, le.data(), n * 4);
        shaOut.update(le.data(), n * 4);
        done += n;
    }
}

// ----------------------------------------------------------------------------
// Manifest V1
// ----------------------------------------------------------------------------
constexpr int NQB_F32_MANIFEST_FIELD_COUNT = 9;
constexpr const char* NQB_F32_MANIFEST_NAME = "NQB_F32_MANIFEST_V1";
constexpr const char* NQB_F32_MANIFEST_FIELDS =
    "name\tstored_codec\trank\tdim0\tdim1\telements\tf32_bytes\tfnv1a64\tsha256";

// One tensor's canonical F32 image. `name` is the join key: comparison is by
// EXACT tensor name, never by traversal index, so a differing order between the
// two producers cannot change the result.
struct NqbF32Record {
    std::string name;
    uint32_t    storedCodec = 0;
    uint32_t    rank        = 0;
    uint64_t    dim0        = 0;   // GGUF ne[0]  / footer rows
    uint64_t    dim1        = 0;   // GGUF ne[1]  / footer cols  (1 when rank==1)
    uint64_t    elements    = 0;
    uint64_t    f32Bytes    = 0;
    uint64_t    fnv1a64     = NQB_FNV_BASIS;
    std::string sha256;
};

inline std::string nqbManifestHeader() {
    return std::string(NQB_F32_MANIFEST_NAME) + "\nFIELDS=" +
           NQB_F32_MANIFEST_FIELDS + "\n#";
}

inline std::string nqbSerialiseRecord(const NqbF32Record& r) {
    char num[128];
    std::snprintf(num, sizeof num, "%u\t%u\t%llu\t%llu\t%llu\t%llu\t%llu\t",
                  r.storedCodec, r.rank,
                  (unsigned long long)r.dim0, (unsigned long long)r.dim1,
                  (unsigned long long)r.elements, (unsigned long long)r.f32Bytes,
                  (unsigned long long)r.fnv1a64);
    return r.name + "\t" + num + r.sha256 + "\n";
}

// MANIFEST_ROOT: SHA-256 over the schema version followed by every record's
// canonical serialisation, sorted by exact name. Sorting is what makes the root
// independent of traversal order, so a model can be re-serialised in any order
// and keep one logical identity. This is the identity replay needs, and it is
// separate from the container SHA-256 that identifies the whole file.
inline std::string nqbManifestRoot(const std::vector<NqbF32Record>& recs) {
    std::vector<const NqbF32Record*> sorted;
    sorted.reserve(recs.size());
    for (const NqbF32Record& r : recs) sorted.push_back(&r);
    std::sort(sorted.begin(), sorted.end(),
              [](const NqbF32Record* a, const NqbF32Record* b) { return a->name < b->name; });
    Sha256 s;
    const std::string hdr = NQB_F32_MANIFEST_NAME;
    s.update(hdr.data(), hdr.size());
    for (const NqbF32Record* r : sorted) {
        const std::string line = nqbSerialiseRecord(*r);
        s.update(line.data(), line.size());
    }
    return s.hex();
}

// ---- strict parsing -------------------------------------------------------
//
// STRICT is the requirement. The earlier defect was not a disagreement about
// values, it was a permissive parse that turned a tensor name into the number
// zero and then reported a confident hash mismatch. Every numeric field here
// must consume its ENTIRE field or the parse fails loudly.
enum class NqbParseStatus {
    Ok,
    MissingSchema,
    SchemaMismatch,
    FieldCountMismatch,
    NotANumber,        // a numeric field contained non-numeric text
    TrailingGarbage,   // a numeric field parsed a prefix and left characters
    EmptyName
};

inline const char* nqbParseStatusName(NqbParseStatus s) {
    switch (s) {
        case NqbParseStatus::Ok:                 return "OK";
        case NqbParseStatus::MissingSchema:       return "MISSING_SCHEMA";
        case NqbParseStatus::SchemaMismatch:      return "SCHEMA_MISMATCH";
        case NqbParseStatus::FieldCountMismatch:  return "FIELD_COUNT_MISMATCH";
        case NqbParseStatus::NotANumber:          return "NOT_A_NUMBER";
        case NqbParseStatus::TrailingGarbage:     return "TRAILING_GARBAGE";
        case NqbParseStatus::EmptyName:           return "EMPTY_NAME";
    }
    return "UNKNOWN";
}

inline bool nqbParseU64Full(const std::string& s, uint64_t& out) {
    if (s.empty()) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c < '0' || c > '9') return false;   // no sign, no space, no letters
        const uint64_t d = uint64_t(c - '0');
        if (v > (UINT64_MAX - d) / 10) return false;   // overflow
        v = v * 10 + d;
    }
    out = v;
    return true;   // full consumption is the only way this returns true
}

inline bool nqbIsHex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

struct NqbManifestLoad {
    std::vector<NqbF32Record> records;
    NqbParseStatus status = NqbParseStatus::Ok;
    std::string     detail;
    uint64_t        linesRead = 0, recordsAccepted = 0, linesRejected = 0;
};

inline NqbManifestLoad nqbLoadManifest(const std::string& text) {
    NqbManifestLoad out;
    bool sawSchema = false;
    std::vector<std::string> lines;
    std::string cur;
    for (char c : text) {
        if (c == '\n') { lines.push_back(cur); cur.clear(); }
        else if (c != '\r') cur.push_back(c);
    }
    if (!cur.empty()) lines.push_back(cur);

    for (const std::string& line : lines) {
        if (line.empty()) continue;
        if (line[0] == '#') continue;
        if (!sawSchema) {
            if (line != NQB_F32_MANIFEST_NAME) {
                out.status = NqbParseStatus::MissingSchema;
                out.detail = "first record line was '" + line + "'";
                return out;
            }
            sawSchema = true;
            continue;
        }
        if (line.rfind("FIELDS=", 0) == 0) {
            if (line.substr(7) != NQB_F32_MANIFEST_FIELDS) {
                out.status = NqbParseStatus::FieldCountMismatch;
                out.detail = "declared '" + line.substr(7) + "' expected '" +
                             NQB_F32_MANIFEST_FIELDS + "'";
                return out;
            }
            continue;
        }
        ++out.linesRead;

        std::vector<std::string> f;
        size_t p = 0;
        for (int k = 0; k < NQB_F32_MANIFEST_FIELD_COUNT; ++k) {
            const size_t t = line.find('\t', p);
            if (t == std::string::npos) { f.push_back(line.substr(p)); break; }
            f.push_back(line.substr(p, t - p));
            p = t + 1;
        }
        if (static_cast<int>(f.size()) != NQB_F32_MANIFEST_FIELD_COUNT) {
            ++out.linesRejected;
            if (out.status == NqbParseStatus::Ok) {
                out.status = NqbParseStatus::FieldCountMismatch;
                out.detail = "record '" + f[0] + "' has " +
                             std::to_string(f.size()) + " fields, expected " +
                             std::to_string(NQB_F32_MANIFEST_FIELD_COUNT);
            }
            continue;
        }
        if (f[0].empty()) {
            ++out.linesRejected;
            if (out.status == NqbParseStatus::Ok) {
                out.status = NqbParseStatus::EmptyName;
                out.detail = "record with empty name";
            }
            continue;
        }

        NqbF32Record r;
        r.name = f[0];
        uint64_t codec = 0, rank = 0;
        bool ok = nqbParseU64Full(f[1], codec) && nqbParseU64Full(f[2], rank) &&
                  nqbParseU64Full(f[3], r.dim0)   && nqbParseU64Full(f[4], r.dim1) &&
                  nqbParseU64Full(f[5], r.elements) &&
                  nqbParseU64Full(f[6], r.f32Bytes) &&
                  nqbParseU64Full(f[7], r.fnv1a64);
        if (!ok) {
            ++out.linesRejected;
            if (out.status == NqbParseStatus::Ok) {
                out.status = NqbParseStatus::NotANumber;
                out.detail = "record '" + r.name + "' has a non-numeric or "
                             "partially-numeric field";
            }
            continue;
        }
        if (!nqbIsHex64(f[8])) {
            ++out.linesRejected;
            if (out.status == NqbParseStatus::Ok) {
                out.status = NqbParseStatus::TrailingGarbage;
                out.detail = "record '" + r.name + "' sha256 is not 64 hex chars: '" +
                             f[8] + "'";
            }
            continue;
        }
        r.storedCodec = static_cast<uint32_t>(codec);
        r.rank        = static_cast<uint32_t>(rank);
        r.sha256      = f[8];
        out.records.push_back(r);
        ++out.recordsAccepted;
    }

    if (!sawSchema) {
        out.status = NqbParseStatus::MissingSchema;
        out.detail = "no " + std::string(NQB_F32_MANIFEST_NAME) + " line";
    }
    return out;
}

} // namespace Deep2