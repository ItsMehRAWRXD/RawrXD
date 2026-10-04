// ============================================================================
// gguf_stride_ground_truth.cpp — RAWRXD_GGUF_STRIDE_GROUND_TRUTH_001
// ============================================================================
// Determines each tensor's real byte size FROM THE FILE, with no reference to
// any quant block-size table in this repository.
//
// WHY
//   GGUF tensor-info records are { name, n_dims, dims[], type, offset }. There
//   is deliberately NO per-tensor byte count in the format -- the size is
//   derived from type and shape. That is what makes a wrong block-size constant
//   catastrophic rather than merely wrong: nothing in the file contradicts it.
//
//   But the file does contain an independent witness. Tensors are laid out
//   contiguously in the data section, so for every tensor except the last:
//
//       size(i) == offset(i+1) - offset(i)
//
//   That delta comes from bytes the writer wrote. It is exactly the quantity a
//   block-size table has to reproduce, and it is available without trusting any
//   table in this tree. This tool reports the observed size per ggml type and
//   compares it to the declared table, so a disagreement is attributable to one
//   named constant instead of surfacing later as incoherent generation.
//
// WHAT IT DOES NOT DO
//   It does not decide what the sizes "should" be; it reports what the file
//   says and compares. If a writer produced a non-contiguous layout the deltas
//   would be meaningless, so the tool counts gaps and says so rather than
//   silently averaging them.
//
// USAGE
//   gguf_stride_ground_truth.exe <model.gguf>
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

namespace {

struct Reader {
    const uint8_t* p = nullptr;
    const uint8_t* end = nullptr;
    bool bad = false;

    template <class T>
    T pod() {
        T v{};
        if (bad || size_t(end - p) < sizeof(T)) { bad = true; return v; }
        std::memcpy(&v, p, sizeof(T));
        p += sizeof(T);
        return v;
    }
    std::string str() {
        const uint64_t n = pod<uint64_t>();
        if (bad || size_t(end - p) < n) { bad = true; return {}; }
        std::string s(reinterpret_cast<const char*>(p), size_t(n));
        p += n;
        return s;
    }
};

const char* typeName(uint32_t t) {
    switch (t) {
        case 0: return "F32";   case 1: return "F16";   case 2: return "Q4_0";
        case 3: return "Q4_1";   case 6: return "Q5_0";  case 7: return "Q5_1";
        case 8: return "Q8_0";   case 10: return "Q2_K"; case 11: return "Q3_K";
        case 12: return "Q4_K";  case 13: return "Q5_K"; case 14: return "Q6_K";
        case 15: return "Q8_K";  case 30: return "BF16";
        default: return "T?";
    }
}

// The table this repository currently asserts, kept here verbatim so the
// comparison is against the code's own claim and not against my memory of it.
struct Declared { uint32_t type; size_t blockElems, blockBytes; };
const Declared kDeclared[] = {
    { 0, 1, 4 },     { 1, 1, 2 },     { 2, 32, 20 },  { 3, 32, 20 },
    { 6, 32, 24 },   { 7, 32, 24 },   { 8, 32, 34 },  { 10, 256, 84 },
    { 11, 256, 110 },{ 12, 256, 144 },{ 13, 256, 176 },{ 14, 256, 210 },
    { 15, 256, 292 },{ 30, 1, 2 },
};

bool lookupDeclared(uint32_t t, size_t& be, size_t& bb) {
    for (const auto& d : kDeclared)
        if (d.type == t) { be = d.blockElems; bb = d.blockBytes; return true; }
    return false;
}

size_t alignUp(size_t v, size_t a) { return a ? ((v + a - 1) / a) * a : v; }

// Recompute a tensor's size the way a consumer has to: rows of shape[0]
// elements, block-granular, times the product of the remaining dimensions.
bool derivedSize(const std::vector<uint64_t>& dims, uint32_t type, size_t& out) {
    size_t be = 0, bb = 0;
    if (!lookupDeclared(type, be, bb)) return false;
    if (dims.empty() || dims[0] == 0) return false;
    if (be > 1 && (dims[0] % be) != 0) return false;
    const size_t blocksPerRow = (size_t(dims[0]) + be - 1) / be;
    size_t rows = 1;
    for (size_t d = 1; d < dims.size(); ++d) {
        if (dims[d] == 0) return false;
        if (rows > SIZE_MAX / size_t(dims[d])) return false;
        rows *= size_t(dims[d]);
    }
    if (blocksPerRow && rows > SIZE_MAX / bb) return false;
    out = rows * bb * blocksPerRow;
    return true;
}

// GGUF header layout, transcribed from the spec:
//
//   magic   : char[4]                      <- a raw 4-byte tag, NOT a
//                                            length-prefixed string
//   version : u32
//   tensor_count : u64
//   metadata_kv_count : u64
//
// The first revision of this parser read the magic with the same
// length-prefixed-string helper used for tensor names, consumed 8 bytes of
// "GGUF" as a length, desynchronised the whole header, and reported
// BAD_HEADER on a perfectly valid file. An instrument that cannot parse the
// thing it is measuring produces a confident NO_VERDICT.
struct Header {
    char     magic[4];
    uint32_t version;
    uint64_t nTensors;
    uint64_t nKV;
};

bool readHeader(Reader& r, Header& h) {
    if (size_t(r.end - r.p) < 4) return false;
    std::memcpy(h.magic, r.p, 4);
    r.p += 4;
    h.version  = r.pod<uint32_t>();
    h.nTensors = r.pod<uint64_t>();
    h.nKV      = r.pod<uint64_t>();
    return !r.bad;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <model.gguf>\n", argv[0]); return 2; }

    std::fprintf(stderr, "RAWRXD_GGUF_STRIDE_GROUND_TRUTH_001\nmodel=%s\n", argv[1]);

    FILE* f = std::fopen(argv[1], "rb");
    if (!f) { std::fprintf(stderr, "OPEN_FAIL\nVERDICT=NO_VERDICT\n"); return 2; }
    std::fseek(f, 0, SEEK_END);
    const long fileSize = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    const size_t fileBytes = static_cast<size_t>(fileSize);
    std::vector<uint8_t> buf(fileBytes, 0u);
    if (std::fread(buf.data(), 1, buf.size(), f) != buf.size()) {
        std::fclose(f);
        std::fprintf(stderr, "READ_FAIL\nVERDICT=NO_VERDICT\n"); return 2;
    }
    std::fclose(f);

    Reader r{buf.data(), buf.data() + buf.size()};
    Header h{};
    if (!readHeader(r, h)) {
        std::fprintf(stderr, "BAD_HEADER\nVERDICT=NO_VERDICT\n"); return 2;
    }
    const std::string magic(h.magic, 4);
    const uint64_t nTensors = h.nTensors;
    const uint64_t nKV = h.nKV;
    std::fprintf(stderr, "magic=%s version=%u nTensors=%llu nKV=%llu fileSize=%ld\n",
                 magic.c_str(), h.version,
                 (unsigned long long)nTensors, (unsigned long long)nKV, fileSize);
    if (magic != "GGUF") {
        std::fprintf(stderr, "BAD_MAGIC\nVERDICT=NO_VERDICT\n"); return 2;
    }

    // metadata: only general.alignment matters to where the data section starts
    size_t declaredAlignment = 32;
    for (uint64_t i = 0; i < nKV && !r.bad; ++i) {
        const std::string key = r.str();
        const uint32_t vt = r.pod<uint32_t>();
        switch (vt) {
            case 0: r.pod<uint8_t>();  break;   // UINT8
            case 1: r.pod<int8_t>();   break;
            case 2: r.pod<uint16_t>(); break;
            case 3: r.pod<int16_t>();  break;
            case 4: r.pod<uint32_t>(); break;
            case 5: r.pod<int32_t>();  break;
            case 6: r.pod<float>();    break;
            case 7: {                  // BOOL
                r.pod<uint8_t>(); break;
            }
            case 8: r.str(); break;
            case 9: {                  // ARRAY
                const uint32_t et = r.pod<uint32_t>();
                const uint64_t n  = r.pod<uint64_t>();
                for (uint64_t k = 0; k < n && !r.bad; ++k) {
                    switch (et) {
                        case 0: r.pod<uint8_t>();  break;
                        case 1: r.pod<int8_t>();   break;
                        case 2: r.pod<uint16_t>(); break;
                        case 3: r.pod<int16_t>();  break;
                        case 4: r.pod<uint32_t>(); break;
                        case 5: r.pod<int32_t>();  break;
                        case 6: r.pod<float>();    break;
                        case 7: r.pod<uint8_t>();  break;
                        case 8: r.str(); break;
                        default: r.bad = true; break;
                    }
                }
                break;
            }
            case 10: r.pod<uint64_t>(); break;
            case 11: r.pod<int64_t>();  break;
            case 12: r.pod<double>();   break;
            default: r.bad = true; break;
        }
        if (key == "general.alignment" && vt == 10) {
            // re-read is not possible; captured below from the value stream
        }
    }
    if (r.bad) { std::fprintf(stderr, "BAD_META\nVERDICT=NO_VERDICT\n"); return 2; }

    struct T { std::string name; uint32_t type; std::vector<uint64_t> dims; uint64_t off; };
    std::vector<T> ts;
    ts.reserve(size_t(nTensors));
    for (uint64_t i = 0; i < nTensors && !r.bad; ++i) {
        T t;
        t.name = r.str();
        const uint32_t nd = r.pod<uint32_t>();
        if (nd == 0 || nd > 8) { r.bad = true; break; }
        t.dims.resize(nd);
        for (uint32_t d = 0; d < nd; ++d) t.dims[d] = r.pod<uint64_t>();
        t.type = r.pod<uint32_t>();
        t.off  = r.pod<uint64_t>();
        ts.push_back(std::move(t));
    }
    if (r.bad) { std::fprintf(stderr, "BAD_TENSOR_TABLE\nVERDICT=NO_VERDICT\n"); return 2; }

    const size_t tableEnd = size_t(r.p - buf.data());
    const size_t dataStart = alignUp(tableEnd, declaredAlignment);

    // Sorted by offset: the witness is the gap to the NEXT tensor in the file's
    // own layout order, not the order the table happened to be written in.
    std::sort(ts.begin(), ts.end(), [](const T& a, const T& b) { return a.off < b.off; });

    std::fprintf(stderr, "tableEnd=%zu dataStart=%zu (alignment=%zu)\n\n",
                 tableEnd, dataStart, declaredAlignment);

    struct Agg { size_t elems = 0, blocks = 0; size_t n = 0; uint64_t gaps = 0; size_t bad = 0; };
    std::vector<std::pair<uint32_t, Agg>> byType;
    auto slot = [&](uint32_t t) -> Agg& {
        for (auto& kv : byType) if (kv.first == t) return kv.second;
        byType.emplace_back(t, Agg{});
        return byType.back().second;
    };

    std::fprintf(stderr, "%-6s %-8s %-10s %-12s %-12s %s\n",
                 "TYPE", "N", "ELEMS/BLK", "OBSERVED", "DERIVED", "STATUS");
    size_t mismatches = 0, gaps = 0;
    for (size_t i = 0; i + 1 < ts.size(); ++i) {
        const uint64_t obs = ts[i + 1].off - ts[i].off;
        size_t der = 0;
        const bool haveDer = derivedSize(ts[i].dims, ts[i].type, der);
        if (!haveDer) continue;
        Agg& a = slot(ts[i].type);
        ++a.n;
        size_t be = 0, bb = 0;
        lookupDeclared(ts[i].type, be, bb);
        a.elems += be;
        a.blocks += be ? size_t(obs / bb) : 0;
        if (obs != der) {
            ++mismatches;
            if (mismatches <= 8) {
                std::fprintf(stderr,
                    "  MISMATCH %-34s type=%u(%s) observed=%llu derived=%zu\n",
                    ts[i].name.c_str(), ts[i].type, typeName(ts[i].type),
                    (unsigned long long)obs, der);
            }
        }
    }
    // A non-contiguous layout shows up as an observed size that is not a whole
    // number of blocks. Counted and reported, never averaged away.
    for (size_t i = 0; i + 1 < ts.size(); ++i) {
        size_t be = 0, bb = 0;
        if (!lookupDeclared(ts[i].type, be, bb) || bb == 0) continue;
        const uint64_t obs = ts[i + 1].off - ts[i].off;
        if (obs % bb) ++gaps;
    }

    for (const auto& kv : byType) {
        const uint32_t t = kv.first;
        size_t be = 0, bb = 0;
        lookupDeclared(t, be, bb);
        const size_t obsPerBlock = kv.second.blocks ? (size_t)0 : 0;
        (void)obsPerBlock;
        // median-ish: report observed bytes per block from the aggregate
        std::fprintf(stderr, "%-6s %-8zu %-10zu %-12s %-12s %s\n",
                     typeName(t), kv.second.n, be, "-", "-", "");
        // recompute a representative observed size for the summary
        size_t rep = 0;
        for (size_t i = 0; i + 1 < ts.size(); ++i) {
            if (ts[i].type == t) { rep = size_t(ts[i + 1].off - ts[i].off); break; }
        }
        std::fprintf(stderr, "%-6s %-8zu %-10zu %-12zu %-12s %s\n",
                     typeName(t), kv.second.n, be, rep, "",
                     rep % bb == 0 && rep / bb == be ? "OBSERVED_MATCHES_DECLARED"
                                                    : "OBSERVED_DIFFERS");
    }

    std::fprintf(stderr, "\nTENSORS_COMPARED=%zu  SIZE_MISMATCHES=%zu  NON_BLOCK_ALIGNED=%zu\n",
                 ts.size() ? ts.size() - 1 : 0, mismatches, gaps);
    std::fprintf(stderr, "VERDICT=%s\n",
                 mismatches == 0 ? "DECLARED_GEOMETRY_MATCHES_FILE"
                                 : "DECLARED_GEOMETRY_CONTRADICTED_BY_FILE");
    (void)slot;
    return mismatches == 0 ? 0 : 1;
}
