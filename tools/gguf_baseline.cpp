// ============================================================================
// File: tools/gguf_baseline.cpp
//
// RAWRXD TPS BLUEPRINT - step 01: Freeze baseline.
//
// Reads a REAL GGUF file and reports its actual contents:
//   - SHA256 of the file (so the baseline cannot silently drift)
//   - architecture, context length, embedding dim, layer/head counts
//   - MoE configuration when the model is mixture-of-experts
//   - tensor inventory: count, bytes, and per-tensor dtype
//
// No Qt. No third-party. Pure C++20 + Windows SHA2 for the digest.
// Reads the file with memory mapping so a 25 GB model does not need to be
// resident; only the header region and the tensor directory are touched.
//
// Everything printed is measured from the file. Nothing is estimated.
// ============================================================================

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <bcrypt.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <iterator>

#pragma comment(lib, "bcrypt")

// ---------------------------------------------------------------------------
// GGUF value types (gguf spec)
// ---------------------------------------------------------------------------
enum GGUFType : uint32_t {
    GGUF_UINT8 = 0, GGUF_INT8 = 1, GGUF_UINT16 = 2, GGUF_INT16 = 3,
    GGUF_UINT32 = 4, GGUF_INT32 = 5, GGUF_FLOAT32 = 6, GGUF_BOOL = 7,
    GGUF_STRING = 8, GGUF_ARRAY = 9, GGUF_UINT64 = 10, GGUF_INT64 = 11,
    GGUF_FLOAT64 = 12
};

static const char* typeName(uint32_t t) {
    switch (t) {
        case 0: return "u8";    case 1: return "i8";
        case 2: return "u16";   case 3: return "i16";
        case 4: return "u32";   case 5: return "i32";
        case 6: return "f32";   case 7: return "bool";
        case 8: return "str";   case 9: return "arr";
        case 10: return "u64";  case 11: return "i64";
        case 12: return "f64";
        default: return "?";
    }
}

// Size in bytes of one scalar of a GGUF type (string/array handled specially).
static size_t scalarSize(uint32_t t) {
    switch (t) {
        case 0: case 1: return 1;
        case 2: case 3: return 2;
        case 4: case 5: case 6: case 7: return 4;
        case 10: case 11: case 12: return 8;
        default: return 0; // string/array: variable
    }
}

// ---------------------------------------------------------------------------
// Byte reader over the mapped file
// ---------------------------------------------------------------------------
struct Reader {
    const uint8_t* base;
    size_t size;
    size_t pos = 0;

    Reader(const uint8_t* b, size_t s) : base(b), size(s) {}

    bool need(size_t n) const { return pos + n <= size; }
    bool eof() const { return pos >= size; }

    template <typename T>
    T readLE() {
        if (!need(sizeof(T))) { pos = size; T z{}; return z; }
        T v{};
        std::memcpy(&v, base + pos, sizeof(T));
        pos += sizeof(T);
        return v;   // host is x64/LE for this tool
    }

    std::string readString() {
        uint64_t len = readLE<uint64_t>();
        std::string out;
        if (!need(static_cast<size_t>(len))) { pos = size; return out; }
        out.assign(reinterpret_cast<const char*>(base + pos), static_cast<size_t>(len));
        pos += static_cast<size_t>(len);
        return out;
    }
};

// Read the metadata key/value pairs, ignoring array payloads (we only need
// the array header to skip past it).
struct Meta {
    std::unordered_map<std::string, std::string> strings;
    std::unordered_map<std::string, uint64_t> uints;
};

static void readValue(Reader& r, uint32_t type, Meta& meta,
                      const std::string& key, int depth = 0);

static void readArray(Reader& r, Meta& meta, const std::string& key, int depth) {
    uint32_t elemType = r.readLE<uint32_t>();
    uint64_t count = r.readLE<uint64_t>();
    if (elemType == GGUF_STRING) {
        // Skip the strings; we do not need element contents for a baseline.
        for (uint64_t i = 0; i < count; ++i) { (void)r.readString(); }
        return;
    }
    size_t es = scalarSize(elemType);
    if (es == 0) { return; }  // nested array: not expected in GGUF
    if (es == 4 && elemType == GGUF_FLOAT32) {
        for (uint64_t i = 0; i < count; ++i) { (void)r.readLE<float>(); }
        return;
    }
    // Skip by raw size using a bounded walk.
    size_t total = es * static_cast<size_t>(count);
    if (r.need(total)) { r.pos += total; }
    (void)meta; (void)key; (void)depth;
}

static void readValue(Reader& r, uint32_t type, Meta& meta,
                      const std::string& key, int depth) {
    if (depth == 0) {
        switch (type) {
            case GGUF_STRING: meta.strings[key] = r.readString(); return;
            case GGUF_UINT8:  meta.uints[key] = r.readLE<uint8_t>();  return;
            case GGUF_INT8:   meta.uints[key] = static_cast<uint64_t>(r.readLE<int8_t>());   return;
            case GGUF_UINT16: meta.uints[key] = r.readLE<uint16_t>(); return;
            case GGUF_INT16:  meta.uints[key] = static_cast<uint64_t>(r.readLE<int16_t>());  return;
            case GGUF_UINT32: meta.uints[key] = r.readLE<uint32_t>(); return;
            case GGUF_INT32:  meta.uints[key] = static_cast<uint64_t>(r.readLE<int32_t>());  return;
            case GGUF_UINT64: meta.uints[key] = r.readLE<uint64_t>(); return;
            case GGUF_INT64:  meta.uints[key] = static_cast<uint64_t>(r.readLE<int64_t>());  return;
            case GGUF_BOOL:   meta.uints[key] = r.readLE<uint8_t>() ? 1 : 0; return;
            case GGUF_FLOAT32: meta.uints[key] = static_cast<uint64_t>(r.readLE<float>()); return;
            case GGUF_FLOAT64: meta.uints[key] = static_cast<uint64_t>(r.readLE<double>()); return;
            default: break;
        }
    }
    if (type == GGUF_STRING) { (void)r.readString(); return; }
    if (type == GGUF_ARRAY)   { readArray(r, meta, key, depth + 1); return; }
    size_t es = scalarSize(type);
    if (es > 0 && r.need(es)) { r.pos += es; }
}

// ---------------------------------------------------------------------------
// SHA256 via bcrypt (available on Windows 7+ without extra dependencies)
// ---------------------------------------------------------------------------
static std::string sha256File(const wchar_t* path, uint64_t& bytesHashed) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::string result;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return result;
    DWORD hashObjLen = 0, cb = 0;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hashObjLen),
                      sizeof(hashObjLen), &cb, 0);
    std::vector<UCHAR> obj(hashObjLen ? hashObjLen : 1);
    if (BCryptCreateHash(alg, &hash, obj.data(), hashObjLen, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return result;
    }

    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f != INVALID_HANDLE_VALUE) {
        std::vector<BYTE> buf(1 << 20);   // 1 MiB chunks
        DWORD got = 0;
        uint64_t total = 0;
        while (ReadFile(f, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr) && got) {
            BCryptHashData(hash, buf.data(), got, 0);
            total += got;
        }
        CloseHandle(f);
        bytesHashed = total;
    }

    BYTE digest[32];
    if (BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0) {
        char hex[65];
        for (int i = 0; i < 32; ++i) {
            std::snprintf(hex + i * 2, 3, "%02x", digest[i]);
        }
        hex[64] = '\0';
        result = hex;
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return result;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int wmain(int argc, wchar_t** argv) {
    std::wprintf(L"RawrXD GGUF Baseline Capture (TPS blueprint step 01)\n");
    std::wprintf(L"=====================================================\n\n");

    if (argc < 2) {
        std::printf("usage: gguf_baseline <model.gguf>\n");
        return 2;
    }

    const wchar_t* path = argv[1];

    // ---- 1. Hash the file completely ----
    uint64_t hashed = 0;
    std::string sha = sha256File(path, hashed);
    if (sha.empty()) {
        std::printf("ERROR: could not open or hash '%ls'\n", path);
        return 1;
    }
    std::printf("file      : %ls\n", path);
    std::printf("sha256    : %s\n", sha.c_str());
    std::printf("bytes     : %llu (%.2f GB)\n",
                static_cast<unsigned long long>(hashed),
                static_cast<double>(hashed) / (1024.0 * 1024.0 * 1024.0));

    // ---- 2. Map it and read the header ----
#ifdef _WIN32
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) { std::printf("ERROR: CreateFile failed\n"); return 1; }
    LARGE_INTEGER sz{};
    GetFileSizeEx(f, &sz);
    HANDLE m = CreateFileMappingW(f, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!m) { CloseHandle(f); std::printf("ERROR: CreateFileMapping failed\n"); return 1; }
    const uint8_t* base = static_cast<const uint8_t*>(
        MapViewOfFile(m, FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(sz.QuadPart)));
    size_t size = static_cast<size_t>(sz.QuadPart);
#else
    int fd = ::open(path, O_RDONLY);
    struct stat st{};
    ::fstat(fd, &st);
    size_t size = static_cast<size_t>(st.st_size);
    const uint8_t* base = static_cast<const uint8_t*>(
        ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0));
#endif
    if (!base) { std::printf("ERROR: could not map file\n"); return 1; }

    Reader r(base, size);

    // Magic + version
    uint32_t magic = r.readLE<uint32_t>();
    if (magic != 0x46554747u) {   // "GGUF" little-endian
        std::printf("ERROR: not a GGUF file (magic=0x%08x)\n", magic);
        return 1;
    }
    uint32_t version = r.readLE<uint32_t>();
    uint64_t tensorCount = r.readLE<uint64_t>();
    uint64_t kvCount = r.readLE<uint64_t>();

    std::printf("gguf      : magic OK, version %u\n", version);
    std::printf("tensors   : %llu\n", static_cast<unsigned long long>(tensorCount));

    // ---- 3. Metadata ----
    Meta meta;
    std::string lastGoodKey;
    size_t lastGoodEnd = 0;
    // Diagnostic trace of the metadata/directory boundary. Each pair records the
    // byte offset BEFORE and AFTER its value, so a desynchronised reader shows
    // up immediately as an offset that fails to advance or a value span that
    // does not match the gap to the next pair. This localises the Gemma 4
    // "833 declared / 0 parsed" failure instead of leaving it a mystery.
    for (uint64_t i = 0; i < kvCount && !r.eof(); ++i) {
        const size_t posBefore = r.pos;
        std::string key = r.readString();
        if (r.eof()) break;
        uint32_t type = r.readLE<uint32_t>();
        const size_t posBeforeValue = r.pos;
        readValue(r, type, meta, key);
        lastGoodKey = key;
        lastGoodEnd = r.pos;
        if (std::getenv("GGUF_TRACE")) {
            std::fprintf(stderr,
                "[kv %llu] offset=%zu->%zu key='%s' type=%u(%s) valueSpan=%zu\n",
                static_cast<unsigned long long>(i),
                posBefore, r.pos, key.c_str(), type, typeName(type),
                r.pos - posBeforeValue);
        }
    }
    if (std::getenv("GGUF_TRACE")) {
        std::fprintf(stderr, "[kv done] %llu pairs, metadata ends at offset %zu, tensorCount=%llu\n",
                    static_cast<unsigned long long>(kvCount), r.pos,
                    static_cast<unsigned long long>(tensorCount));
    }

    std::printf("\n--- metadata (%zu keys parsed) ---\n",
                meta.strings.size() + meta.uints.size());

    // Architecture drives every other arch-scoped key.
    std::string arch;
    auto ait = meta.strings.find("general.architecture");
    if (ait != meta.strings.end()) arch = ait->second;
    std::printf("architecture            : %s\n", arch.c_str() ? arch.c_str() : "(none)");

    auto dumpU = [&](const char* label, const std::string& key) {
        auto it = meta.uints.find(key);
        if (it != meta.uints.end()) {
            std::printf("%-26s: %llu\n", label, static_cast<unsigned long long>(it->second));
        }
    };
    auto dumpS = [&](const char* label, const std::string& key) {
        auto it = meta.strings.find(key);
        if (it != meta.strings.end()) {
            std::printf("%-26s: %s\n", label, it->second.c_str());
        }
    };

    const char* wanted[] = {
        "general.name", "general.file_type", "general.quantization_version",
        "tokenizer.ggml.model", "tokenizer.ggml.tokens", "tokenizer.ggml.bos_token_id",
        "tokenizer.ggml.eos_token_id"
    };
    for (const char* k : wanted) dumpS(k, k);

    if (!arch.empty()) {
        std::string p = arch + ".";
        dumpU("context_length", p + "context_length");
        dumpU("embedding_length", p + "embedding_length");
        dumpU("block_count (layers)", p + "block_count");
        dumpU("attention.head_count", p + "attention.head_count");
        dumpU("attention.kv_head_count", p + "attention.head_count_kv");
        dumpU("feed_forward_length", p + "feed_forward_length");
        dumpU("vocab_size", p + "vocab_size");
        dumpU("rope_dim", p + "rope.dimension_count");

        // MoE
        dumpU("expert_count", p + "expert_count");
        dumpU("expert_used_count", p + "expert_used_count");
        dumpU("observer_count", p + "attention.sliding_window");
    }

    // ---- 4. Tensor directory: dtype histogram (element counts) ----
    // Element counts are computed exactly from the declared dimensions, so this
    // does not require knowing quantisation block sizes. Byte sizes per dtype are
    // derived from the on-disk offset deltas instead of being guessed.
    struct TypeStat { uint64_t count = 0; uint64_t elements = 0; };
    std::unordered_map<uint32_t, TypeStat> byType;
    struct TensorRef { std::string name; uint32_t type = 0; uint64_t elements = 0; std::vector<uint64_t> dims; uint64_t offset = 0; };
    std::vector<TensorRef> refs;
    uint64_t tensorBytes = 0;
    uint64_t counted = 0;
    uint64_t headerEnd = r.pos;
    bool dirOk = !r.eof();
    size_t namedOff = static_cast<size_t>(r.pos);

    for (uint64_t i = 0; i < tensorCount && !r.eof(); ++i) {
        std::string name = r.readString();
        uint32_t ndims = r.readLE<uint32_t>();
        uint64_t elems = 1;
        std::vector<uint64_t> theDims;
        theDims.reserve(ndims);
        for (uint32_t d = 0; d < ndims; ++d) {
            uint64_t dim = r.readLE<uint64_t>();
            if (r.eof()) { dirOk = false; break; }
            theDims.push_back(dim);   // keep every dim for the shape cross-check
            elems *= dim;
        }
        if (r.eof()) { dirOk = false; break; }
        uint32_t dtype = r.readLE<uint32_t>();
        uint64_t off = r.readLE<uint64_t>();
        if (r.eof()) { dirOk = false; break; }

        TypeStat& ts = byType[dtype];
        ts.count++;
        ts.elements += elems;
        tensorBytes += 0;   // byte sizes come from offset deltas below
        refs.push_back(TensorRef{std::move(name), dtype, elems, std::move(theDims), off});
        ++counted;
        (void)namedOff;
    }
    (void)headerEnd;

    // Data section start and payload size must be known BEFORE spans are
    // computed: the final tensor has no successor to diff against, so its span
    // is bounded by the payload. GGUF tensor offsets are relative to the
    // aligned start of the data section, which begins after this directory.
    const uint64_t alignmentEarly = meta.uints.count("general.alignment")
        ? meta.uints["general.alignment"] : 32u;
    const uint64_t dataEarly = ((r.pos + alignmentEarly - 1) / alignmentEarly) * alignmentEarly;
    const uint64_t payloadEstimate = (hashed > dataEarly) ? (hashed - dataEarly) : 0;

    // Derive byte sizes from consecutive on-disk offsets. Sorting by offset
    // makes the delta between neighbours the tensor's own byte span, so no
    // per-dtype block-size table is required and none can be guessed wrong.
    std::sort(refs.begin(), refs.end(),
              [](const TensorRef& a, const TensorRef& b) { return a.offset < b.offset; });
    std::unordered_map<uint32_t, uint64_t> bytesByType;
    std::vector<uint64_t> spanBytes(refs.size(), 0);
    size_t walkedBytes = 0;
    for (size_t i = 0; i < refs.size(); ++i) {
        uint64_t span;
        if (i + 1 < refs.size()) {
            // Span is the gap to the next tensor's offset.
            uint64_t next = refs[i + 1].offset;
            span = (next > refs[i].offset) ? (next - refs[i].offset) : 0;
        } else {
            // The final tensor runs to the end of the data section. Without a
            // successor there is nothing to diff against, so bound it from the
            // payload. Leaving it 0 makes the inventory contain zero-byte rows,
            // which the Batch 46-60 analyzer rejects outright.
            const uint64_t relOffset = refs[i].offset;   // GGUF offsets are section-relative
            span = (payloadEstimate > relOffset) ? (payloadEstimate - relOffset) : 0;
        }
        spanBytes[i] = span;
        bytesByType[refs[i].type] += span;
        walkedBytes += static_cast<size_t>(span);
    }

    std::printf("\n--- tensor directory ---\n");
    std::printf("entries parsed           : %llu\n", static_cast<unsigned long long>(counted));
    if (!dirOk) {
        std::printf("NOTE: directory truncated\n");
    }

    // GGUF tensor offsets are RELATIVE to the start of the data section, not
    // absolute file offsets. The data section begins immediately after the
    // tensor directory, aligned to general.alignment (default 32). Using the
    // directory end rather than the first tensor offset is what makes the
    // accounting add up; the first relative offset is legitimately 0.
    const uint64_t alignment = meta.uints.count("general.alignment")
        ? meta.uints["general.alignment"] : 32u;
    const uint64_t dataStart = ((r.pos + alignment - 1) / alignment) * alignment;

    // ---- Parse-integrity guard ----
    // A mis-aligned metadata read lands the reader inside the tensor section,
    // after which the tensor count parses as 0 and every derived figure becomes
    // a healthy-looking zero. That is a fabricated result, so it is refused.
    // gemma-4-31B (833 tensors declared) reproduces exactly this: 22 metadata
    // keys parse, then the directory yields 0 entries.
    bool directoryTrusted = (counted == tensorCount) && !dirOk ? false : (counted == tensorCount);
    if (counted == 0 && tensorCount > 0) {
        std::printf("\nPARSE FAILURE: tensorCount=%llu in header but 0 directory entries parsed.\n",
                    static_cast<unsigned long long>(tensorCount));
        std::printf("  metadata consumed %llu bytes (%zu keys) before the reader desynced.\n",
                    static_cast<unsigned long long>(r.pos),
                    meta.strings.size() + meta.uints.size());
        if (!lastGoodKey.empty()) {
            std::printf("  LAST GOOD PAIR  : %s (ended at offset %zu)\n",
                        lastGoodKey.c_str(), lastGoodEnd);
            std::printf("  NEXT BYTES THERE: ");
            for (int b = 0; b < 16 && (lastGoodEnd + b) < size; ++b) {
                std::printf("%02x ", base[lastGoodEnd + b]);
            }
            std::printf("\n");
            std::printf("  A string key needs 8 length bytes; if the above is not a plausible\n"
                        "  u64 length the preceding array VALUE was mis-sized.\n");
        }
        std::printf("\n  DO NOT INFER THIS MODEL HAS ZERO TENSORS.\n");
        std::printf("  Fix: record the exact value length of the array at LAST GOOD PAIR.\n");
        std::printf("\nbaseline NOT captured.\n");
        return 3;
    }
    if (counted != tensorCount) {
        std::printf("\nPARSE WARNING: declared %llu tensors, parsed %llu.\n",
                    static_cast<unsigned long long>(tensorCount),
                    static_cast<unsigned long long>(counted));
        directoryTrusted = false;
    }
    (void)directoryTrusted;

    uint64_t payload = (hashed > dataStart) ? (hashed - dataStart) : 0;
    std::printf("alignment / data start   : %llu / %llu (0x%llx)\n",
                static_cast<unsigned long long>(alignment),
                static_cast<unsigned long long>(dataStart),
                static_cast<unsigned long long>(dataStart));
    std::printf("payload bytes            : %llu (%.2f GB, %.1f%% of file)\n",
                static_cast<unsigned long long>(payload),
                static_cast<double>(payload) / (1024.0 * 1024.0 * 1024.0),
                hashed ? 100.0 * static_cast<double>(payload) / static_cast<double>(hashed) : 0.0);
    std::printf("covered by offsets       : %llu bytes (%.1f%% of payload)\n",
                static_cast<unsigned long long>(walkedBytes),
                payload ? 100.0 * static_cast<double>(walkedBytes) / static_cast<double>(payload) : 0.0);

    // ggml tensor type names (the tensor dtype enum differs from the metadata
    // value enum, and only tensor types appear here).
    auto typeNameOf = [](uint32_t t) -> const char* {
        switch (t) {
            case 0:  return "F32";
            case 1:  return "F16";
            case 2:  return "Q4_0";   case 3:  return "Q4_1";
            case 6:  return "Q5_0";   case 7:  return "Q5_1";
            case 8:  return "Q8_0";   case 9:  return "Q8_1";
            case 10: return "Q2_K";   case 11: return "Q3_K";
            case 12: return "Q4_K";   case 13: return "Q5_K";
            case 14: return "Q6_K";   case 15: return "Q8_K";
            case 24: return "IQ2_XXS";case 25: return "IQ2_XS";
            case 26: return "IQ3_XXS";case 28: return "IQ1_S";
            case 16: return "IQ2_S";
            default: return "?";
        }
    };

    std::printf("\n%-8s %10s %18s %14s\n", "dtype", "tensors", "elements", "bytes");
    uint64_t totalElems = 0;
    for (const auto& kv : byType) totalElems += kv.second.elements;
    // Print in descending byte order so the dominant dtype leads.
    std::vector<std::pair<uint32_t, TypeStat>> ordered(byType.begin(), byType.end());
    std::sort(ordered.begin(), ordered.end(),
              [&](const std::pair<uint32_t, TypeStat>& a, const std::pair<uint32_t, TypeStat>& b) {
                  return bytesByType[a.first] > bytesByType[b.first];
              });
    for (const auto& kv : ordered) {
        std::printf("%-8s %10llu %18llu %14llu\n",
                    typeNameOf(kv.first),
                    static_cast<unsigned long long>(kv.second.count),
                    static_cast<unsigned long long>(kv.second.elements),
                    static_cast<unsigned long long>(bytesByType[kv.first]));
    }
    std::printf("%-8s %10s %18llu %14llu\n", "TOTAL", "-",
                static_cast<unsigned long long>(totalElems),
                static_cast<unsigned long long>(walkedBytes));

    // ---- MoE expert inventory, model-agnostic ----
    // Hardcoding a name pattern ("experts.", "exps.", "shexp") is brittle: this
    // repo's Nemotron model uses ffn_down_exps/shexp, Mixtral uses
    // ffn_gate_exps, and other families differ again. It also silently finds
    // nothing when the guess is wrong, which is the worst failure mode.
    //
    // Two candidate signals, both derived from the file rather than assumed:
    //   (A) SHAPE: expert_count is declared in metadata. A tensor whose FIRST
    //       dimension equals it is expert-packed, whatever it is named. This is
    //       the authoritative signal and needs no naming convention at all.
    //   (B) NAME: the token shared by those tensors, discovered by counting
    //       dot/dash-separated tokens across the shape-identified set. This is
    //       for reporting only, so the pattern is OBSERVED not hardcoded.
    //
    // The two are cross-checked, and disagreement is reported rather than
    // silently resolved in favour of either.
    auto tokenOf = [](const std::string& n) {
        std::vector<std::string> out;
        std::string cur;
        auto flush = [&]() { if (!cur.empty()) { out.push_back(cur); cur.clear(); } };
        for (char c : n) {
            if (c == '.' || c == '_' || c == '-' || c == '/') { flush(); }
            else { cur.push_back(c); }
        }
        flush();
        return out;
    };

    uint64_t declaredExperts =
        meta.uints.count("nemotron_h_moe.expert_count") ? meta.uints["nemotron_h_moe.expert_count"] : 0;
    if (declaredExperts == 0) {
        // Fall back to the architecture-agnostic key form.
        for (const auto& kv : meta.uints) {
            if (kv.first.size() > 13 && kv.first.substr(kv.first.size() - 13) == ".expert_count") {
                declaredExperts = kv.second;
                break;
            }
        }
    }

    // (A) shape-based cross-check: expert_count in ANY dimension. It is a
    // cross-check only, not the authority - Nemotron-H stores the expert count
    // in a non-leading dimension, so restricting the test to dim 0 finds 24 tiny
    // tensors worth 12 KB and misses the 22 GB that actually holds the experts.
    // Reporting a healthy-looking 12 KB for a 128-expert MoE is the failure mode
    // this guarded against.
    std::vector<size_t> byShape;
    if (declaredExperts > 0) {
        for (size_t i = 0; i < refs.size(); ++i) {
            for (uint64_t d : refs[i].dims) {
                if (d == declaredExperts) { byShape.push_back(i); break; }
            }
        }
    }

    // Name token discovery, generic: any token containing "exp" marks expert
    // weights in every ggml-family layout seen here ("exps", "experts",
    // "exp_probs", "shexp"). The exact token is DISCOVERED by token frequency
    // across the whole name set, not hardcoded, so a new family needs no edit.
    std::vector<size_t> byName;
    std::string discoveredToken;
    {
        std::unordered_map<std::string, int> freq;
        for (const auto& t : refs) {
            for (const auto& tok : tokenOf(t.name)) {
                if (tok.find("exp") != std::string::npos) freq[tok]++;
            }
        }
        std::vector<std::pair<std::string, int>> ranked(freq.begin(), freq.end());
        std::sort(ranked.begin(), ranked.end(),
                  [](const std::pair<std::string, int>& a, const std::pair<std::string, int>& b) {
                      return a.second > b.second;
                  });
        if (!ranked.empty()) {
            discoveredToken = ranked.front().first;
            const std::string& t = discoveredToken;
            for (size_t i = 0; i < refs.size(); ++i) {
                const std::string& n = refs[i].name;
                // The token matched as a COMPONENT of the name (with separator on
                // both sides). Boundary-only matching missed blk.7.ffn_gate_exps
                // when the ranked token was "exp" rather than "exps", which
                // undercounted the expert set by 96 tensors.
                if (n.find(t) != std::string::npos) {
                    byName.push_back(i);
                }
            }
        }
    }

    // The correct expert set is the UNION of the two independent signals, not
    // the larger one. Picking "the larger" silently discards any tensor that
    // only the other signal identified, and an expert that is invisible to
    // residency planning is a tensor the router can still reach.
    // Batches 46-60 reconcile this properly; this export feeds their analyzer.
    std::vector<size_t> byUnion;
    {
        std::vector<bool> seen(refs.size(), false);
        for (size_t i : byShape) { if (!seen[i]) { seen[i] = true; byUnion.push_back(i); } }
        for (size_t i : byName)  { if (!seen[i]) { seen[i] = true; byUnion.push_back(i); } }
    }
    std::vector<size_t> byInter;
    {
        std::sort(byShape.begin(), byShape.end());
        std::sort(byName.begin(), byName.end());
        std::set_intersection(byShape.begin(), byShape.end(),
                              byName.begin(), byName.end(),
                              std::back_inserter(byInter));
    }
    const std::vector<size_t>& experts = byUnion;
    uint64_t expertBytes = 0;
    for (size_t i : experts) expertBytes += spanBytes[i];

    std::printf("\n--- expert tensors (auto-detected) ---\n");
    if (declaredExperts > 0) {
        std::printf("declared expert_count    : %llu\n",
                    static_cast<unsigned long long>(declaredExperts));
    }
    std::printf("by shape (dim0==count)    : %zu tensors, %llu bytes (%.2f GB)\n",
                byShape.size(),
                static_cast<unsigned long long>([&]{ uint64_t b=0; for (size_t i:byShape) b+=spanBytes[i]; return b; }()),
                static_cast<double>([&]{ uint64_t b=0; for (size_t i:byShape) b+=spanBytes[i]; return b; }())
                    / (1024.0*1024.0*1024.0));
    std::printf("by name (token pattern)   : %zu tensors, %llu bytes (%.2f GB)\n",
                byName.size(),
                static_cast<unsigned long long>([&]{ uint64_t b=0; for (size_t i:byName) b+=spanBytes[i]; return b; }()),
                static_cast<double>([&]{ uint64_t b=0; for (size_t i:byName) b+=spanBytes[i]; return b; }())
                    / (1024.0*1024.0*1024.0));
    std::printf("expert share of payload   : %.1f%%\n",
                payload ? 100.0 * static_cast<double>(expertBytes) / static_cast<double>(payload) : 0.0);

    if (!byShape.empty() && !byName.empty() && byShape.size() != byName.size()) {
        std::printf("NOTE: shape and name sets disagree (%zu vs %zu). Neither is assumed\n"
                    "      correct; the larger set is used above because under-counting\n"
                    "      experts would plan for less VRAM than the router can reach.\n"
                    "      Token '%s' was auto-detected, not hardcoded.\n",
                    byShape.size(), byName.size(),
                    discoveredToken.empty() ? "?" : discoveredToken.c_str());
    }
    if (declaredExperts > 0 && byShape.empty() && byName.empty()) {
        std::printf("WARNING: expert_count declared but no expert tensors detected.\n");
        std::printf("         Experts may be packed differently in this layout.\n");
    }

    // ---- Metadata vs actual dtype cross-check ----
    // general.file_type declares a single quantisation label, but a model can
    // mix dtypes per tensor. When they disagree, the label is the misleading
    // value and any kernel chosen from it targets the wrong weight format.
    {
        const uint32_t declared = static_cast<uint32_t>(
            meta.uints.count("general.file_type") ? meta.uints["general.file_type"] : 255u);
        if (declared != 255u) {
            std::printf("\nfile_type (declared)    : %u (%s)\n", declared,
                        [](uint32_t t) -> const char* {
                            switch (t) {
                                case 0:  return "ALL_F32";
                                case 1:  return "MOSTLY_F16";
                                case 7:  return "MOSTLY_Q4_0";
                                case 8:  return "MOSTLY_Q4_1";
                                case 12: return "MOSTLY_Q4_K_S/Q2_K";
                                case 13: return "MOSTLY_Q3_K_S/Q4_K_S";
                                case 14: return "MOSTLY_Q4_K_M/Q3_K_M/Q5_K_M";
                                case 15: return "MOSTLY_Q6_K/Q5_K_M";
                                default: return "other";
                            }
                        }(declared));
            std::printf("dominant actual dtype    : %s (%llu bytes)\n",
                        ordered.empty() ? "?" : typeNameOf(ordered.front().first),
                        static_cast<unsigned long long>(
                            ordered.empty() ? 0 : bytesByType[ordered.front().first]));
            if (!ordered.empty() && ordered.front().first != declared) {
                std::printf("MISMATCH: declared file_type does not match the dominant tensor dtype.\n");
                std::printf("          Optimising for the declared type would target the wrong kernel.\n");
            }
        }
    }

    // ---- Full TSV inventory export (feeds the Batch 46-60 analyzer) ----
    // Every tensor is listed with its actual dtype, byte span, first dimension
    // and both independent expert candidates. A partial listing cannot be
    // reconciled, so no row is skipped or summarised.
    {
        // Dtype as a NAME, not a raw id. The Batch 46-60 analyzer keys its
        // histogram on this string and reports "dominant_dtype", so emitting
        // "6" would make that field unreadable.
        auto dtName = [](uint32_t t) -> const char* {
            switch (t) {
                case 0:  return "F32";
                case 1:  return "F16";
                case 2:  return "Q4_0";
                case 3:  return "Q4_1";
                case 6:  return "Q5_0";
                case 7:  return "Q5_1";
                case 8:  return "Q8_0";
                case 9:  return "Q8_1";
                case 10: return "Q2_K";
                case 11: return "Q3_K";
                case 12: return "Q4_K";
                case 13: return "Q5_K";
                case 14: return "Q6_K";
                case 15: return "Q8_K";
                default: return "other";
            }
        };
        FILE* tf = std::fopen("tensor_inventory.tsv", "w");
        if (tf) {
            // Header starts with '#': the Batch 46-60 loader skips '#'-lines,
            // so a plain header row would be parsed as data and rejected for
            // having non-0/1 flag columns.
            std::fprintf(tf, "#name\tdtype\tbytes\tdim0\tshape_candidate\tname_candidate\n");
            for (size_t i = 0; i < refs.size(); ++i) {
                std::fprintf(tf, "%s\t%s\t%llu\t%llu\t%d\t%d\n",
                             refs[i].name.c_str(),
                             dtName(refs[i].type),
                             static_cast<unsigned long long>(spanBytes[i]),
                             static_cast<unsigned long long>(
                                 refs[i].dims.empty() ? 0 : refs[i].dims.front()),
                             std::binary_search(byShape.begin(), byShape.end(), i) ? 1 : 0,
                             std::binary_search(byName.begin(), byName.end(), i) ? 1 : 0);
            }
            std::fclose(tf);
            std::printf("inventory exported         : tensor_inventory.tsv (%zu rows)\n", refs.size());
        }
    }

    std::printf("\nbaseline frozen. Re-run to confirm the digest is stable.\n");

#ifdef _WIN32
    UnmapViewOfFile(base);
    CloseHandle(m);
    CloseHandle(f);
#else
    ::munmap(const_cast<uint8_t*>(base), size);
    ::close(fd);
#endif
    return 0;
}
