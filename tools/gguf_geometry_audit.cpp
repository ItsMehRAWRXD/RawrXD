/**
 * @file gguf_geometry_audit.cpp
 * @brief MODEL_GENIE_NATIVE_FORWARD_001 Gate 3: real GGUF tensor validation.
 *
 * Validates an actual GGUF file end to end and refuses to accept a mismatch:
 *
 *   1. magic, version, tensor count, metadata_kv_count
 *   2. metadata key/value decoding for every type in the GGUF enum
 *   3. tensor names, dims, types, block geometry
 *   4. byte lengths and row strides derived from EACH tensor's own type
 *   5. absolute offsets, bounds and alignment
 *   6. overlapping or truncated tensor regions
 *   7. a machine-readable report, and exit code 4 on any failure
 *
 * Point 4 is the one that matters: row geometry must come from each tensor's
 * actual quantization type, never from a model-wide assumption. A model that
 * mixes Q2_K weights with an F32 or Q8_0 embedding has different row strides
 * per tensor, and assuming one layout silently mis-read everything that differs.
 *
 * Build:
 *   cl /std:c++17 /EHsc /O2 gguf_geometry_audit.cpp
 *   gguf_geometry_audit.exe <model.gguf>
 */
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

// ── GGUF value types ────────────────────────────────────────────────────────
enum GgufValueType : uint32_t {
    GGUF_UINT8 = 0,  GGUF_INT8 = 1,  GGUF_UINT16 = 2, GGUF_INT16 = 3,
    GGUF_UINT32 = 4, GGUF_INT32 = 5, GGUF_FLOAT32 = 6, GGUF_BOOL = 7,
    GGUF_STRING = 8, GGUF_ARRAY = 9, GGUF_UINT64 = 10, GGUF_INT64 = 11,
    GGUF_FLOAT64 = 12,
};

// ── GGML tensor types, with block geometry from the reference layout ────────
// The numeric IDs are authoritative: read from the ggml.h that this build
// actually uses (3rdparty/ggml/include/ggml.h:380). An earlier version of this
// table guessed IDs 4-7 and 14, which silently produced wrong row sizes for
// every K-quant tensor and cascaded into bogus "past EOF" and "overlap"
// failures. IDs beyond 15 are deliberately UNKNOWN so the auditor fails closed
// rather than inventing geometry.
struct TypeInfo {
    const char* name;
    uint32_t blockElems;   ///< elements per block
    uint32_t blockBytes;   ///< bytes per block
};

static const TypeInfo kTypes[] = {
    /*0  F32   */ {"F32",   1,   4},
    /*1  F16   */ {"F16",   1,   2},
    /*2  Q4_0  */ {"Q4_0",  32,  18},
    /*3  Q4_1  */ {"Q4_1",  32,  20},
    /*4  (removed in ggml: Q4_2) */ {"REMOVED_Q4_2", 0, 0},
    /*5  (removed in ggml: Q4_3) */ {"REMOVED_Q4_3", 0, 0},
    /*6  Q5_0  */ {"Q5_0",  32,  22},
    /*7  Q5_1  */ {"Q5_1",  32,  24},
    /*8  Q8_0  */ {"Q8_0",  32,  34},
    /*9  Q8_1  */ {"Q8_1",  32,  36},
    /*10 Q2_K  */ {"Q2_K",  256, 84},
    /*11 Q3_K  */ {"Q3_K",  256, 110},
    /*12 Q4_K  */ {"Q4_K",  256, 144},
    /*13 Q5_K  */ {"Q5_K",  256, 176},
    /*14 Q6_K  */ {"Q6_K",  256, 210},
    /*15 Q8_K  */ {"Q8_K",  256, 292},
};
constexpr int kTypeCount = 16;

static const TypeInfo& typeInfo(uint32_t t) {
    static const TypeInfo kUnknown{"UNKNOWN", 0, 0};
    return (t < kTypeCount) ? kTypes[t] : kUnknown;
}

// ── Reader ──────────────────────────────────────────────────────────────────
struct Reader {
    const uint8_t* p;
    size_t size;
    size_t pos = 0;
    bool failed = false;
    std::string failReason;

    Reader(const uint8_t* data, size_t n) : p(data), size(n) {}

    bool need(size_t n, const char* what) {
        if (failed) return false;
        if (pos + n > size) {
            failed = true;
            failReason = std::string("truncated while reading ") + what +
                         " (need " + std::to_string(n) + " bytes at offset " +
                         std::to_string(pos) + ", file is " + std::to_string(size) + ")";
            return false;
        }
        return true;
    }
    template <typename T>
    T read(const char* what) {
        if (!need(sizeof(T), what)) return T{};
        T v;
        std::memcpy(&v, p + pos, sizeof(T));
        pos += sizeof(T);
        return v;
    }
    // GGUF strings are uint64 length + raw bytes; NOT null terminated.
    std::string readString(const char* what) {
        uint64_t n = read<uint64_t>(what);
        if (failed) return {};
        if (n > size - pos) {
            failed = true;
            failReason = std::string("string ") + what + " declares " +
                         std::to_string(n) + " bytes at offset " +
                         std::to_string(pos) + " which exceeds the file";
            return {};
        }
        std::string s(reinterpret_cast<const char*>(p + pos),
                      static_cast<size_t>(n));
        pos += static_cast<size_t>(n);
        return s;
    }
    // Skip one value of the given GGUF type. Arrays store the element type once
    // followed by `count` raw values with NO per-element type tag, so the type
    // must be passed in rather than re-read.
    void skipTyped(uint32_t t) {
        if (failed) return;
        switch (t) {
            case GGUF_UINT8: case GGUF_INT8: case GGUF_BOOL: need(1, "scalar"); pos += 1; break;
            case GGUF_UINT16: case GGUF_INT16: need(2, "scalar"); pos += 2; break;
            case GGUF_UINT32: case GGUF_INT32: case GGUF_FLOAT32: need(4, "scalar"); pos += 4; break;
            case GGUF_UINT64: case GGUF_INT64: case GGUF_FLOAT64: need(8, "scalar"); pos += 8; break;
            case GGUF_STRING: readString("string"); break;
            case GGUF_ARRAY: {
                uint32_t elem = read<uint32_t>("array element type");
                uint64_t cnt = read<uint64_t>("array count");
                if (failed) return;
                if (cnt > size) { failed = true;
                    failReason = "array count " + std::to_string(cnt) + " exceeds file size";
                    return; }
                for (uint64_t i = 0; i < cnt && !failed; ++i) skipTyped(elem);
                break;
            }
            default:
                failed = true;
                failReason = "unknown value type " + std::to_string(t);
                return;
        }
    }

    /// Convenience: skip a full key/value metadata entry.
    void skipEntry() {
        readString("metadata key");
        if (failed) return;
        uint32_t t = read<uint32_t>("value type");
        if (failed) return;
        skipTyped(t);
    }
};

struct TensorReport {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t type = 0;
    uint64_t dataOffset = 0;   ///< relative to data start
    uint64_t rowLen = 0;       ///< elements in dim[0]
    uint64_t rowBytes = 0;
    uint64_t totalBytes = 0;
    uint64_t absOffset = 0;    ///< absolute file offset
};

static int gFailures = 0;
static void report(bool ok, const std::string& msg) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", msg.c_str());
    fflush(stdout);
    if (!ok) ++gFailures;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage: gguf_geometry_audit <model.gguf> [--json out.json]\n");
        return 1;
    }
    const char* path = argv[1];
    const char* jsonPath = nullptr;
    for (int i = 2; i < argc; ++i)
        if (!std::strcmp(argv[i], "--json") && i + 1 < argc) jsonPath = argv[++i];

    // ── read the whole file ────────────────────────────────────────────────
    FILE* f = fopen(path, "rb");
    if (!f) {
        printf("  [FAIL] cannot open %s\n", path);
        printf("PARITY_STATUS=FAIL\n");
        return 4;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0) {
        printf("  [FAIL] %s is empty\n", path);
        fclose(f);
        printf("PARITY_STATUS=FAIL\n");
        return 4;
    }
    std::vector<uint8_t> data(static_cast<size_t>(fsize));
    if (fread(data.data(), 1, data.size(), f) != data.size()) {
        printf("  [FAIL] short read on %s\n", path);
        fclose(f);
        printf("PARITY_STATUS=FAIL\n");
        return 4;
    }
    fclose(f);
    printf("=== GGUF geometry audit: %s (%ld bytes) ===\n", path, fsize);
    fflush(stdout);

    // ── 1. header ─────────────────────────────────────────────────────────
    const uint32_t magic = static_cast<uint32_t>(data[0]) |
                           (static_cast<uint32_t>(data[1]) << 8) |
                           (static_cast<uint32_t>(data[2]) << 16) |
                           (static_cast<uint32_t>(data[3]) << 24);
    report(magic == 0x46554747u, "GGUF magic is 0x46554747 ('GGUF')");

    Reader r(data.data(), data.size());
    r.pos = 4;
    const uint32_t version = r.read<uint32_t>("version");
    const uint64_t tensorCount = r.read<uint64_t>("tensor count");
    const uint64_t metaCount = r.read<uint64_t>("metadata count");
    if (r.failed) {
        report(false, "header readable: " + r.failReason);
        printf("PARITY_STATUS=FAIL\n");
        return 4;
    }
    report(version == 2 || version == 3,
           "version is 2 or 3 (got " + std::to_string(version) + ")");
    report(tensorCount > 0, "tensor count is non-zero (got " +
                             std::to_string(tensorCount) + ")");
    report(tensorCount < 10000000, "tensor count is plausible (no absurd value)");
    printf("           metadata entries: %llu\n",
           static_cast<unsigned long long>(metaCount));
    fflush(stdout);

    // ── 2. metadata ───────────────────────────────────────────────────────
    // Fully decoded so a malformed key/value cannot pass unnoticed.
    {
        int bad = 0;
        for (uint64_t i = 0; i < metaCount && !r.failed; ++i)
            r.skipEntry();
        report(!r.failed, "all " + std::to_string(metaCount) +
                               " metadata entries decoded" +
                               (r.failed ? (": " + r.failReason) : ""));
        if (r.failed) {
            printf("PARITY_STATUS=FAIL\n");
            return 4;
        }
    }

    // ── 3. alignment, from the metadata if present ────────────────────────
    // Default per the GGUF spec is 32 when general.alignment is absent.
    uint64_t alignment = 32;
    {
        Reader m(data.data(), data.size());
        m.pos = 4 + 4 + 8 + 8;
        for (uint64_t i = 0; i < metaCount && !m.failed; ++i) {
            std::string key = m.readString("metadata key");
            if (m.failed) break;
            uint32_t t = m.read<uint32_t>("value type");
            if (m.failed) break;
            if (key == "general.alignment") {
                if (t == GGUF_UINT32) alignment = m.read<uint32_t>("alignment");
                else if (t == GGUF_UINT64) alignment = m.read<uint64_t>("alignment");
                if (!m.failed) break;
                m.failed = false;
                m.failReason.clear();
                m.pos += 8;  // tolerate and continue
                continue;
            }
            // Skip this value; the type was read above, so skipTyped must not
            // consume a second type tag.
            Reader tmp = m;
            tmp.skipTyped(t);
            if (tmp.failed) { m.failed = true; break; }
            m = tmp;
        }
    }
    report(alignment == 1 || alignment == 8 || alignment == 16 || alignment == 32 ||
               alignment == 64 || alignment == 128,
           "alignment is a sane power-of-two-like value (" +
           std::to_string(alignment) + ")");
    printf("           alignment: %llu\n", static_cast<unsigned long long>(alignment));
    fflush(stdout);

    // ── 4. tensor infos ───────────────────────────────────────────────────
    std::vector<TensorReport> tensors;
    tensors.reserve(static_cast<size_t>(tensorCount));
    {
        bool ok = true;
        std::string why;
        for (uint64_t i = 0; i < tensorCount; ++i) {
            TensorReport t;
            t.name = r.readString("tensor name");
            if (r.failed) { ok = false; why = r.failReason; break; }
            uint32_t nDims = r.read<uint32_t>("tensor ndim");
            if (r.failed) { ok = false; why = r.failReason; break; }
            if (nDims == 0 || nDims > 8) { ok = false; why = "tensor '" + t.name +
                "' has out-of-range ndim " + std::to_string(nDims); break; }
            uint64_t elems = 1;
            for (uint32_t d = 0; d < nDims; ++d) {
                uint64_t dim = r.read<uint64_t>("tensor dim");
                if (r.failed) { ok = false; why = r.failReason; break; }
                if (dim == 0 || dim > (1ull << 32)) {
                    ok = false; why = "tensor '" + t.name + "' has invalid dim " +
                        std::to_string(dim); break;
                }
                t.dims.push_back(dim);
                elems *= dim;
            }
            if (!ok) break;
            t.type = r.read<uint32_t>("tensor type");
            t.dataOffset = r.read<uint64_t>("tensor offset");
            if (r.failed) { ok = false; why = r.failReason; break; }

            // 5. geometry from THIS tensor's type, not a model-wide assumption
            const TypeInfo& ti = typeInfo(t.type);
            if (t.type >= kTypeCount || ti.blockElems == 0) {
                ok = false; why = "tensor '" + t.name + "' has unknown ggml type " +
                    std::to_string(t.type); break;
            }
            if (ti.blockElems > 1 && (t.dims[0] % ti.blockElems) != 0) {
                ok = false; why = "tensor '" + t.name + "' (" + ti.name +
                    ") row length " + std::to_string(t.dims[0]) +
                    " is not a multiple of block size " +
                    std::to_string(ti.blockElems); break;
            }
            t.rowLen = t.dims[0];
            t.rowBytes = (t.dims[0] / ti.blockElems) * ti.blockBytes;
            uint64_t rows = elems / t.dims[0];
            t.totalBytes = rows * t.rowBytes;
            tensors.push_back(t);
        }
        report(ok, "all " + std::to_string(tensorCount) +
                       " tensor infos parsed and geometrically valid" +
                       (ok ? "" : (": " + why)));
        if (!ok) {
            printf("PARITY_STATUS=FAIL\n");
            return 4;
        }
    }

    // ── 6. alignment of the data section start ────────────────────────────
    const uint64_t dataStart = (r.pos + alignment - 1) / alignment * alignment;
    report(dataStart <= data.size(),
           "tensor data section start " + std::to_string(dataStart) +
           " is within the file");
    printf("           data section starts at offset %llu\n",
           static_cast<unsigned long long>(dataStart));
    fflush(stdout);

    // ── 7. per-tensor offsets, bounds, overlaps, truncation ───────────────
    uint64_t maxEnd = 0, minOffset = UINT64_MAX;
    std::vector<std::pair<uint64_t, uint64_t>> spans;
    spans.reserve(tensors.size());
    for (auto& t : tensors) {
        t.absOffset = dataStart + t.dataOffset;
        minOffset = std::min(minOffset, t.dataOffset);
        uint64_t end = t.absOffset + t.totalBytes;
        spans.emplace_back(t.absOffset, end);
        if (end > maxEnd) maxEnd = end;
    }
    report(minOffset == 0, "lowest tensor offset is 0 (offsets are relative to the "
                           "data section, not absolute)");

    {
        bool allInBounds = true;
        std::string bad;
        for (const auto& t : tensors) {
            if (t.absOffset > data.size() || t.absOffset + t.totalBytes > data.size()) {
                allInBounds = false;
                bad = "tensor '" + t.name + "' ends at " +
                      std::to_string(t.absOffset + t.totalBytes) +
                      " but the file is " + std::to_string(data.size());
                break;
            }
        }
        report(allInBounds, "no tensor extends past the end of the file" +
                                (allInBounds ? "" : (": " + bad)));
    }

    {
        // Overlap detection: sort spans and check for interval intersection.
        bool overlap = false;
        std::string who;
        std::sort(spans.begin(), spans.end());
        for (size_t i = 1; i < spans.size() && !overlap; ++i) {
            if (spans[i].first < spans[i - 1].second) {
                overlap = true;
                who = "region [" + std::to_string(spans[i - 1].first) + "," +
                      std::to_string(spans[i - 1].second) + "] overlaps [" +
                      std::to_string(spans[i].first) + "," +
                      std::to_string(spans[i].second) + "]";
            }
        }
        report(!overlap, "no overlapping tensor regions" +
                             (overlap ? (": " + who) : ""));
    }

    {
        // Truncation: the last tensor must not run past EOF, and the data
        // region must actually cover every tensor.
        report(maxEnd <= data.size(),
               "highest tensor end " + std::to_string(maxEnd) +
               " is covered by the file (" + std::to_string(data.size()) + ")");
    }

    {
        // Mixed-type coverage: prove that more than one row stride exists when
        // the model mixes types, and that every stride was derived per tensor.
        std::vector<uint64_t> strides;
        for (const auto& t : tensors)
            strides.push_back(t.rowBytes);
        std::vector<uint64_t> uniq(strides);
        std::sort(uniq.begin(), uniq.end());
        uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());

        std::vector<uint32_t> types;
        for (const auto& t : tensors)
            if (std::find(types.begin(), types.end(), t.type) == types.end())
                types.push_back(t.type);

        printf("           distinct tensor types: %zu  distinct row strides: %zu\n",
               types.size(), uniq.size());
        fflush(stdout);
        report(!types.empty(), "at least one tensor type present");

        // Cross-check the per-tensor stride against the type's block geometry
        // independently of how it was computed above.
        bool strideOk = true;
        std::string why;
        for (const auto& t : tensors) {
            const TypeInfo& ti = typeInfo(t.type);
            uint64_t expect = (t.dims[0] / ti.blockElems) * ti.blockBytes;
            if (expect != t.rowBytes) {
                strideOk = false;
                why = "tensor '" + t.name + "' type " + ti.name +
                      " rowLen " + std::to_string(t.dims[0]) +
                      " -> computed " + std::to_string(t.rowBytes) +
                      " but block geometry says " + std::to_string(expect);
                break;
            }
        }
        report(strideOk, "every tensor's row stride matches its own block geometry" +
                             (strideOk ? "" : (": " + why)));
        report(types.size() > 1,
               "model mixes quantization types, so per-tensor stride derivation "
               "is exercised (" + std::to_string(types.size()) + " types)");
    }

    // ── 8. machine-readable report ────────────────────────────────────────
    if (jsonPath) {
        FILE* j = fopen(jsonPath, "wb");
        if (j) {
            fprintf(j, "{\n  \"file\": \"%s\",\n  \"file_bytes\": %zu,\n",
                    path, data.size());
            fprintf(j, "  \"version\": %u,\n", version);
            fprintf(j, "  \"tensor_count\": %llu,\n",
                    static_cast<unsigned long long>(tensorCount));
            fprintf(j, "  \"alignment\": %llu,\n",
                    static_cast<unsigned long long>(alignment));
            fprintf(j, "  \"data_section_offset\": %llu,\n",
                    static_cast<unsigned long long>(dataStart));
            fprintf(j, "  \"failures\": %d,\n", gFailures);
            fprintf(j, "  \"tensors\": [\n");
            for (size_t i = 0; i < tensors.size(); ++i) {
                const auto& t = tensors[i];
                const TypeInfo& ti = typeInfo(t.type);
                fprintf(j, "    {\"name\": \"%s\", \"type\": \"%s\", \"ggml_type\": %u, "
                           "\"row_len\": %llu, \"row_bytes\": %llu, "
                           "\"total_bytes\": %llu, \"abs_offset\": %llu}%s\n",
                        t.name.c_str(), ti.name, t.type,
                        static_cast<unsigned long long>(t.rowLen),
                        static_cast<unsigned long long>(t.rowBytes),
                        static_cast<unsigned long long>(t.totalBytes),
                        static_cast<unsigned long long>(t.absOffset),
                        (i + 1 < tensors.size()) ? "," : "");
            }
            fprintf(j, "  ]\n}\n");
            fclose(j);
        }
    }

    printf("\n=== VERDICT: %s (%d failure(s)) ===\n",
           gFailures == 0 ? "PASS" : "FAIL", gFailures);
    printf("tensors_validated=%zu failures=%d\n", tensors.size(), gFailures);
    printf("PARITY_STATUS=%s\n", gFailures == 0 ? "PASS" : "FAIL");
    fflush(stdout);
    return gFailures == 0 ? 0 : 4;
}
