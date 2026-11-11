// deep2_rom_manifest.cpp - runtime tensor manifest with exact binding.
// RAWRXD_DEEP2_RUNTIME_TENSOR_MANIFEST_001
//
// The runtime authority. Opens a GGUF through RawrXDGgufReader, emits canonical
// tensor descriptors carrying the file's own name, dtype, dims, absolute offset
// and byte count, validates every descriptor against Deep2::QuantTypeTable and
// against the file bounds, and fails closed on any tensor that does not bind.
//
// This replaces the static model-specific TensorROM table as the authority.
// It also detects the class of bug where a static table declares one dtype
// while its own byte count encodes another, by recomputing the bytes from the
// dtype and comparing.
#include "RawrXDGgufReader.hpp"
#include "QuantTypeTable.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

using namespace rawrxd;

namespace {

// Recompute encoded bytes from a dtype and element count, using only the
// canonical table. Used to cross-check a declared byte count.
bool BytesFromTable(int32_t type, uint64_t elements, uint64_t& out) {
    const Deep2::QuantTypeDescriptor* d = Deep2::LookupQuantType(type);
    if (!d) return false;
    const uint64_t be = d->blockElements;
    const uint64_t bb = d->blockBytes;
    if (be == 0 || bb == 0) return false;
    if (elements % be != 0) return false;
    const uint64_t blocks = elements / be;
    if (blocks > (uint64_t)-1 / bb) return false;
    out = blocks * bb;
    return true;
}

} // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 2) {
        printf("usage: deep2_rom_manifest <model.gguf> [--json out.json]\n");
        return 2;
    }
    const char* path = argv[1];
    const char* jsonPath = argc > 3 && std::string(argv[2]) == "--json" ? argv[3] : nullptr;

    GgufReader r;
    if (!r.Open(path)) {
        printf("OPEN_FAIL %s : %s\n", path, r.why().c_str());
        return 1;
    }

    printf("FILE    %s\n", path);
    printf("ARCH    %s\n", r.architecture().c_str());
    printf("GGUF    version %u, %llu tensors, data start %llu, %llu bytes\n",
           r.version(), (unsigned long long)r.tensorCount(),
           (unsigned long long)r.dataStart(), (unsigned long long)r.fileSize());

    // ---- build the runtime manifest with exact binding ----
    struct Entry {
        std::string      name;
        std::string      dtypeName;
        int32_t          dtype;
        std::vector<uint64_t> dims;
        uint64_t         absOffset;
        uint64_t         bytes;
        bool             bound;
        std::string      reason;
    };
    std::vector<Entry> manifest;
    manifest.reserve(r.tensorCount());

    int bound = 0;
    int unbound = 0;
    int dtypeInconsistent = 0;
    int unknownDtype = 0;
    std::map<std::string, int> dtypeCensus;

    for (const auto& kv : r.tensors()) {
        const GgufTensor& t = kv.second;
        Entry e;
        e.name = t.name;
        e.dtype = t.type;
        e.dtypeName = Deep2::QuantTypeName(static_cast<uint32_t>(t.type));
        for (int64_t d : t.dims) e.dims.push_back(static_cast<uint64_t>(d));
        e.absOffset = t.abs_offset;
        e.bytes = t.nbytes;
        e.bound = true;

        // 1. dtype must be known to the canonical table
        const Deep2::QuantTypeDescriptor* q = Deep2::LookupQuantType(t.type);
        if (!q) {
            e.bound = false;
            e.reason = "unknown ggml type id";
            ++unknownDtype;
        } else {
            dtypeCensus[e.dtypeName] += 1;

            // 2. byte count must be derivable from the table
            uint64_t expect = 0;
            if (!BytesFromTable(t.type, (uint64_t)t.nelements(), expect)) {
                e.bound = false;
                e.reason = "element count is not a whole number of blocks";
                ++unbound;
            } else {
                // 3. reported bytes must equal the table-derived bytes.
                //    A mismatch here is the signature of a static table that
                //    declares one dtype while encoding another.
                if (expect != t.nbytes) {
                    e.bound = false;
                    e.reason = "byte count disagrees with dtype geometry";
                    ++dtypeInconsistent;
                }
            }

            // 4. range must lie inside the file
            if (e.bound &&
                (t.abs_offset + t.nbytes > r.fileSize())) {
                e.bound = false;
                e.reason = "range past end of file";
                ++unbound;
            }
        }

        if (e.bound) ++bound;
        else if (e.reason == "byte count disagrees with dtype geometry") {
            // already counted
        } else if (e.reason != "unknown ggml type id" &&
                   e.reason != "element count is not a whole number of blocks" &&
                   e.reason != "range past end of file") {
            ++unbound;
        }

        manifest.push_back(e);
    }

    printf("\nMANIFEST  entries=%zu bound=%d unbound=%d\n",
           manifest.size(), bound, unbound + unknownDtype + dtypeInconsistent);
    printf("DTYPE_CROSSCHECK inconsistent=%d unknown=%d\n",
           dtypeInconsistent, unknownDtype);
    printf("DTYPES");
    for (const auto& kv : dtypeCensus)
        printf(" %s=%d", kv.first.c_str(), kv.second);
    printf("\n");

    if (unbound + unknownDtype + dtypeInconsistent > 0) {
        printf("\nFIRST_UNBOUND\n");
        int shown = 0;
        for (const Entry& e : manifest) {
            if (e.bound) continue;
            printf("  %-40s dtype=%-8s ne=[", e.name.c_str(), e.dtypeName.c_str());
            for (size_t i = 0; i < e.dims.size(); ++i)
                printf("%s%llu", i ? "," : "", (unsigned long long)e.dims[i]);
            printf("] off=%llu bytes=%llu  %s\n",
                   (unsigned long long)e.absOffset, (unsigned long long)e.bytes,
                   e.reason.c_str());
            if (++shown >= 10) break;
        }
    }

    const bool ok = (bound == (int)manifest.size());
    printf("\nVERDICT=%s\n", ok ? "BOUND_ALL" : "INCOMPLETE_BINDING");

    if (jsonPath) {
        // Minimal JSON, written directly to avoid a dependency.
        FILE* f = fopen(jsonPath, "wb");
        if (f) {
            fprintf(f, "{\n  \"file\": \"%s\",\n  \"arch\": \"%s\",\n  \"tensors\": [\n", path,
                    r.architecture().c_str());
            for (size_t i = 0; i < manifest.size(); ++i) {
                const Entry& e = manifest[i];
                fprintf(f, "    {\"name\":\"%s\",\"dtype\":\"%s\",\"dtype_id\":%d,\"dims\":[",
                        e.name.c_str(), e.dtypeName.c_str(), e.dtype);
                for (size_t j = 0; j < e.dims.size(); ++j)
                    fprintf(f, "%s%llu", j ? "," : "", (unsigned long long)e.dims[j]);
                fprintf(f, "],\"offset\":%llu,\"bytes\":%llu,\"bound\":%s,\"reason\":\"%s\"}%s\n",
                        (unsigned long long)e.absOffset, (unsigned long long)e.bytes,
                        e.bound ? "true" : "false", e.reason.c_str(),
                        i + 1 < manifest.size() ? "," : "");
            }
            fprintf(f, "  ]\n}\n");
            fclose(f);
            printf("wrote %s\n", jsonPath);
        }
    }
    return ok ? 0 : 1;
}
