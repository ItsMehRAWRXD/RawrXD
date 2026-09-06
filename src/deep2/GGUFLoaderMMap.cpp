// ============================================================================
// GGUFLoaderMMap.cpp — additive zero-copy GGUF tensor access
// ============================================================================
#include "GGUFLoaderMMap.hpp"
#include <cstdio>
#include <cstring>
#include <limits>

namespace Deep2 {
namespace {

static bool CheckedAddU64(uint64_t a, uint64_t b, uint64_t& out) {
    if (a > (std::numeric_limits<uint64_t>::max)() - b) return false;
    out = a + b;
    return true;
}

} // namespace

GGUFMMapResult LoadGGUFMMap(const char* filepath, bool verbose) {
    GGUFMMapResult r;
    if (!filepath || filepath[0] == '\0') {
        r.error = "empty path";
        return r;
    }

    // 1) Parse header/metadata/tensor-info via existing FILE* parser.
    //    loadTensors=false → no fread of tensor payloads.
    GGUFLoadOptions opts;
    opts.loadTensors = false;
    opts.verbose = verbose;
    const GGUFLoadResult parsed = GGUFLoader::Load(filepath, opts);
    if (!parsed.success) {
        r.error = parsed.error[0] ? std::string(parsed.error) : "GGUF parse failed";
        return r;
    }
    r.metadata = parsed.metadata;
    r.dataOffset = parsed.dataOffset;

    // 2) Memory-map the shard so tensor data pointers are zero-copy.
    auto mapping = std::make_shared<MemoryMappedFile>();
    if (!mapping->Map(filepath)) {
        r.error = "memory map failed: " + mapping->error;
        return r;
    }
    r.mapping = mapping;
    r.fileSize = mapping->fileSize;

    // 3) Build tensor list with data pointers into the mapping.
    r.tensors.reserve(parsed.tensors.size());
    for (const auto& t : parsed.tensors) {
        TensorInfo info = t;
        if (t.size == 0) {
            info.data = nullptr;
        } else {
            uint64_t absOff = 0;
            if (!CheckedAddU64(r.dataOffset, t.offset, absOff)) {
                r.error = "tensor '" + t.name + "' offset overflow";
                return r;
            }
            if (absOff > mapping->fileSize || t.size > (mapping->fileSize - absOff)) {
                r.error = "tensor '" + t.name + "' out of mapping bounds";
                return r;
            }
            info.data = const_cast<uint8_t*>(mapping->data + absOff);
        }
        r.tensors.push_back(std::move(info));
    }

    if (verbose) {
        std::printf("[GGUFMMap] mapped %llu bytes, %zu tensors, dataOffset=%llu\n",
                    static_cast<unsigned long long>(r.fileSize),
                    r.tensors.size(),
                    static_cast<unsigned long long>(r.dataOffset));
    }
    r.success = true;
    return r;
}

bool GGUFMMapResult::PrefetchRangeFromDataOffset(uint64_t relativeOffset, uint64_t size) const {
    if (!success || !mapping) return false;
    uint64_t absOff = 0;
    if (!CheckedAddU64(dataOffset, relativeOffset, absOff)) return false;
    return mapping->Prefetch(absOff, size);
}

bool GGUFMMapResult::PrefetchTensor(const char* name) const {
    if (!name || name[0] == '\0') return false;
    const TensorInfo* t = GetTensor(name);
    if (!t) return false;
    if (t->size == 0) return true;
    return PrefetchRangeFromDataOffset(t->offset, t->size);
}

uint64_t GGUFMMapTotalTensorBytes(const GGUFMMapResult& r) {
    uint64_t total = 0;
    for (const auto& t : r.tensors) {
        if (t.size == 0 || !t.data) continue;
        // Touch the first byte of each tensor to prove pointer access works.
        volatile uint8_t b = static_cast<const volatile uint8_t*>(t.data)[0];
        (void)b;
        total += t.size;
    }
    return total;
}

} // namespace Deep2
