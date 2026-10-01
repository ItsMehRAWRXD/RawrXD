// rawrxd_model_loader.cpp — RawrXDModelLoader implementation
// Used by: gguf_swarm_plan_builder.cpp, swarm_scheduler.cpp, main.cpp

#include "rawrxd_model_loader.h"

#include <windows.h>

// windows.h defines min/max as function-like macros that break std::min/max.
#undef min
#undef max

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <string>
#include <vector>

namespace RawrXD {

namespace {

// MapViewOfFile requires the file offset to be a multiple of the system
// allocation granularity, so every mapping is anchored at an aligned base and
// the caller's byte is returned as an offset into that base.
constexpr std::uint64_t kU64Max = (std::numeric_limits<std::uint64_t>::max)();

std::uint64_t SystemAllocationGranularity() {
    static const std::uint64_t g = []() -> std::uint64_t {
        SYSTEM_INFO si{};
        ::GetSystemInfo(&si);
        if (si.dwAllocationGranularity != 0)
            return static_cast<std::uint64_t>(si.dwAllocationGranularity);
        return 65536ull;
    }();
    return g;
}

std::uint64_t AlignDown(std::uint64_t v, std::uint64_t a) {
    return a == 0 ? v : (v / a) * a;
}

// RAWRXD_MODEL_LOADER_PREFETCH_001
//
// Mapping a view is lazy: the pages are not resident until something touches
// them. On a multi-gigabyte GGUF the first forward pass would otherwise fault
// in the entire weight span synchronously, which stalls the decode loop for
// seconds.
//
// This walks the mapped span with a volatile read per page instead of relying
// on an advisory prefetch API. PrefetchInformation is not declared by the
// Windows SDK this project builds against, and the documented
// SetFileInformationByHandle/FILE_WORKING_SET_INFORMATION route needs a file
// handle and only works on NTFS volumes -- neither is portable to the
// read-only view this loader holds. A per-page touch is slower than a single
// kernel-side hint but it is unconditional, works on any filesystem, and
// cannot fail.
//
// Best effort by design: this only changes WHEN pages fault in, never WHAT is
// read. If the loop is interrupted or the span is unbacked, the forward path
// still faults the pages on demand and correctness is unaffected.
void IssuePrefetch(void* base, std::size_t bytes) {
    if (!base || bytes == 0)
        return;

    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    const std::uintptr_t pageSize =
        si.dwPageSize != 0 ? si.dwPageSize : 4096u;

    // Bound the up-front cost: touching every page of a 38 GB model on the
    // loader thread would stall startup for longer than it saves. A bounded
    // warm-up of the first span is enough to overlap the header/tokenizer/embed
    // reads that immediately follow.
    constexpr std::uint64_t kMaxPrefetchBytes = 256ull * 1024ull * 1024ull;

    const std::size_t span =
        bytes > kMaxPrefetchBytes
            ? static_cast<std::size_t>(kMaxPrefetchBytes)
            : bytes;

    auto* p = reinterpret_cast<volatile unsigned char*>(base);
    volatile unsigned char sink = 0;

    for (std::size_t off = 0; off < span; off += static_cast<std::size_t>(pageSize)) {
        sink = p[off];
    }

    // Keep the touched value observable so the loop cannot be optimised out.
    (void)sink;
}

// Read `bytes` at absolute `offset`. The handle is synchronous, so the offset
// is moved with SetFilePointerEx and lpOverlapped stays NULL.
bool ReadExactAt(HANDLE file, std::uint64_t offset, void* dst, std::size_t bytes) {
    if (bytes == 0)
        return true;
    if (file == INVALID_HANDLE_VALUE || !dst)
        return false;

    LARGE_INTEGER li{};
    li.QuadPart = static_cast<LONGLONG>(offset);
    if (!::SetFilePointerEx(file, li, nullptr, FILE_BEGIN))
        return false;

    unsigned char* out = static_cast<unsigned char*>(dst);
    std::size_t done = 0;
    while (done < bytes) {
        const DWORD chunk = static_cast<DWORD>((bytes - done) < (1u << 20) ? (bytes - done) : (1u << 20));
        DWORD got = 0;
        if (!::ReadFile(file, out + done, chunk, &got, nullptr) || got == 0)
            return false;
        done += got;
    }
    return true;
}

std::uint32_t RdU32(const unsigned char* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t RdU64(const unsigned char* p) {
    return static_cast<std::uint64_t>(RdU32(p)) | (static_cast<std::uint64_t>(RdU32(p + 4)) << 32);
}

// ggml tensor type ids we size correctly. Anything else is reported as-is and
// the caller decides whether it supports it; we never guess a block size.
bool KnownGgmlType(std::uint32_t t) {
    switch (t) {
        case 0:   // F32
        case 1:   // F16
        case 2: case 3:      // Q4_0 Q4_1
        case 6: case 7:      // Q5_0 Q5_1
        case 8: case 9:      // Q8_0 Q8_1
        case 10: case 11: case 12: case 13: case 14: case 15:  // Q2_K..Q8_K
        case 24: case 25: case 26: case 27: case 28:          // I8..F64
        case 30:                                              // BF16
            return true;
        default:
            return false;
    }
}

// ggml type -> payload bytes per element. Block-quantized types return the
// whole super-block, so n_elements is derived as nelem / blockElems.
void GgmlGeometry(std::uint32_t t, std::uint64_t& blockElems, std::uint64_t& typeBytes) {
    switch (t) {
        case 0:  blockElems = 1;   typeBytes = 4;  return;  // F32
        case 1:  blockElems = 1;   typeBytes = 2;  return;  // F16
        case 2:  blockElems = 32;  typeBytes = 18; return;  // Q4_0
        case 3:  blockElems = 32;  typeBytes = 20; return;  // Q4_1
        case 6:  blockElems = 32;  typeBytes = 22; return;  // Q5_0
        case 7:  blockElems = 32;  typeBytes = 24; return;  // Q5_1
        case 8:  blockElems = 32;  typeBytes = 34; return;  // Q8_0
        case 9:  blockElems = 32;  typeBytes = 40; return;  // Q8_1 (f16 pairs + f32 scale)
        case 10: blockElems = 256; typeBytes = 84; return;  // Q2_K
        case 11: blockElems = 256; typeBytes = 110; return; // Q3_K
        case 12: blockElems = 256; typeBytes = 144; return; // Q4_K
        case 13: blockElems = 256; typeBytes = 176; return; // Q5_K
        case 14: blockElems = 256; typeBytes = 210; return; // Q6_K
        case 15: blockElems = 256; typeBytes = 292; return; // Q8_K
        case 24: blockElems = 1;   typeBytes = 1;  return;  // I8
        case 25: blockElems = 1;   typeBytes = 2;  return;  // I16
        case 26: blockElems = 1;   typeBytes = 4;  return;  // I32
        case 27: blockElems = 1;   typeBytes = 8;  return;  // I64
        case 28: blockElems = 1;   typeBytes = 8;  return;  // F64
        case 30: blockElems = 1;   typeBytes = 2;  return;  // BF16
        default:  blockElems = 1;  typeBytes = 0;  return;
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Impl
// ---------------------------------------------------------------------------

class RawrXDModelLoader::Impl {
public:
    static constexpr std::size_t kMaxComputeSlots = 3;

    struct ComputeSlot {
        void* view = nullptr;        // mapping base (granularity aligned)
        std::uint64_t viewOffset = 0;  // file offset of view base
        std::uint64_t viewSize = 0;    // mapped length
        std::uint64_t lastTouch = 0;
        std::uint32_t inUseCount = 0;
    };

    mutable std::mutex mutex;

    std::string path;
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = nullptr;
    std::uint64_t fileSize = 0;
    std::uint64_t dataSectionOffset = 0;
    std::vector<TensorFileSpan> spans;

    std::array<ComputeSlot, kMaxComputeSlots> slots{};
    std::uint64_t touchClock = 0;

    void* prefetchView = nullptr;
    std::uint64_t prefetchOffset = 0;
    std::uint64_t prefetchSize = 0;

    std::uint64_t pinBackoffCycles = 0;

    ~Impl() { teardownLocked(); }

    void unmapSlotLocked(std::size_t i) {
        ComputeSlot& s = slots[i];
        if (s.view) {
            ::UnmapViewOfFile(s.view);
            s.view = nullptr;
        }
        s.viewOffset = 0;
        s.viewSize = 0;
        s.inUseCount = 0;
    }

    void unmapPrefetchLocked() {
        if (prefetchView) {
            ::UnmapViewOfFile(prefetchView);
            prefetchView = nullptr;
        }
        prefetchOffset = 0;
        prefetchSize = 0;
    }

    void teardownLocked() {
        for (std::size_t i = 0; i < slots.size(); ++i)
            unmapSlotLocked(i);
        unmapPrefetchLocked();
        if (mapping) {
            ::CloseHandle(mapping);
            mapping = nullptr;
        }
        if (file != INVALID_HANDLE_VALUE) {
            ::CloseHandle(file);
            file = INVALID_HANDLE_VALUE;
        }
        fileSize = 0;
        dataSectionOffset = 0;
        spans.clear();
    }

    // Parse the GGUF tensor table by streaming from the file. Only the header,
    // metadata and tensor-info records are read; tensor payloads are never
    // touched here.
    bool parseTensorTableLocked() {
        spans.clear();
        dataSectionOffset = 0;

        unsigned char head[24];
        if (fileSize < sizeof(head) || !ReadExactAt(file, 0, head, sizeof(head)))
            return false;
        if (std::memcmp(head, "GGUF", 4) != 0)
            return false;

        const std::uint32_t version = RdU32(head + 4);
        if (version != 2 && version != 3)
            return false;
        const std::uint64_t tensorCount = RdU64(head + 8);
        const std::uint64_t kvCount = RdU64(head + 16);

        // A corrupt count must not turn into a multi-gigabyte allocation.
        if (tensorCount > (1u << 20) || kvCount > (1u << 20))
            return false;

        std::uint64_t pos = sizeof(head);

        // --- metadata: we only need general.alignment ---
        std::uint64_t alignment = 32;
        for (std::uint64_t i = 0; i < kvCount; ++i) {
            std::uint64_t len = 0;
            if (!readVarLen(pos, len)) return false;
            std::string key;
            key.resize(static_cast<std::size_t>(len));
            if (len && !ReadExactAt(file, pos, key.data(), static_cast<std::size_t>(len))) return false;
            pos += len;
            std::uint32_t type = 0;
            if (!ReadExactAt(file, pos, &type, 4)) return false;
            pos += 4;
            if (key == "general.alignment" && type == 4 /* uint32 */) {
                unsigned char v[4];
                if (!ReadExactAt(file, pos, v, 4)) return false;
                alignment = RdU32(v);
                pos += 4;
            } else if (!skipMetaValue(type, pos)) {
                return false;
            }
            if (alignment == 0) alignment = 32;
        }

        // --- tensor info records ---
        spans.reserve(static_cast<std::size_t>(tensorCount));
        for (std::uint64_t i = 0; i < tensorCount; ++i) {
            std::uint64_t len = 0;
            if (!readVarLen(pos, len)) return false;
            std::string name;
            name.resize(static_cast<std::size_t>(len));
            if (len && !ReadExactAt(file, pos, name.data(), static_cast<std::size_t>(len))) return false;
            pos += len;

            unsigned char nd[4];
            if (!ReadExactAt(file, pos, nd, 4)) return false;
            const std::uint32_t nDims = RdU32(nd);
            pos += 4;
            if (nDims > 4) return false;

            std::uint64_t nelem = 1;
            for (std::uint32_t d = 0; d < nDims; ++d) {
                unsigned char dim[8];
                if (!ReadExactAt(file, pos, dim, 8)) return false;
                const std::uint64_t v = RdU64(dim);
                pos += 8;
                if (v == 0 || nelem > kU64Max / v) return false;
                nelem *= v;
            }

            unsigned char typeBuf[4];
            if (!ReadExactAt(file, pos, typeBuf, 4)) return false;
            const std::uint32_t ggmlType = RdU32(typeBuf);
            pos += 4;

            unsigned char offBuf[8];
            if (!ReadExactAt(file, pos, offBuf, 8)) return false;
            const std::uint64_t relOffset = RdU64(offBuf);
            pos += 8;

            std::uint64_t blockElems = 1, typeBytes = 0;
            GgmlGeometry(ggmlType, blockElems, typeBytes);
            std::uint64_t payload = 0;
            if (typeBytes != 0 && nelem % blockElems == 0) {
                payload = (nelem / blockElems) * typeBytes;
            } else if (!KnownGgmlType(ggmlType)) {
                payload = 0;  // unknown encoding: report span but zero length
            } else {
                return false;  // known type whose geometry contradicts the shape
            }

            TensorFileSpan sp;
            sp.name = std::move(name);
            sp.ggmlType = ggmlType;
            sp.payloadBytes = payload;
            sp.fileOffset = relOffset;  // resolved against dataSectionOffset below
            sp.sizeBytes = payload;
            spans.push_back(std::move(sp));
        }

        const std::uint64_t pad = (alignment - (pos % alignment)) % alignment;
        dataSectionOffset = pos + pad;
        if (dataSectionOffset > fileSize)
            return false;

        for (TensorFileSpan& sp : spans) {
            if (sp.fileOffset > fileSize || sp.sizeBytes > fileSize - dataSectionOffset ||
                sp.fileOffset > fileSize - dataSectionOffset - sp.sizeBytes) {
                sp.sizeBytes = 0;  // out-of-range payload: expose name only
                continue;
            }
            sp.fileOffset += dataSectionOffset;
        }
        return true;
    }

private:
    bool readVarLen(std::uint64_t& pos, std::uint64_t& len) {
        unsigned char b[8];
        if (!ReadExactAt(file, pos, b, 8)) return false;
        len = RdU64(b);
        pos += 8;
        if (len > fileSize || len > (1u << 20))
            return false;
        return true;
    }

    bool skipBytes(std::uint64_t& pos, std::uint64_t n) {
        if (n > fileSize - pos)
            return false;
        pos += n;
        return true;
    }

    bool readVarStr(std::uint64_t& pos) {
        std::uint64_t len = 0;
        if (!readVarLen(pos, len)) return false;
        return skipBytes(pos, len);
    }

    bool skipMetaValue(std::uint32_t type, std::uint64_t& pos) {
        // GGUF metadata value tags (gguf_metadata_value_type):
        //   0 u8  1 i8  2 u16  3 i16  4 u32  5 i32  6 f32
        //   7 bool  8 string  9 array  10 u64  11 i64  12 f64
        switch (type) {
            case 0: case 1: case 7: return skipBytes(pos, 1);
            case 2: case 3:          return skipBytes(pos, 2);
            case 4: case 5: case 6:  return skipBytes(pos, 4);
            case 10: case 11: case 12: return skipBytes(pos, 8);
            case 8:  return readVarStr(pos);   // string
            case 9: {                           // array
                unsigned char t[4];
                if (!ReadExactAt(file, pos, t, 4)) return false;
                const std::uint32_t elem = RdU32(t);
                pos += 4;
                std::uint64_t count = 0;
                if (!readVarLen(pos, count)) return false;
                for (std::uint64_t i = 0; i < count; ++i) {
                    if (!skipMetaValue(elem, pos)) return false;
                }
                return true;
            }
            default:
                return false;  // unknown tag: cannot safely skip
        }
    }
};

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

RawrXDModelLoader::RawrXDModelLoader() : m_impl(new Impl()) {}

RawrXDModelLoader::~RawrXDModelLoader() {
    if (m_impl) {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        m_impl->teardownLocked();
    }
    delete m_impl;
    m_impl = nullptr;
}

bool RawrXDModelLoader::Open(const std::string& path) {
    if (!m_impl || path.empty())
        return false;

    HANDLE f = INVALID_HANDLE_VALUE;
    HANDLE m = nullptr;
    std::uint64_t size = 0;

    f = ::CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER li{};
    if (!::GetFileSizeEx(f, &li) || li.QuadPart <= 0) {
        ::CloseHandle(f);
        return false;
    }
    size = static_cast<std::uint64_t>(li.QuadPart);

    m = ::CreateFileMappingA(f, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!m) {
        ::CloseHandle(f);
        return false;
    }

    std::lock_guard<std::mutex> lock(m_impl->mutex);
    m_impl->teardownLocked();
    m_impl->path = path;
    m_impl->file = f;
    m_impl->mapping = m;
    m_impl->fileSize = size;

    if (!m_impl->parseTensorTableLocked()) {
        m_impl->teardownLocked();
        return false;
    }
    return true;
}

void RawrXDModelLoader::Close() {
    if (!m_impl)
        return;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    m_impl->teardownLocked();
}

bool RawrXDModelLoader::IsOpen() const {
    if (!m_impl)
        return false;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return m_impl->mapping != nullptr;
}

std::uint64_t RawrXDModelLoader::GetFileSizeBytes() const {
    if (!m_impl)
        return 0;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return m_impl->fileSize;
}

std::vector<TensorFileSpan> RawrXDModelLoader::listTensorFileSpans() const {
    if (!m_impl)
        return {};
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return m_impl->spans;
}

std::uint64_t RawrXDModelLoader::GetDataSectionOffset() const {
    if (!m_impl)
        return 0;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return m_impl->dataSectionOffset;
}

void* RawrXDModelLoader::MapWindow(std::uint64_t offset, std::size_t size) {
    if (!m_impl || size == 0)
        return nullptr;
    std::lock_guard<std::mutex> lock(m_impl->mutex);

    Impl& s = *m_impl;
    if (!s.mapping || s.fileSize == 0)
        return nullptr;
    if (offset > s.fileSize || static_cast<std::uint64_t>(size) > s.fileSize - offset)
        return nullptr;

    const std::uint64_t gran = SystemAllocationGranularity();
    const std::uint64_t mapBase = AlignDown(offset, gran);
    const std::uint64_t delta = offset - mapBase;
    std::uint64_t mapSize = static_cast<std::uint64_t>(size) + delta;
    if (mapSize > s.fileSize - mapBase)
        mapSize = s.fileSize - mapBase;

    // 1. covering hit in any slot
    for (auto& slot : s.slots) {
        if (!slot.view)
            continue;
        if (offset >= slot.viewOffset && mapBase <= slot.viewOffset) {
            const std::uint64_t end = offset + size;
            if (end <= slot.viewOffset + slot.viewSize) {
                slot.lastTouch = ++s.touchClock;
                return static_cast<unsigned char*>(slot.view) + (offset - slot.viewOffset);
            }
        }
    }

    // 2. exact reuse
    for (std::size_t i = 0; i < s.slots.size(); ++i) {
        Impl::ComputeSlot& slot = s.slots[i];
        if (slot.view && slot.viewOffset == mapBase && slot.viewSize >= mapSize) {
            slot.lastTouch = ++s.touchClock;
            return static_cast<unsigned char*>(slot.view) + delta;
        }
    }

    // 3. promote the prefetch view when it fully covers the request
    if (s.prefetchView && offset >= s.prefetchOffset &&
        offset + size <= s.prefetchOffset + s.prefetchSize) {
        for (std::size_t i = 0; i < s.slots.size(); ++i) {
            Impl::ComputeSlot& slot = s.slots[i];
            if (slot.view || slot.inUseCount > 0)
                continue;
            slot.view = s.prefetchView;
            slot.viewOffset = s.prefetchOffset;
            slot.viewSize = s.prefetchSize;
            slot.lastTouch = ++s.touchClock;
            s.prefetchView = nullptr;
            s.prefetchOffset = 0;
            s.prefetchSize = 0;
            return static_cast<unsigned char*>(slot.view) + (offset - slot.viewOffset);
        }
    }

    // 4. fresh map into a free or evictable slot
    std::size_t pick = s.slots.size();
    for (std::size_t i = 0; i < s.slots.size(); ++i) {
        if (!s.slots[i].view) {
            pick = i;
            break;
        }
    }
    if (pick == s.slots.size()) {
        std::uint64_t oldest = kU64Max;
        for (std::size_t i = 0; i < s.slots.size(); ++i) {
            if (s.slots[i].inUseCount > 0)
                continue;
            if (s.slots[i].lastTouch < oldest) {
                oldest = s.slots[i].lastTouch;
                pick = i;
            }
        }
        if (pick == s.slots.size()) {
            std::fprintf(stderr, "[RawrXDModelLoader] all compute slots pinned; refusing map off=%llu size=%zu\n",
                         static_cast<unsigned long long>(offset), size);
            return nullptr;
        }
    }

    void* view = ::MapViewOfFile(s.mapping, FILE_MAP_READ,
                                 static_cast<DWORD>(mapBase >> 32),
                                 static_cast<DWORD>(mapBase & 0xFFFFFFFFu),
                                 static_cast<SIZE_T>(mapSize));
    if (!view)
        return nullptr;

    s.unmapSlotLocked(pick);
    Impl::ComputeSlot& slot = s.slots[pick];
    slot.view = view;
    slot.viewOffset = mapBase;
    slot.viewSize = mapSize;
    slot.lastTouch = ++s.touchClock;
    return static_cast<unsigned char*>(view) + delta;
}

void RawrXDModelLoader::UnmapWindow() {
    if (!m_impl)
        return;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    for (std::size_t i = 0; i < m_impl->slots.size(); ++i)
        m_impl->unmapSlotLocked(i);
}

std::size_t RawrXDModelLoader::ComputeSlotCount() const {
    if (!m_impl)
        return 0;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    std::size_t n = 0;
    for (const auto& slot : m_impl->slots)
        if (slot.view)
            ++n;
    return n;
}

void* RawrXDModelLoader::MapPrefetchWindow(std::uint64_t offset, std::size_t size) {
    if (!m_impl || size == 0)
        return nullptr;
    std::lock_guard<std::mutex> lock(m_impl->mutex);

    Impl& s = *m_impl;
    if (!s.mapping)
        return nullptr;
    if (offset > s.fileSize || static_cast<std::uint64_t>(size) > s.fileSize - offset)
        return nullptr;

    const std::uint64_t gran = SystemAllocationGranularity();
    const std::uint64_t mapBase = AlignDown(offset, gran);
    const std::uint64_t delta = offset - mapBase;
    std::uint64_t mapSize = static_cast<std::uint64_t>(size) + delta;
    if (mapSize > s.fileSize - mapBase)
        mapSize = s.fileSize - mapBase;

    if (s.prefetchView && offset >= s.prefetchOffset &&
        offset + size <= s.prefetchOffset + s.prefetchSize) {
        return static_cast<unsigned char*>(s.prefetchView) + (offset - s.prefetchOffset);
    }

    void* view = ::MapViewOfFile(s.mapping, FILE_MAP_READ,
                                 static_cast<DWORD>(mapBase >> 32),
                                 static_cast<DWORD>(mapBase & 0xFFFFFFFFu),
                                 static_cast<SIZE_T>(mapSize));
    if (!view)
        return nullptr;

    s.unmapPrefetchLocked();
    s.prefetchView = view;
    s.prefetchOffset = mapBase;
    s.prefetchSize = mapSize;

    // Mapping alone is lazy: the pages are not resident until touched, so a
    // "prefetch" view that is never faulted in prefetches nothing. Issue an
    // explicit read-ahead over the whole span now.
    IssuePrefetch(view, mapSize);

    return static_cast<unsigned char*>(view) + delta;
}

void RawrXDModelLoader::UnmapPrefetchWindow() {
    if (!m_impl)
        return;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    m_impl->unmapPrefetchLocked();
}

void RawrXDModelLoader::markComputeRangeInUse(std::uint64_t offset, std::uint64_t size) {
    if (!m_impl || size == 0)
        return;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    Impl& s = *m_impl;
    for (auto& slot : s.slots) {
        if (!slot.view || offset < slot.viewOffset)
            continue;
        if (offset + size <= slot.viewOffset + slot.viewSize) {
            ++slot.inUseCount;
            return;
        }
    }
}

void RawrXDModelLoader::unmarkComputeRangeInUse(std::uint64_t offset, std::uint64_t size) {
    if (!m_impl || size == 0)
        return;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    Impl& s = *m_impl;
    for (auto& slot : s.slots) {
        if (!slot.view || offset < slot.viewOffset)
            continue;
        if (offset + size <= slot.viewOffset + slot.viewSize) {
            if (slot.inUseCount > 0)
                --slot.inUseCount;
            return;
        }
    }
}

bool RawrXDModelLoader::ComputeMappingCovers(std::uint64_t offset, std::uint64_t size) const {
    if (!m_impl || size == 0)
        return false;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    const std::uint64_t end = offset + size;
    if (end < offset)
        return false;
    for (const auto& slot : m_impl->slots) {
        if (!slot.view || offset < slot.viewOffset)
            continue;
        if (end <= slot.viewOffset + slot.viewSize)
            return true;
    }
    return false;
}

bool RawrXDModelLoader::HasActivePrefetchMapping() const {
    if (!m_impl)
        return false;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return m_impl->prefetchView != nullptr;
}

void RawrXDModelLoader::recordSwarmPinBackoffCycle() {
    if (!m_impl)
        return;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    ++m_impl->pinBackoffCycles;
}

std::uint64_t RawrXDModelLoader::GetSwarmPinBackoffCycles() const {
    if (!m_impl)
        return 0;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return m_impl->pinBackoffCycles;
}

}  // namespace RawrXD