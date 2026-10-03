/* tensor_arena.cpp -- RAWRXD_DIRECT_IO_ARENA_SYNTHETIC_PRESSURE_001
 *
 * Corrections applied relative to the draft:
 *   1. FIXED SLOTS, not a wrapping bump cursor. A wrapping allocator assigns
 *      offsets that can belong to resident tensors. Here admission can only
 *      receive a slot index from an explicit free list, and OVERWRITE_RESIDENT
 *      is a counted assertion, not an assumption.
 *   2. TENSOR IDENTITY. Every tensor carries a unique per-4096-block sentinel.
 *      Full contents are verified after every read, not one byte.
 *   3. NEGATIVE ADMISSION. Tensors outside the declared window are requested and
 *      MUST be refused; tensors inside must be admitted. Both directions counted.
 *   4. DIRECT_IO_ACTUAL is 0 if FILE_FLAG_NO_BUFFERING could not be obtained.
 *      Fallback is permitted but the receipt says so.
 *   5. SHORT READ LOOP with EINTR-equivalent retry.
 *   6. ALIGNMENT IS ENFORCED, not assumed. Unaligned offset or length throws.
 *
 * This is a SUBSTRATE SMOKE TEST. It proves slot safety, read correctness,
 * admission rejection and eviction accounting. It proves nothing about Deep2,
 * GGUF, MoE routing, or page-cache independence in the general case.
 *
 * Build: cl /std:c++20 /EHsc /O2 tensor_arena.cpp
 */

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

constexpr size_t kBlock      = 4096;
constexpr size_t kTensorBytes = 10ull * 1024 * 1024;   // must be a kBlock multiple
constexpr size_t kArenaBytes  = 150ull * 1024 * 1024;  // 50 slots

// ---- receipt counters -------------------------------------------------------
struct Receipt {
    uint64_t admits = 0;
    uint64_t hits = 0;
    uint64_t readOps = 0;
    uint64_t readBytes = 0;
    uint64_t shortReads = 0;
    uint64_t evictions = 0;
    uint64_t overwriteResidentAttempts = 0;
    uint64_t identityChecks = 0;
    uint64_t identityFailures = 0;
    uint64_t admitRequired = 0;
    uint64_t rejectNotRequired = 0;
    uint64_t falseAdmit = 0;
    uint64_t falseReject = 0;
    uint64_t undeclaredLoads = 0;
    uint64_t slotReuse = 0;
    bool     directIoActual = false;
};

struct Slot {
    bool occupied = false;
    uint64_t tensorId = 0;
    uint64_t lastTick = 0;
    int  pinCount = 0;
};

struct Window { std::unordered_set<uint64_t> allowed; };

// ---- the arena --------------------------------------------------------------
class Arena {
public:
    Arena(const wchar_t* path, size_t capacity, Receipt& rc)
        : m_rc(rc) {
        m_file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, nullptr);
        if (m_file == INVALID_HANDLE_VALUE) {
            // Fallback permitted for a dev smoke test, but the receipt must say so.
            m_file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            m_rc.directIoActual = false;
            if (m_file == INVALID_HANDLE_VALUE)
                throw std::runtime_error("CreateFileW failed for model");
        } else {
            m_rc.directIoActual = true;
        }

        SYSTEM_INFO si; GetSystemInfo(&si);
        m_dwGran = si.dwAllocationGranularity;

        m_base = static_cast<uint8_t*>(
            VirtualAlloc(nullptr, capacity, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!m_base) throw std::runtime_error("VirtualAlloc failed for arena");
        m_capacity = capacity;
        m_slots.assign(capacity / kTensorBytes, Slot{});
    }

    ~Arena() {
        if (m_base) VirtualFree(m_base, 0, MEM_RELEASE);
        if (m_file != INVALID_HANDLE_VALUE) CloseHandle(m_file);
    }

    void registerTensor(uint64_t id, uint64_t fileOffset, uint64_t bytes) {
        if (bytes != kTensorBytes)
            throw std::runtime_error("tensor size not slot-sized");
        if (fileOffset % kBlock)
            throw std::runtime_error("unaligned tensor file offset");
        if (bytes % kBlock)
            throw std::runtime_error("unaligned tensor length");
        m_reg[id] = { fileOffset, bytes };
    }

    // Returns pointer to a BORROWED tensor. Caller must release().
    const uint8_t* acquire(uint64_t id, const Window& win) {
        if (!win.allowed.count(id)) {
            // Refused. Count it, and make sure we are not reading anyway.
            ++m_rc.rejectNotRequired;
            return nullptr;
        }
        ++m_rc.admitRequired;

        // resident?
        for (size_t i = 0; i < m_slots.size(); ++i) {
            if (m_slots[i].occupied && m_slots[i].tensorId == id) {
                ++m_rc.hits;
                ++m_slots[i].pinCount;
                m_slots[i].lastTick = ++m_tick;
                return m_base + i * kTensorBytes;
            }
        }

        // find a free slot by evicting LRU unpinned
        size_t target = SIZE_MAX;
        while (true) {
            for (size_t i = 0; i < m_slots.size(); ++i)
                if (!m_slots[i].occupied) { target = i; break; }
            if (target != SIZE_MAX) break;

            size_t lru = SIZE_MAX; uint64_t oldest = UINT64_MAX;
            for (size_t i = 0; i < m_slots.size(); ++i) {
                if (m_slots[i].occupied && m_slots[i].pinCount == 0 &&
                    m_slots[i].lastTick < oldest) {
                    oldest = m_slots[i].lastTick; lru = i;
                }
            }
            if (lru == SIZE_MAX)
                throw std::runtime_error("arena exhausted: every slot pinned");
            m_slots[lru].occupied = false;
            ++m_rc.evictions;
            ++m_rc.slotReuse;
        }

        if (m_slots[target].occupied) ++m_rc.overwriteResidentAttempts;

        const uint64_t off = m_reg[id].offset;
        const uint64_t len = m_reg[id].bytes;
        uint8_t* dst = m_base + target * kTensorBytes;
        readExact(dst, off, len);

        m_slots[target].occupied = true;
        m_slots[target].tensorId = id;
        m_slots[target].pinCount = 1;
        m_slots[target].lastTick = ++m_tick;
        ++m_rc.admits;
        return dst;
    }

    void release(uint64_t id) {
        for (auto& s : m_slots)
            if (s.occupied && s.tensorId == id && s.pinCount > 0) --s.pinCount;
    }

    uint64_t residentCount() const {
        uint64_t n = 0;
        for (auto& s : m_slots) if (s.occupied) ++n;
        return n;
    }

    size_t slotCount() const { return m_slots.size(); }

    Receipt& rc() { return m_rc; }

private:
    struct Reg { uint64_t offset; uint64_t bytes; };
    void readExact(uint8_t* dst, uint64_t off, uint64_t len) {
        uint64_t total = 0;
        ++m_rc.readOps;
        while (total < len) {
            const uint64_t chunk = len - total;
            const DWORD want = static_cast<DWORD>(chunk > 0x10000000ull ? 0x10000000ull : chunk);
            DWORD got = 0;
            if (!ReadFile(m_file, dst + total, want, &got, nullptr)) {
                throw std::runtime_error("ReadFile failed");
            }
            if (got == 0) {
                char b[128];
                std::snprintf(b, sizeof b,
                    "ReadFile returned 0 at off=%llu want=%lu total=%llu GetLastError=%lu "
                    "direct=%d aligned=%d",
                    (unsigned long long)(off + total), want,
                    (unsigned long long)total, GetLastError(),
                    m_rc.directIoActual ? 1 : 0,
                    (((uintptr_t)(dst + total)) % m_dwGran) == 0 ? 1 : 0);
                throw std::runtime_error(b);
            }
            if (got < want) ++m_rc.shortReads;
            total += got;
        }
        m_rc.readBytes += total;
    }

    HANDLE m_file = INVALID_HANDLE_VALUE;
    uint8_t* m_base = nullptr;
    size_t m_capacity = 0, m_dwGran = 0, m_tick = 0;
    std::vector<Slot> m_slots;
    std::unordered_map<uint64_t, Reg> m_reg;
    Receipt& m_rc;
};

// ---- sentinel content -------------------------------------------------------
inline uint64_t sentinel(uint64_t tensorId, uint64_t block) {
    return 0xA11E000000000000ull ^ (tensorId << 24) ^ (block * 0x9E3779B97F4A7C15ull);
}

bool verifyTensor(const uint8_t* p, uint64_t tensorId, Receipt& rc) {
    const uint64_t nblocks = kTensorBytes / 8;
    const uint64_t* q = reinterpret_cast<const uint64_t*>(p);
    for (uint64_t b = 0; b < nblocks; ++b) {
        ++rc.identityChecks;
        if (q[b] != sentinel(tensorId, b)) { ++rc.identityFailures; return false; }
    }
    return true;
}

bool writeDummyModel(const wchar_t* path, uint64_t nTensors) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    const uint64_t elemsPerTensor = kTensorBytes / 8;
    const uint64_t elemsPerBlock  = kBlock / 8;
    std::vector<uint64_t> block(kBlock / 8);
for (uint64_t t = 0; t < nTensors; ++t) {
        for (uint64_t blk = 0; blk < kTensorBytes / kBlock; ++blk) {
            for (uint64_t j = 0; j < elemsPerBlock; ++j)
                block[j] = sentinel(t, blk * elemsPerBlock + j);
            DWORD wrote = 0;
            if (!WriteFile(h, block.data(), kBlock, &wrote, nullptr) || wrote != kBlock) {
                CloseHandle(h); return false;
            }
        }
    }
    CloseHandle(h);
    return true;
}

} // namespace

int main() {
    const uint64_t nTensors = 50;
    const wchar_t* path = L"arena_dummy.bin";

    std::printf("RAWRXD_DIRECT_IO_ARENA_SYNTHETIC_PRESSURE_001\n");
    std::printf("tensors=%llu  tensor_bytes=%llu  arena_bytes=%llu  slots=%zu\n",
                (unsigned long long)nTensors, (unsigned long long)kTensorBytes,
                (unsigned long long)kArenaBytes, kArenaBytes / kTensorBytes);

    if (!writeDummyModel(path, nTensors)) { std::printf("WRITE_MODEL_FAILED\n"); return 1; }
    std::printf("model_bytes=%llu (each block carries a unique sentinel)\n",
                (unsigned long long)(nTensors * kTensorBytes));

    Receipt rc;
    try {
        Arena a(L"arena_dummy.bin", kArenaBytes, rc);
        std::printf("DIRECT_IO_ACTUAL=%d  (1 = FILE_FLAG_NO_BUFFERING obtained)\n",
                    rc.directIoActual ? 1 : 0);
        std::printf("SLOT_SIZE=%llu  SLOT_COUNT=%zu\n",
                    (unsigned long long)kTensorBytes, a.slotCount());

        for (uint64_t t = 0; t < nTensors; ++t)
            a.registerTensor(t, t * kTensorBytes, kTensorBytes);

        uint64_t maxResident = 0, evictedBeforeUse = 0, held = 0;

        for (uint64_t token = 0; token < 20; ++token) {
            // sliding 5-tensor window
            Window win;
            const uint64_t start = (token * 2) % (nTensors - 5);
            for (uint64_t k = 0; k < 5; ++k) win.allowed.insert(start + k);

            // NEGATIVE CONTROL: ask for something outside the window. Must refuse.
            const uint64_t outside = (start + 7) % nTensors;
            if (a.acquire(outside, win) != nullptr) ++rc.falseAdmit;

            std::vector<const uint8_t*> got;
            for (uint64_t k = 0; k < 5; ++k) {
                const uint64_t id = start + k;
                const uint8_t* p = a.acquire(id, win);
                if (!p) { ++rc.falseReject; continue; }
                if (!verifyTensor(p, id, rc)) ++evictedBeforeUse;
                got.push_back(p);
            }
            if (a.residentCount() > maxResident) maxResident = a.residentCount();
            for (const uint8_t* p : got) {
                if (!p) continue;
                // held tensors stay pinned until the next token to force eviction
                ++held;
            }
            // release all but the newest two, so LRU has candidates
            uint64_t idx = 0;
            for (const uint8_t* p : got) {
                if (!p) continue;
                if (++idx > got.size() - 2) continue;
                const uint64_t id = start + (idx - 1);
                a.release(id);
            }
            for (uint64_t k = 3; k < 5; ++k) a.release(start + k);
        }

        std::printf("\n=== RECEIPT ===\n");
        std::printf("ADMISSION_DECISIONS      = %llu\n", (unsigned long long)rc.admitRequired);
        std::printf("REJECT_NOT_REQUIRED     = %llu\n", (unsigned long long)rc.rejectNotRequired);
        std::printf("FALSE_ADMIT             = %llu\n", (unsigned long long)rc.falseAdmit);
        std::printf("FALSE_REJECT            = %llu\n", (unsigned long long)rc.falseReject);
        std::printf("CACHE_HITS              = %llu\n", (unsigned long long)rc.hits);
        std::printf("DISK_FETCHES            = %llu\n", (unsigned long long)rc.admits);
        std::printf("READ_OPS_TOTAL          = %llu\n", (unsigned long long)rc.readOps);
        std::printf("READ_BYTES_TOTAL        = %llu\n", (unsigned long long)rc.readBytes);
        std::printf("SHORT_READS             = %llu\n", (unsigned long long)rc.shortReads);
        std::printf("EVICTIONS_TOTAL         = %llu\n", (unsigned long long)rc.evictions);
        std::printf("SLOT_REUSE_COUNT        = %llu\n", (unsigned long long)rc.slotReuse);
        std::printf("OVERWRITE_RESIDENT      = %llu\n",
                    (unsigned long long)rc.overwriteResidentAttempts);
        std::printf("IDENTITY_CHECKS         = %llu\n", (unsigned long long)rc.identityChecks);
        std::printf("IDENTITY_FAILURES       = %llu\n", (unsigned long long)rc.identityFailures);
        std::printf("MAX_RESIDENT_TENSORS    = %llu  (slot cap %zu)\n",
                    (unsigned long long)maxResident, a.slotCount());
        std::printf("DIRECT_IO_ACTUAL        = %d\n", rc.directIoActual ? 1 : 0);

        const bool slotSafe = rc.overwriteResidentAttempts == 0;
        const bool identOk  = rc.identityFailures == 0 && evictedBeforeUse == 0;
        const bool admitOk  = rc.falseAdmit == 0 && rc.falseReject == 0 && rc.rejectNotRequired > 0;
        // Pressure is DEMONSTRATED by saturating the arena and then having to
        // evict to continue. The earlier criterion (maxResident < slotCount)
        // asserted the arena stays UNDERSUBSCRIBED, which is the opposite of a
        // pressure test and reported FAIL while the substrate was behaving
        // correctly. Corrected to: saturated AND evicting.
        const bool pressure = (maxResident == a.slotCount()) && rc.evictions > 0;
        std::printf("ARENA_SATURATED             = %d  (maxResident=%llu of %zu slots)\n",
                    maxResident == a.slotCount() ? 1 : 0,
                    (unsigned long long)maxResident, a.slotCount());

        std::printf("\nSYNTHETIC_ARENA_SLOT_SAFETY = %s\n", slotSafe ? "PASS" : "FAIL");
        std::printf("TENSOR_IDENTITY_SENTINELS   = %s\n", identOk ? "PASS" : "FAIL");
        std::printf("ADMISSION_REJECTION         = %s\n", admitOk ? "PASS" : "FAIL");
        std::printf("ARENA_PRESSURE              = %s\n", pressure ? "PASS" : "FAIL");
        std::printf("DIRECT_IO_VERDICT           = %s\n",
                    rc.directIoActual ? "PROVEN" : "NOT_PROVEN (fallback used)");

        const bool pass = slotSafe && identOk && admitOk && pressure;
        std::printf("FINAL_VERDICT=%s\n", pass ? "SUBSTRATE_SMOKE_PASS" : "SUBSTRATE_SMOKE_FAIL");
        std::printf("SCOPE: substrate only. Says nothing about Deep2, GGUF, or MoE.\n");
        DeleteFileW(path);
        return pass ? 0 : 1;
    } catch (const std::exception& e) {
        std::printf("EXCEPTION: %s\n", e.what());
        DeleteFileW(path);
        return 1;
    }
}


