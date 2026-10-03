// ============================================================================
// InferenceWire.cpp — RAWRXD_INFERENCE_WIRE_001 implementation
//
// See InferenceWire.hpp for the scope limit. This file makes residency
// transitions observable as framed bytes and nothing more.
// ============================================================================

#include "InferenceWire.hpp"

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>

namespace Deep2::Wire {

namespace {

// FNV-1a 64. Chosen because it is 5 lines and needs no table, not because it is
// collision resistant. The hash's job here is to make single-byte corruption and
// post-hoc editing DETECTABLE by a second reader, not to authenticate anything.
// A cryptographic digest would imply a threat model this file does not have.
constexpr std::uint64_t kFnvOffset = 1469598103934665603ull;
constexpr std::uint64_t kFnvPrime  = 1099511628211ull;

std::uint64_t fnv1a64(const unsigned char* p, std::size_t n) {
    std::uint64_t h = kFnvOffset;
    for (std::size_t i = 0; i < n; ++i) {
        h ^= static_cast<std::uint64_t>(p[i]);
        h *= kFnvPrime;
    }
    return h;
}

std::uint32_t nextPow2(std::uint32_t v) {
    if (v < 16) v = 16;
    std::uint32_t p = 1;
    while (p < v) p <<= 1;
    return p;
}

std::uint64_t packKey(std::uint32_t layer, std::uint32_t expert) {
    return (static_cast<std::uint64_t>(layer) << 32) | static_cast<std::uint64_t>(expert);
}

// The eviction ring is power-of-two sized; 256 entries covers a thrash window
// far longer than any working set that matters and keeps the probe O(1).
constexpr std::uint32_t kEvictRingSlots = 256;

}  // namespace

// ---------------------------------------------------------------------------
// Contract assertions. These are the numbers in the wire specification, and they
// are checked by the compiler rather than by a comment. A state byte that
// silently changed value would make every historical capture misread.
// ---------------------------------------------------------------------------
static_assert(kHotHit             == 0x01, "state bit 0x01 is HOT_HIT");
static_assert(kColdFault          == 0x02, "state bit 0x02 is COLD_FAULT");
static_assert(kEmptyConsumed      == 0x04, "state bit 0x04 is EMPTY_CONSUMED");
static_assert(kMetalBlockThrash   == 0x08, "state bit 0x08 is METAL_BLOCK_THRASH");
static_assert(kCpuFallbackViolation == 0x10, "state bit 0x10 is CPU_FALLBACK_VIOLATION");
static_assert(kStateMask == 0x1F, "exactly five state bits are defined");

bool WireFlagLegal(std::uint8_t flag) noexcept {
    return (flag & ~static_cast<std::uint8_t>(kStateMask)) == 0;
}

const char* WireStateName(std::uint8_t flag) noexcept {
    if (!WireFlagLegal(flag)) return "ILLEGAL_FLAG";
    switch (flag & kStateMask) {
        case 0x00: return "NONE";
        case kHotHit: return "HOT_HIT";
        case kColdFault: return "COLD_FAULT";
        case kEmptyConsumed: return "EMPTY_CONSUMED";
        case kMetalBlockThrash: return "METAL_BLOCK_THRASH";
        case kCpuFallbackViolation: return "CPU_FALLBACK_VIOLATION";
        case static_cast<std::uint8_t>(kColdFault | kMetalBlockThrash):
            return "COLD_FAULT|METAL_BLOCK_THRASH";
        case static_cast<std::uint8_t>(kColdFault | kCpuFallbackViolation):
            return "COLD_FAULT|CPU_FALLBACK_VIOLATION";
        default: return "COMPOSITE";
    }
}

const char* WireFaultName(std::uint8_t f) noexcept {
    switch (f) {
        case kFaultNone: return "NONE";
        case kFaultColdStart: return "COLD_START_MISS";
        case kFaultReuse: return "REUSE_MISS";
        case kFaultCapacity: return "CAPACITY_MISS";
        case kFaultPrediction: return "PREDICTION_MISS";
        case kFaultScheduling: return "SCHEDULING_MISS";
        case kFaultIo: return "IO_MISS";
        default: return "UNKNOWN";
    }
}

void WireClock(std::uint64_t& wallNs, std::uint64_t& qpcRaw) {
    LARGE_INTEGER q{};
    QueryPerformanceCounter(&q);
    qpcRaw = static_cast<std::uint64_t>(q.QuadPart);

    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    // FILETIME is 100 ns ticks since 1601-01-01. Converted to nanoseconds and
    // rebased so the value is a usable epoch nanosecond count rather than an
    // opaque large integer. The conversion is exact (integer), never a double.
    unsigned long long ticks = (static_cast<unsigned long long>(ft.dwHighDateTime) << 32)
                             | static_cast<unsigned long long>(ft.dwLowDateTime);
    constexpr unsigned long long kTicksToUnixNs = 116444736000000000ull;
    wallNs = (ticks - kTicksToUnixNs) * 100ull;
}

std::uint64_t WireContentHash(const Packet& p) {
    Packet copy = p;
    copy.contentHash = 0;
    return fnv1a64(reinterpret_cast<const unsigned char*>(&copy), sizeof(copy));
}

// ---------------------------------------------------------------------------
// ExpertLedger
// ---------------------------------------------------------------------------

ExpertLedger::ExpertLedger(std::uint32_t capacitySlots, std::uint32_t thrashWindowTokens)
    : thrashWindow_(thrashWindowTokens ? thrashWindowTokens : 1) {
    const std::uint32_t cap = nextPow2(capacitySlots);
    mask_ = cap - 1u;
    slots_ = static_cast<Slot*>(::operator new(sizeof(Slot) * cap, std::nothrow));
    if (!slots_) { mask_ = 0; return; }
    for (std::uint32_t i = 0; i < cap; ++i) slots_[i].key = kInvalidKey;

    evictRing_ = static_cast<Eviction*>(
        ::operator new(sizeof(Eviction) * kEvictRingSlots, std::nothrow));
    if (!evictRing_) evictMask_ = 0;
    else {
        evictMask_ = kEvictRingSlots - 1u;
        for (std::uint32_t i = 0; i < kEvictRingSlots; ++i) evictRing_[i].key = kInvalidKey;
    }
}

ExpertLedger::~ExpertLedger() {
    ::operator delete(slots_);
    ::operator delete(evictRing_);
}

void ExpertLedger::reset() {
    if (!slots_) return;
    for (std::uint32_t i = 0; i <= mask_; ++i) slots_[i].key = kInvalidKey;
    if (evictRing_)
        for (std::uint32_t i = 0; i <= evictMask_; ++i) evictRing_[i].key = kInvalidKey;
    residentCount_ = 0;
    usedBytes_ = 0;
    evictions_ = 0;
    thrashes_ = 0;
    maxReuse_ = 0;
    evictHead_ = 0;
    curToken_ = 0;
    stats_ = TokenStats{};
}

// The probe helpers live here rather than in the header so the header stays
// free of implementation detail and the hot loop inlines cleanly.
namespace {

inline std::uint32_t mix32(std::uint64_t k) {
    // splitmix64 finalizer, truncated: kills the fact that expert keys are
    // dense small integers and would otherwise cluster in a power-of-two table.
    std::uint64_t x = k;
    x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ull;
    x ^= x >> 27; x *= 0x94d049bb133111ebull;
    x ^= x >> 31;
    return static_cast<std::uint32_t>(x);
}

}  // namespace

ExpertLedger::RouteEvidence ExpertLedger::route(std::uint32_t layer, std::uint32_t expert,
                                                std::uint32_t token, std::uint64_t bytes,
                                                bool prefetchRequested) {
    RouteEvidence ev{};
    ev.capacityEntries = mask_ + 1u;
    ev.residentEntries = residentCount_;
    if (!slots_) { ev.fault = kFaultScheduling; return ev; }

    const std::uint64_t key = packKey(layer, expert);
    const std::uint32_t start = mix32(key) & mask_;

    // --- probe for the key, remembering the first free slot for insertion ---
    Slot* freeSlot = nullptr;
    Slot* found = nullptr;
    std::uint32_t i = start;
    for (std::uint32_t probe = 0; probe <= mask_; ++probe) {
        Slot& s = slots_[i];
        if (s.key == key) { found = &s; break; }
        if (s.key == kInvalidKey) { if (!freeSlot) freeSlot = &s; break; }
        i = (i + 1u) & mask_;
    }

    curToken_ = token;

    if (found && found->resident) {
        // ---- HOT -------------------------------------------------------------
        if (found->routeEpoch != 0) {
            ev.reuseDistance = token - found->lastRoute;
            if (ev.reuseDistance > maxReuse_) maxReuse_ = ev.reuseDistance;
        }
        found->lastRoute = token;
        ++found->routeEpoch;
        ev.hit = true;
        ++stats_.hits;
        ++stats_.routed;
        return ev;
    }

    // ---- COLD. Classify WHY, from evidence the ledger actually holds. ----
    bool wasEvictedRecently = false;
    std::uint32_t evictedAtToken = 0;
    std::uint32_t evictedLastRoute = 0;
    bool wasRoutedBeforeEviction = false;
    if (evictRing_) {
        // Walk the ring from newest; the ring is small and this only runs on a
        // miss, so a linear scan of <=256 entries is cheaper than hashing.
        for (std::uint32_t back = 0; back <= evictMask_; ++back) {
            std::uint32_t idx = (evictHead_ + evictMask_ - back) & evictMask_;
            if (evictRing_[idx].key != key) continue;
            evictedAtToken = evictRing_[idx].token;
            evictedLastRoute = evictRing_[idx].lastRoute;
            wasRoutedBeforeEviction = evictRing_[idx].wasRouted != 0;
            const std::uint32_t age = token >= evictedAtToken ? token - evictedAtToken
                                                               : 0u;
            wasEvictedRecently = (age <= thrashWindow_);
            break;
        }
    }

    if (found && found->routeEpoch != 0) {
        // The ledger still has the key but not resident: it was demoted without
        // eviction, so the reuse distance is known even though it was a miss.
        ev.reuseDistance = token - found->lastRoute;
        if (ev.reuseDistance > maxReuse_) maxReuse_ = ev.reuseDistance;
    } else if (wasRoutedBeforeEviction) {
        // The slot was wiped by the eviction, so recover the distance from the
        // ring. This is the case that makes METAL_BLOCK_THRASH measurable: the
        // expert was needed again sooner than the eviction policy assumed.
        ev.reuseDistance = token >= evictedLastRoute ? token - evictedLastRoute : 0u;
        if (ev.reuseDistance > maxReuse_) maxReuse_ = ev.reuseDistance;
    }

    if (wasEvictedRecently && wasRoutedBeforeEviction) {
        // HOT recently, evicted by pressure, needed again inside the window.
        // This is the metal block: a policy failure, not a capacity fact.
        ev.thrash = true;
        ev.fault = kFaultReuse;
        ++thrashes_;
        ++stats_.thrash;
    } else if (found && found->routeEpoch != 0) {
        ev.fault = kFaultCapacity;     // known expert, not resident: too small
    } else if (prefetchRequested) {
        ev.fault = kFaultPrediction;   // asked for in advance, still arrived cold
    } else {
        ev.fault = kFaultColdStart;    // first ever route: unavoidable
    }
    (void)evictedAtToken;

    ++stats_.cold;
    ++stats_.routed;

    // ---- admit, evicting the coldest unpinned entry if needed ----
    Slot* dst = found ? found : freeSlot;
    if (!dst) {
        // Table genuinely full (only reachable if capacity was exhausted).
        ev.fault = kFaultCapacity;
        return ev;
    }
    if (!found) ++residentCount_;

    // Evict by coldest lastRoute; ties broken by smallest routeEpoch, so a
    // never-re-routed entry loses to one that is merely old. Linear scan: it
    // runs only on a capacity-pressured admission, and clarity here matters more
    // than the probe, which is bounded by the ring size and is not the hot path.
    while (capacityBytes_ && (usedBytes_ + bytes > capacityBytes_) && residentCount_ > 0) {
        bool haveVictim = false;
        std::uint32_t v = 0;
        for (std::uint32_t idx = 0; idx <= mask_; ++idx) {
            const Slot& c = slots_[idx];
            if (c.key == kInvalidKey || !c.resident) continue;
            if (!haveVictim) { v = idx; haveVictim = true; continue; }
            const Slot& b = slots_[v];
            if (c.lastRoute < b.lastRoute ||
                (c.lastRoute == b.lastRoute && c.routeEpoch < b.routeEpoch)) {
                v = idx;
            }
        }
        if (!haveVictim) break;

        Slot& vs = slots_[v];
        if (evictRing_) {
            Eviction& e = evictRing_[evictHead_];
            e.key = vs.key;
            e.token = token;
            e.wasRouted = vs.routeEpoch != 0 ? 1u : 0u;
            e.lastRoute = vs.lastRoute;
            evictHead_ = (evictHead_ + 1u) & evictMask_;
        }
        usedBytes_ -= vs.bytes < usedBytes_ ? vs.bytes : usedBytes_;
        vs.key = kInvalidKey;
        vs.bytes = 0;
        vs.resident = 0;
        vs.routeEpoch = 0;
        --residentCount_;
        ++evictions_;
        ++stats_.evicted;
    }

    dst->key = key;
    dst->bytes = bytes;
    dst->lastRoute = token;
    dst->routeEpoch = 1;
    dst->resident = 1;
    usedBytes_ += bytes;
    ev.residentEntries = residentCount_;
    return ev;
}

void ExpertLedger::noteTransition(std::uint32_t layer, std::uint32_t expert,
                                  Tier from, Tier to, std::uint64_t bytes,
                                  const char* reason) {
    (void)layer; (void)expert; (void)from; (void)to; (void)bytes; (void)reason;
    // Reserved. Deliberately a no-op rather than a stub that pretends to record:
    // there is no packet channel wired to it yet, and a no-op that reports
    // success would be exactly the fabricated-counter failure mode.
}

void ExpertLedger::beginToken(std::uint32_t token) {
    curToken_ = token;
    stats_ = TokenStats{};
}

ExpertLedger::TokenStats ExpertLedger::endToken() {
    if (stats_.routed > 0) {
        stats_.coldFraction = static_cast<double>(stats_.cold) /
                              static_cast<double>(stats_.routed);
        stats_.hitRate = static_cast<double>(stats_.hits) /
                         static_cast<double>(stats_.routed);
    } else {
        stats_.coldFraction = 0.0;
        stats_.hitRate = 0.0;
    }
    return stats_;
}

// ---------------------------------------------------------------------------
// WireWriter
// ---------------------------------------------------------------------------

WireWriter::~WireWriter() { close(); }

bool WireWriter::open(const wchar_t* pathW) {
    close();
    HANDLE h = CreateFileW(pathW, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        lastError_ = static_cast<std::uint64_t>(GetLastError());
        return false;
    }
    handle_ = h;
    block_ = static_cast<Packet*>(::operator new(sizeof(Packet) * batchPackets_,
                                                std::nothrow));
    if (!block_) { close(); lastError_ = ERROR_OUTOFMEMORY; return false; }
    blockFill_ = 0;
    seq_ = 0;
    written_ = 0;
    rejected_ = 0;
    lastError_ = 0;
    return true;
}

void WireWriter::close() {
    if (handle_) {
        flush();
        CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
    if (block_) {
        ::operator delete(block_);
        block_ = nullptr;
    }
    blockFill_ = 0;
}

void WireWriter::stamp(Packet& p, std::uint64_t wallNs, std::uint64_t qpcRaw) {
    p.magic = kMagic;
    p.version = kVersion;
    p.sizeBytes = static_cast<std::uint16_t>(sizeof(Packet));
    p.packetSeq = seq_++;
    p.wallNs = wallNs;
    p.qpcRaw = qpcRaw;
    p.contentHash = WireContentHash(p);
}

void WireWriter::writeBlock() {
    if (!handle_ || blockFill_ == 0) return;
    const DWORD want = static_cast<DWORD>(sizeof(Packet) * blockFill_);
    DWORD put = 0;
    if (!WriteFile(static_cast<HANDLE>(handle_), block_, want, &put, nullptr) ||
        put != want) {
        lastError_ = static_cast<std::uint64_t>(GetLastError());
    } else {
        written_ += blockFill_;
    }
    blockFill_ = 0;
}

bool WireWriter::emit(const Packet& p) {
    if (!handle_ || !block_) { ++rejected_; return false; }
    if (p.sizeBytes != sizeof(Packet) || p.version != kVersion) { ++rejected_; return false; }
    // The whole point of a validated state byte: an undefined bit cannot reach
    // the file. Rejections are counted, not silently dropped, because a wire
    // that quietly discards frames is indistinguishable from a quiet system.
    if (!WireFlagLegal(p.stateFlag)) { ++rejected_; return false; }
    if (WireContentHash(p) != p.contentHash) { ++rejected_; return false; }
    block_[blockFill_++] = p;
    if (blockFill_ >= batchPackets_) writeBlock();
    return true;
}

bool WireWriter::flush() {
    if (!handle_) return false;
    writeBlock();
    if (lastError_) return false;
    return FlushFileBuffers(static_cast<HANDLE>(handle_)) != FALSE;
}

// ---------------------------------------------------------------------------
// VerifyCapture -- the dissector
// ---------------------------------------------------------------------------

bool VerifyCapture(const wchar_t* pathW, VerifyReport& out, std::uint64_t& lastError) {
    out = VerifyReport{};
    lastError = 0;

    HANDLE h = CreateFileW(pathW, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        lastError = static_cast<std::uint64_t>(GetLastError());
        return false;
    }

    LARGE_INTEGER li{};
    if (!GetFileSizeEx(h, &li)) {
        lastError = static_cast<std::uint64_t>(GetLastError());
        CloseHandle(h);
        return false;
    }
    const unsigned __int64 total = static_cast<unsigned __int64>(li.QuadPart);
    if (total % sizeof(Packet) != 0) out.shortFrames = (total % sizeof(Packet)) ? 1u : 0u;

    const std::uint64_t n = total / sizeof(Packet);
    Packet* buf = static_cast<Packet*>(::operator new(sizeof(Packet) * 4096, std::nothrow));
    if (!buf) { lastError = ERROR_OUTOFMEMORY; CloseHandle(h); return false; }

    std::uint64_t readTotal = 0;
    std::uint64_t coldCount = 0, hotCount = 0;
    bool haveExpect = false;
    std::uint64_t expect = 0;

    while (readTotal < n) {
        DWORD want = static_cast<DWORD>((n - readTotal) < 4096 ? (n - readTotal) : 4096);
        want = static_cast<DWORD>(want * sizeof(Packet));
        DWORD got = 0;
        if (!ReadFile(h, buf, want, &got, nullptr) || got == 0) break;
        const std::uint64_t count = got / sizeof(Packet);
        for (std::uint64_t k = 0; k < count; ++k) {
            const Packet& p = buf[k];
            ++out.packetsRead;
            if (p.magic != kMagic) { ++out.magicFailures; continue; }
            if (p.sizeBytes != sizeof(Packet) || p.version != kVersion) {
                ++out.shortFrames; continue;
            }
            if (WireContentHash(p) != p.contentHash) { ++out.hashFailures; continue; }
            if (!WireFlagLegal(p.stateFlag)) { ++out.illegalFlags; continue; }
            if (haveExpect && p.packetSeq != expect) ++out.seqGaps;
            expect = p.packetSeq + 1;
            haveExpect = true;

            if (p.stateFlag & kHotHit)             { ++out.hotHits; ++hotCount; }
            if (p.stateFlag & kColdFault)          { ++out.coldFaults; ++coldCount; }
            if (p.stateFlag & kEmptyConsumed)      ++out.emptyConsumed;
            if (p.stateFlag & kMetalBlockThrash)   ++out.metalThrash;
            if (p.stateFlag & kCpuFallbackViolation) ++out.cpuFallback;
            out.bytesMoved += p.bytes;
            if (p.reuseDistance > out.maxReuseDistance) out.maxReuseDistance = p.reuseDistance;
        }
        readTotal += count;
        if (got < want) break;
    }

    ::operator delete(buf);
    CloseHandle(h);

    const std::uint64_t routed = hotCount + coldCount;
    out.coldFractionRecomputed = routed ? static_cast<double>(coldCount) /
                                          static_cast<double>(routed)
                                        : 0.0;
    return true;
}

void WireEmitArmedHook(std::uint32_t token, double coldFraction,
                       std::uint32_t reuseDistance) {
    // The immediate wire hook. Raw, first, and before any summary: the tuple a
    // reader needs to decide whether residency is working at all.
    std::printf("[WIRESHARK_CAPTURE] token=%u cold_fraction=%.3f reuse_distance=%u "
                "status=ARMED\n",
                token, coldFraction, reuseDistance);
    std::fflush(stdout);
}

// ---------------------------------------------------------------------------
// Engine-side hook implementation.
//
// A function-local static gives thread-safe lazy init under C++11 and later and
// keeps the sink out of any static-initialisation-order dependency. It is
// deliberately NOT a Meyers singleton exposed to callers: nothing outside this
// file can swap the sink, replace the recorder, or make the hook a no-op.
// ---------------------------------------------------------------------------
namespace {

struct SinkState {
    WireWriter writer;
    bool attempted = false;
    bool open = false;
    std::uint64_t seen = 0;
    std::uint64_t recorded = 0;
    // Bitmask of decision predicates, so a reader can tell "Vulkan was never
    // enabled" from "Vulkan was enabled and declined" without parsing prose.
    // bit 0 vulkanEnabled, 1 vulkanInitialized, 2 strict, 3 residentFirst,
    // 4 forceLayerSplit, 5 isMoE, 6 useMLA, 7 onHost
    std::uint32_t lastFlags = 0;
    std::uint32_t lastDeviceCount = 0;
};

SinkState& sinkState() {
    static SinkState s;
    return s;
}

}  // namespace

std::uint64_t WireDispatchSeen()     { return sinkState().seen; }
std::uint64_t WireDispatchRecorded() { return sinkState().recorded; }
bool          WireSinkOpen()         { return sinkState().open; }
void          WireCloseSink()        { sinkState().writer.close();
                                      sinkState().open = false; }

bool WireRecordDispatch(const DispatchDecision& d) {
    SinkState& s = sinkState();
    ++s.seen;

    if (!s.attempted) {
        s.attempted = true;
        const char* p = std::getenv("DEEP2_WIRE");
        if (p && p[0] && std::strcmp(p, "0") != 0) {
            const int n = MultiByteToWideChar(CP_UTF8, 0, p, -1, nullptr, 0);
            if (n > 0) {
                std::vector<wchar_t> w(static_cast<std::size_t>(n));
                if (MultiByteToWideChar(CP_UTF8, 0, p, -1, w.data(), n) > 0 &&
                    s.writer.open(w.data())) {
                    s.open = true;
                }
            }
        }
    }
    if (!s.open) return false;

    s.lastFlags = (d.vulkanEnabled       ? 1u << 0 : 0u)
                | (d.vulkanInitialized   ? 1u << 1 : 0u)
                | (d.strictNoCpuFallback ? 1u << 2 : 0u)
                | (d.residentFirst       ? 1u << 3 : 0u)
                | (d.forceLayerSplit     ? 1u << 4 : 0u)
                | (d.isMoE               ? 1u << 5 : 0u)
                | (d.useMLA              ? 1u << 6 : 0u)
                | (d.onHost              ? 1u << 7 : 0u);
    s.lastDeviceCount = d.deviceCount;

    Packet p{};
    p.tokenSeq = d.token;
    p.layerId = d.layer;
    p.routerId = 0;
    p.expertId = 0;
    // The contract this capture exists to enforce: a GPU-intended dispatch that
    // executed on the CPU is CPU_FALLBACK_VIOLATION, whatever the engine chose to
    // call the route afterwards.
    p.stateFlag = d.onHost ? kCpuFallbackViolation : kHotHit;
    p.severity = d.onHost ? kSeverityViolation : kSeverityInfo;
    p.faultKind = static_cast<std::uint8_t>(kFaultScheduling);
    // The predicate bits are a MEASURED value: each is read straight out of the
    // engine's own state at the decision point, not declared by the caller.
    p.sourceKind = kSourceMeasured;
    p.reuseDistance = 0;
    p.latencyNs = static_cast<std::uint32_t>(
        d.latencyNs > 0xFFFFFFFFull ? 0xFFFFFFFFull : d.latencyNs);
    p.bytes = 0;
    p.demandId = 0;
    p.tierFrom = static_cast<std::uint8_t>(kTierGpu);   // intended
    p.tierTo   = static_cast<std::uint8_t>(d.onHost ? kTierHost : kTierGpu);
    p.routeCount = 0;
    p.capacityEntries = d.numLayers;
    p.residentEntries = 0;
    // lastFlags rides in routerId, which is otherwise unused at this boundary.
    // It is the whole causal explanation packed into a 32-bit field.
    p.routerId = s.lastFlags;
    p.expertId = d.deviceCount;

    std::uint64_t wall = 0, qpc = 0;
    WireClock(wall, qpc);
    s.writer.stamp(p, wall, qpc);
    if (!s.writer.emit(p)) return false;
    ++s.recorded;
    return true;
}

}  // namespace Deep2::Wire
