// ============================================================================
// RAWRXD_INFERENCE_WIRE_001
//
// A raw wire protocol between NVMe, host memory, and the GPU execution units.
//
// This is NOT a logging wrapper and NOT a metrics facade. It is a framed binary
// stream: fixed-width records, gapless sequence numbers, a validated state byte,
// a per-record content hash, and both absolute and raw-clock timestamps so a
// reader can compute deltas without trusting the writer's time conversion.
// Anything that cannot be expressed as bytes on a link does not belong here.
//
// Deliberately absent: std::string, std::map, iostreams, RTTI, exceptions on the
// emit path, and any global registry. Those turn a wire into a heap-allocating
// observer whose own behaviour perturbs what it observes.
//
// HONEST SCOPE LIMIT -- read this before citing any number it produces.
//
// This file is an INSTRUMENT. It moves no bytes, holds no weights, and makes
// nothing faster. The residency ledger below is a SHADOW MIRROR fed by facts the
// caller reports from its own accounting; it is not a cache and does not evict
// anything. Calling it "CoinBox" would be exactly the decorative-metric failure
// this project exists to catch: a component that reports on residency while
// having no effect on it.
//
// What it can establish, and what it cannot:
//
//   CAN: every route, every residency transition, every declared fallback, with
//        a byte-exact record of what happened and in what order.
//   CAN: cold_fraction and reuse_distance computed by division over the packets
//        actually emitted, not assigned as literals.
//   CAN: prove the failure states are EMITTABLE, which a counter that is never
//        incremented cannot.
//   CANNOT: certify that the engine was correct, fast, or GPU-resident. Those
//        are claims about the engine. This file only makes them checkable.
//
// Every derived value it publishes is a function of emitted packets, and the
// falsification probe (certs/inference_wire_001.cpp) is required to demonstrate
// that the division actually responds to its inputs.
// ============================================================================

#pragma once

#include <cstdint>

namespace Deep2::Wire {

// ---------------------------------------------------------------------------
// The unforgeable state byte.
//
// A bit is defined by what the engine DID, observed at a callsite, not by what a
// caller intended. Bits are additive where an event genuinely carries two facts
// (a re-fault after eviction is both a cold fetch and a thrash).
//
// Values are contract. kStateMask below is asserted against these constants at
// compile time in the .cpp; the probe additionally proves the emitter REFUSES to
// write a byte with any bit outside the mask, which is what stops "unforgeable"
// from meaning "whatever the caller passed".
// ---------------------------------------------------------------------------
enum StateBit : std::uint8_t {
    kHotHit             = 0x01,  // resident at route time; zero fetch cost
    kColdFault          = 0x02,  // not resident; fetched this route
    kEmptyConsumed      = 0x04,  // already consumed for this token; re-route waste
    kMetalBlockThrash   = 0x08,  // was resident, evicted by pressure, re-fetched
    kCpuFallbackViolation = 0x10, // a GPU-intended op executed on the CPU
};

constexpr std::uint8_t kStateMask =
    kHotHit | kColdFault | kEmptyConsumed | kMetalBlockThrash | kCpuFallbackViolation;

// Residency location. LOCATION ONLY. Representation (quantized / decoded /
// packed) is a separate axis and is deliberately NOT encoded here: folding the
// two into one enum is how a buffer ends up reporting a tier it does not hold.
enum Tier : std::uint8_t {
    kTierAbsent  = 0,
    kTierStorage = 1,  // on NVMe, no bytes resident
    kTierFileCache = 2, // Windows file cache
    kTierHost    = 3,  // process heap / mapped and resident
    kTierGpu     = 4,  // device memory
};

// Why a cold fetch happened. "Cache miss" is not one event; collapsing the
// classes is what makes an over-capacity cache and a broken eviction policy look
// identical. The class is derived from evidence the ledger holds, not chosen.
enum FaultClass : std::uint8_t {
    kFaultNone       = 0,
    kFaultColdStart  = 1,  // first ever route to this expert: unavoidable
    kFaultReuse      = 2,  // evicted while still hot, then re-fetched: eviction bug
    kFaultCapacity   = 3,  // correct demand, insufficient hot storage
    kFaultPrediction = 4,  // prefetch asked for it and it did not arrive first
    kFaultScheduling = 5,  // bytes were resident but not moved in time
    kFaultIo         = 6,  // storage failed to deliver
};

// Provenance of a packet's payload. A reader can refuse to aggregate across
// these: a MEASURED byte count and a DERIVED one do not belong in one average.
enum SourceKind : std::uint8_t {
    kSourceMeasured = 0,  // value came from a real counter the engine owns
    kSourceDerived  = 1,  // value computed by the wire from its own packets
    kSourceDeclared = 2,  // value asserted by the caller, not independently checked
};

// ---------------------------------------------------------------------------
// The frame. 96 bytes, packed, no padding, no vtable, no indirection.
//
// Layout is fixed and versioned. A reader that does not recognise `magic` or
// `sizeBytes` must refuse the file rather than reinterpret it: a misparsed wire
// produces confident, specific, wrong answers.
// ---------------------------------------------------------------------------
#pragma pack(push, 1)

struct Packet {
    // --- framing ---
    std::uint32_t magic;       // 0x58545044 'DPTX'; reader validates
    std::uint16_t version;     // kVersion
    std::uint16_t sizeBytes;   // sizeof(Packet) == 96; reader validates
    std::uint64_t packetSeq;   // gapless from 0; a gap is packet loss, not idle
    // --- timing ---
    std::uint64_t wallNs;      // FILETIME-derived, for cross-process correlation
    std::uint64_t qpcRaw;      // raw counter, so a reader needs no time conversion
    // --- the six specified fields ---
    std::uint32_t tokenSeq;      // TOKEN_SEQ
    std::uint32_t layerId;
    std::uint32_t routerId;      // ROUTER_ID
    std::uint32_t expertId;      // EXPERT_ID
    std::uint8_t  stateFlag;     // STATE_FLAG: validated against kStateMask
    std::uint32_t reuseDistance; // REUSE_DISTANCE
    std::uint32_t latencyNs;     // LATENCY_NS
    // --- physical context ---
    std::uint8_t  tierFrom;
    std::uint8_t  tierTo;
    std::uint8_t  faultKind;
    std::uint8_t  sourceKind;
    std::uint8_t  severity;      // 0 info, 1 warn, 2 violation
    std::uint16_t routeCount;    // experts in this token's route group
    std::uint64_t bytes;
    std::uint64_t demandId;      // 0 = not demand-tracked
    std::uint32_t capacityEntries;
    std::uint32_t residentEntries;
    std::uint64_t contentHash;   // FNV-1a over the frame with this field zeroed
};

#pragma pack(pop)

constexpr std::uint32_t kMagic     = 0x58545044u;  // 'D','P','T','X'
constexpr std::uint16_t kVersion   = 1;
static_assert(sizeof(Packet) == 96, "wire frame must be exactly 96 bytes");

// Severity levels.
constexpr std::uint8_t kSeverityInfo      = 0;
constexpr std::uint8_t kSeverityWarn      = 1;
constexpr std::uint8_t kSeverityViolation = 2;

// ---------------------------------------------------------------------------
// Expert residency ledger.
//
// The residency substrate for the wire. Open-addressed, fixed capacity, no
// allocation after construction, and it KEEPS AN EVICTION LOG -- which is the
// whole point. A cache that only knows hit/miss cannot distinguish "evicted and
// needed again soon" (a policy bug) from "never seen before" (unavoidable), and
// therefore cannot emit kMetalBlockThrash at all. A wire that structurally
// cannot emit its own failure state is decorative.
//
// This holds no weight bytes. See HONEST SCOPE LIMIT above.
// ---------------------------------------------------------------------------
class ExpertLedger {
public:
    // capacitySlots is rounded up to a power of two and capped; it bounds both
    // memory and probe length. thrashWindowTokens defines how recent an
    // eviction must be for a re-fetch to count as thrash rather than capacity
    // pressure.
    explicit ExpertLedger(std::uint32_t capacitySlots = 4096,
                          std::uint32_t thrashWindowTokens = 8);
    ~ExpertLedger();

    ExpertLedger(const ExpertLedger&) = delete;
    ExpertLedger& operator=(const ExpertLedger&) = delete;

    void reset();

    // Record a route to (layer, expert). Returns the evidence needed to build a
    // packet: whether it was resident, the measured reuse distance, the fault
    // class if it was not, and whether this is a thrash.
    struct RouteEvidence {
        bool        hit          = false;
        bool        thrash       = false;  // re-fetched after recent eviction
        std::uint32_t reuseDistance = 0;   // tokens since last route; 0 on first
        FaultClass  fault        = kFaultNone;
        std::uint32_t capacityEntries = 0;
        std::uint32_t residentEntries = 0;
    };
    RouteEvidence route(std::uint32_t layer, std::uint32_t expert,
                        std::uint32_t token, std::uint64_t bytes,
                        bool prefetchRequested);

    // Record a transition that did not come from a route (e.g. an explicit
    // demotion), so tier changes are not silently lost.
    void noteTransition(std::uint32_t layer, std::uint32_t expert,
                        Tier from, Tier to, std::uint64_t bytes,
                        const char* reason);

    // Post-route statistics for the token just completed.
    struct TokenStats {
        std::uint32_t routed = 0;
        std::uint32_t hits   = 0;
        std::uint32_t cold   = 0;
        std::uint32_t thrash = 0;
        std::uint32_t evicted = 0;
        double coldFraction = 0.0;  // cold / routed; 0 when routed == 0
        double hitRate     = 0.0;
    };
    void beginToken(std::uint32_t token);
    TokenStats endToken();
    const TokenStats& tokenStats() const noexcept { return stats_; }

    std::uint32_t residentEntries() const noexcept { return residentCount_; }
    std::uint32_t capacityEntries()  const noexcept { return mask_ + 1u; }
    std::uint64_t totalEvictions()   const noexcept { return evictions_; }
    std::uint64_t totalThrash()      const noexcept { return thrashes_; }
    std::uint64_t usedBytes()        const noexcept { return usedBytes_; }
    void setCapacityBytes(std::uint64_t bytes) { capacityBytes_ = bytes; }
    std::uint64_t capacityBytes() const noexcept { return capacityBytes_; }

    // Worst measured reuse distance and the ratio of tokens to cache capacity,
    // which is the number that decides whether the cache is mathematically too
    // small or the eviction policy is simply wrong.
    std::uint32_t maxReuseDistance() const noexcept { return maxReuse_; }

private:
    struct Slot {
        std::uint64_t key;        // (layer<<32)|expert; kInvalidKey when empty
        std::uint64_t bytes;
        std::uint32_t lastRoute;
        std::uint32_t routeEpoch; // incremented per token; 0 == never routed
        std::uint32_t resident;
    };
    struct Eviction {
        std::uint64_t key;
        std::uint32_t token;       // token at which the eviction happened
        std::uint32_t wasRouted;   // victim had been routed at least once
        // The victim's lastRoute at eviction time. Carried here deliberately:
        // the slot is cleared on eviction, so without this the reuse distance of
        // a re-fetched expert is destroyed -- and reuse distance is precisely
        // the number that distinguishes "evicted too early" from "cache too
        // small". Losing it makes thrash indistinguishable from cold start.
        std::uint32_t lastRoute;
    };

    static constexpr std::uint64_t kInvalidKey = ~0ull;

    Slot*       slots_  = nullptr;
    std::uint32_t mask_ = 0;        // capacity - 1
    std::uint32_t residentCount_ = 0;
    std::uint64_t usedBytes_ = 0;
    std::uint64_t capacityBytes_ = 0;
    std::uint64_t evictions_ = 0;
    std::uint64_t thrashes_ = 0;
    std::uint32_t maxReuse_ = 0;

    Eviction*  evictRing_ = nullptr;
    std::uint32_t evictMask_ = 0;
    std::uint32_t evictHead_ = 0;

    std::uint32_t thrashWindow_ = 8;
    TokenStats   stats_{};
    std::uint32_t curToken_ = 0;
};

// ---------------------------------------------------------------------------
// The sink.
//
// Opens a real file handle and writes framed records. Records are batched into
// a fixed block and flushed on a boundary, because one WriteFile per packet
// would make the instrument the dominant syscall in the run it is measuring.
// The block size is reported in the summary so a reader knows the batching.
// ---------------------------------------------------------------------------
class WireWriter {
public:
    WireWriter() = default;
    ~WireWriter();
    WireWriter(const WireWriter&) = delete;
    WireWriter& operator=(const WireWriter&) = delete;

    // pathW is a UTF-16 Windows path. Returns false and sets lastError() on
    // failure; a wire that cannot open its sink is not silently a no-op sink.
    bool open(const wchar_t* pathW);
    bool isOpen() const noexcept { return handle_ != nullptr; }
    void close();

    // Emit. Returns false only when the frame is rejected or the write fails.
    // Rejected means an out-of-mask state byte or a short block; both are
    // counted in rejections() rather than being smoothed away.
    bool emit(const Packet& p);

    bool flush();
    std::uint64_t lastError() const noexcept { return lastError_; }

    std::uint64_t packetsWritten()  const noexcept { return written_; }
    std::uint64_t packetsRejected() const noexcept { return rejected_; }
    std::uint32_t batchPackets()   const noexcept { return batchPackets_; }

    // Fill in magic/version/size/seq/hash from the payload fields. Called by the
    // emitter helper; exposed so a caller can log its own frames.
    void stamp(Packet& p, std::uint64_t wallNs, std::uint64_t qpcRaw);

private:
    void writeBlock();

    void*       handle_  = nullptr;  // HANDLE, held as void* to keep this header
                                    // free of <windows.h>
    Packet*     block_   = nullptr;
    std::uint32_t blockFill_ = 0;
    std::uint32_t batchPackets_ = 1024;  // 1024 * 96 = 96 KiB
    std::uint64_t seq_    = 0;
    std::uint64_t written_ = 0;
    std::uint64_t rejected_ = 0;
    std::uint64_t lastError_ = 0;
};

// ---------------------------------------------------------------------------
// The dissector: reads a capture back and reports what it can prove.
//
// Verification is the reason this exists. It re-derives every packet's content
// hash, checks sequence continuity, rejects illegal state bytes, and recounts
// cold_fraction FROM THE FILE rather than trusting any summary the writer kept.
// A capture that cannot fail to verify is not a capture.
// ---------------------------------------------------------------------------
struct VerifyReport {
    std::uint64_t packetsRead      = 0;
    std::uint64_t hashFailures     = 0;
    std::uint64_t seqGaps          = 0;
    std::uint64_t illegalFlags     = 0;
    std::uint64_t shortFrames      = 0;
    std::uint64_t magicFailures    = 0;
    std::uint64_t hotHits          = 0;
    std::uint64_t coldFaults       = 0;
    std::uint64_t emptyConsumed    = 0;
    std::uint64_t metalThrash      = 0;
    std::uint64_t cpuFallback      = 0;
    std::uint64_t bytesMoved       = 0;
    std::uint32_t maxReuseDistance = 0;
    double        coldFractionRecomputed = 0.0;  // recount from the file
    bool          clean() const noexcept {
        return hashFailures == 0 && seqGaps == 0 && illegalFlags == 0 &&
               shortFrames == 0 && magicFailures == 0;
    }
};

bool VerifyCapture(const wchar_t* pathW, VerifyReport& out, std::uint64_t& lastError);

// Compute the frame hash over the frame with contentHash zeroed. Exposed so the
// probe can forge a frame deliberately and prove the check catches it.
std::uint64_t WireContentHash(const Packet& p);

// Monotonic clock pair. One call site so wallNs and qpcRaw are consistent
// within a packet; a frame whose two clocks disagree by a frame is a bug in
// the emitter, not in the reader.
void WireClock(std::uint64_t& wallNs, std::uint64_t& qpcRaw);

// True when every bit of `flag` is defined. The emitter refuses anything else.
bool WireFlagLegal(std::uint8_t flag) noexcept;

const char* WireStateName(std::uint8_t flag) noexcept;
const char* WireFaultName(std::uint8_t fault) noexcept;

// The immediate wire hook, emitted on the first token of a run.
void WireEmitArmedHook(std::uint32_t token, double coldFraction,
                       std::uint32_t reuseDistance);

// ---------------------------------------------------------------------------
// Engine-side hook.
//
// This is the ONLY thing Deep2Engine needs in order to appear on the wire. It is
// deliberately one call with no handle, no registration, and no lifecycle: a
// subsystem that must be wired up before it can be observed is a subsystem that
// will be observed by nobody. The sink is opened lazily from an environment
// variable so that a build with no wire configured costs one getenv per call.
//
// Enabled by DEEP2_WIRE=<path>. Absent or "0" means the capture is closed, and
// the hook reports that rather than pretending to have recorded anything.
// ---------------------------------------------------------------------------

// The decision inputs at the layer-dispatch boundary. Recorded verbatim, because
// the question "why did this go to the host" is answered entirely by which of
// these was false, and a capture that omits them answers nothing.
struct DispatchDecision {
    std::uint32_t token        = 0;
    std::uint32_t layer        = 0;
    std::uint32_t seqLen       = 0;
    std::uint32_t numLayers    = 0;
    std::uint32_t deviceCount  = 0;
    bool vulkanEnabled         = false;
    bool vulkanInitialized     = false;
    bool strictNoCpuFallback   = false;
    bool residentFirst         = false;
    bool forceLayerSplit       = false;
    bool isMoE                 = false;
    bool useMLA                = false;
    std::uint64_t latencyNs    = 0;
    bool onHost                = true;   // true => executed on the CPU
};

// Records one dispatch decision. Returns true when it reached the file. Safe and
// cheap to call unconditionally.
bool WireRecordDispatch(const DispatchDecision& d);

// Number of dispatch decisions handed over since process start. Counted even
// when the sink is closed, so a run with no wire still reports whether any
// dispatch ever crossed this boundary.
std::uint64_t WireDispatchSeen();
std::uint64_t WireDispatchRecorded();
bool WireSinkOpen();
void WireCloseSink();

}  // namespace Deep2::Wire
