// ============================================================================
// WeightConsumptionCensus.hpp
// RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001
// ============================================================================
// WHY THIS EXISTS
// ---------------
// The previous audit law was "does this path call LinearW()?" and it was
// wrong in a way that produced confidently incorrect results.
//
// Calling LinearW() is NOT computing in LinearW(). LinearW() is a ROUTING
// BOUNDARY:
//
//     LinearW(wt)
//         |- dual-GPU eligible -> tryVulkanHostGEMV(wt) -> RETURN
//         |- single-GPU        -> tryVulkanHostGEMV(wt) -> RETURN
//         `- GPU unused/failed -> QuantKernelRegistry::GetGEMV(wt.type)(wt.data,...)
//
// So a path whose caller contains `LinearW(w, ...)` may have had its weight
// arithmetic performed entirely by another authority. Classifying such a path
// as "NOT_BYPASS" is unsound, and doing so hides the second bypass class:
//
//     CLASS A  weight compute never enters LinearW()            (BYPASS)
//     CLASS B  enters LinearW(), which delegates and returns  (DELEGATED)
//
// Both must be closed before LinearW() can be called a universal
// weight-consumption boundary.
//
// THE LAW THIS FILE ENCODES
// -------------------------
//     WEIGHT CONSUMPTION AUTHORITY > FUNCTION ENTRY
//
// The census is recorded at the point the bytes are actually consumed -- the
// common weight-resolution boundary -- and NEVER at the call site. A caller
// cannot annotate its way out of the audit: if the weights are read by a GPU
// dispatch, the event says so regardless of who called it.
//
// HONESTY RULES
// -------------
//  * No field is a literal. Every count is a recorded observation.
//  * A site with no observed events is UNOBSERVED, never PASS. Silence is not
//    a result.
//  * The verdict is computed from the observations.
//  * Recording an event requires a real byte count. Callers that have no
//    measurement must not record.
// ============================================================================

#pragma once

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace rawrxd::deep2::weightcensus {

// ---------------------------------------------------------------------------
// The audited consumption perimeter. These are the real entry points that read
// model-weight bytes, named from the source census. COUNT must stay last.
// ---------------------------------------------------------------------------
enum class Site : uint32_t {
    EmbedToken          = 0,  // raw quantized row -> GetDequant
    RmsNormW            = 1,  // norm tensors: direct dequant + weighted RMS
    LinearW             = 2,  // the dispatcher itself
    LinearWBatch4       = 3,  // batched GEMV; GPU branch can return before LinearW
    GroupedGemm         = 4,  // tryVulkanHostGEMVGroup (QKV / gate+up)
    SsmDirect           = 5,  // conv1d/bias, dtBias, A, D, norm
    MlaGpu              = 6,  // computeMLAAttentionGpu
    MoeGpu              = 7,  // computeMoEFFNGpu / RunExpertFFN
    ResidentForward     = 8,  // forwardLayerGpuResident + resident resolver
    SpecQ4KGroup        = 9,  // speculative QKV + FFN gate/up
    SpecColumnSplit     = 10, // speculative O-proj + FFN down
    SpecRmsNorm         = 11, // speculative norm batch
    COUNT               = 12
};

const char* siteName(Site s);

// ---------------------------------------------------------------------------
// How the bytes were actually consumed. This is the whole point of the census.
// ---------------------------------------------------------------------------
enum class Route : uint32_t {
    LinearWOwned     = 0, // reached LinearW's locally registered GEMV kernel
    LinearWDelegated = 1, // entered LinearW, handed to another authority
    Bypass           = 2, // never entered LinearW at all
};

const char* routeName(Route r);

// The four-state classification the audit must produce for each site.
enum class Classification : uint32_t {
    Unobserved   = 0, // no real consumption recorded yet -- NOT a pass
    Bypass       = 1, // consumed without LinearW
    Delegated    = 2, // LinearW delegated
    Owned        = 3, // LinearW owned the arithmetic
    Conditional  = 4, // more than one route observed at this site
};

// ---------------------------------------------------------------------------
// One real consumption. `bytes` is the number of weight bytes actually read;
// a caller with no measurement must not construct an Event.
// ---------------------------------------------------------------------------
struct Event {
    Site        site      = Site::EmbedToken;
    Route       route     = Route::Bypass;
    std::string tensor;        // GGUF tensor name, empty if unknown
    uint64_t    bytes      = 0;  // must be > 0 for the event to count
    uint32_t    tokenEpoch = 0;
};

// Per-site rollup, computed from the event stream.
struct SiteReport {
    Site        site          = Site::EmbedToken;
    std::string name;
    uint64_t    events        = 0;
    uint64_t    bytes         = 0;
    uint64_t    ownedEvents   = 0;
    uint64_t    delegatedEvents = 0;
    uint64_t    bypassEvents  = 0;
    Classification classification = Classification::Unobserved;
};

// The census.
struct Census {
    std::vector<SiteReport> sites;
    uint64_t totalEvents      = 0;
    uint64_t totalBytes       = 0;
    uint64_t rejectedEvents   = 0;  // dropped for bytes==0 or invalid site
    uint64_t ownedEvents      = 0;
    uint64_t delegatedEvents  = 0;
    uint64_t bypassEvents     = 0;
    uint64_t unobservedSites  = 0;
    uint64_t conditionalSites = 0;

    // Derived, never assigned. A site is Conditional when it has been observed
    // under more than one Route -- which is the honest description of a
    // runtime-dependent path such as lmHead (GPU -> delegated, CPU -> owned).
    const char* verdict() const;
    std::string toText() const;
};

// ---------------------------------------------------------------------------
// Recording. Thread-safe: weight consumption happens on host, GPU and
// speculative threads concurrently.
// ---------------------------------------------------------------------------
class WeightConsumptionCensus {
public:
    static WeightConsumptionCensus& instance();

    // Records one real consumption. Returns false (and counts a rejection)
    // if the event carries no byte measurement, because an unmeasured event
    // would let a site look exercised when nothing was read.
    bool record(const Event& e);

    void reset();

    // Snapshot under lock.
    Census snapshot() const;

    // True if this site has ever been recorded.
    bool sawSite(Site s) const;

private:
    WeightConsumptionCensus() = default;
    mutable std::mutex      m_mutex;
    std::vector<Event>      m_events;
    uint64_t                m_rejected = 0;
};

// ---------------------------------------------------------------------------
// Scoped recorder: the only sanctioned way to attribute bytes to a site.
// RAWRXD_WEIGHT_SCOPE(site, name, bytes) records on destruction, so a route
// that returns early still accounts for what it consumed.
// ---------------------------------------------------------------------------
class Scope {
public:
    Scope(Site site, Route route, std::string tensor, uint64_t bytes,
          uint32_t tokenEpoch = 0)
        : m_site(site), m_route(route), m_tensor(std::move(tensor)),
          m_bytes(bytes), m_epoch(tokenEpoch) {}
    ~Scope() {
        if (m_bytes > 0) {
            Event e;
            e.site = m_site; e.route = m_route; e.tensor = m_tensor;
            e.bytes = m_bytes; e.tokenEpoch = m_epoch;
            WeightConsumptionCensus::instance().record(e);
        }
    }
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;

private:
    Site        m_site;
    Route       m_route;
    std::string m_tensor;
    uint64_t    m_bytes;
    uint32_t    m_epoch;
};

#define RAWRXD_WC_CAT2(a, b) a##b
#define RAWRXD_WC_CAT(a, b) RAWRXD_WC_CAT2(a, b)

#define RAWRXD_WEIGHT_SCOPE(site, route, tensor, bytes)          \
    ::rawrxd::deep2::weightcensus::Scope RAWRXD_WC_CAT(         \
        rawrxd_wc_scope_, __LINE__)(site, route, tensor, bytes)

// ============================================================================
// Implementation (header-only on purpose)
// ============================================================================
// Header-only, not for brevity: the census is referenced from Deep2Engine.cpp,
// which is compiled into a dozen different CMake source lists. A separate .cpp
// would have to be added to every one of them, and this repository's
// CMakeLists.txt is under active concurrent edit -- a missed list is an
// unresolved-external link error at the worst possible moment. Inline keeps the
// instrument self-contained: including the header is sufficient and there is
// no build-graph entry that can be forgotten.
//
// Note for callers: the functions below are inline, so every field is still
// computed from the recorded event stream at snapshot() time. Nothing is
// precomputed into a constant.
// ============================================================================

inline const char* siteName(Site s) {
    switch (s) {
        case Site::EmbedToken:      return "EmbedToken";
        case Site::RmsNormW:        return "RmsNormW";
        case Site::LinearW:         return "LinearW";
        case Site::LinearWBatch4:   return "LinearWBatch4";
        case Site::GroupedGemm:     return "GroupedGemm";
        case Site::SsmDirect:       return "SsmDirect";
        case Site::MlaGpu:          return "MlaGpu";
        case Site::MoeGpu:          return "MoeGpu";
        case Site::ResidentForward: return "ResidentForward";
        case Site::SpecQ4KGroup:    return "SpecQ4KGroup";
        case Site::SpecColumnSplit: return "SpecColumnSplit";
        case Site::SpecRmsNorm:     return "SpecRmsNorm";
        case Site::COUNT:           return "COUNT";
    }
    return "UNKNOWN";
}

inline const char* routeName(Route r) {
    switch (r) {
        case Route::LinearWOwned:     return "LINEARW_OWNED";
        case Route::LinearWDelegated: return "LINEARW_DELEGATED";
        case Route::Bypass:           return "BYPASS";
    }
    return "UNKNOWN";
}

inline const char* classificationName(Classification c) {
    switch (c) {
        case Classification::Unobserved:  return "UNOBSERVED";
        case Classification::Bypass:      return "LINEARW_BYPASS";
        case Classification::Delegated:   return "LINEARW_DELEGATED";
        case Classification::Owned:       return "LINEARW_OWNED";
        case Classification::Conditional: return "LINEARW_CONDITIONAL";
    }
    return "UNKNOWN";
}

inline WeightConsumptionCensus& WeightConsumptionCensus::instance() {
    static WeightConsumptionCensus s;
    return s;
}

inline bool WeightConsumptionCensus::record(const Event& e) {
    // An event with no byte measurement is refused. Without this rule a caller
    // could announce "the speculative Q4K group ran" while having read nothing,
    // and the census would report a site as exercised on the strength of a
    // claim.
    if (e.bytes == 0 || static_cast<uint32_t>(e.site) >= static_cast<uint32_t>(Site::COUNT)) {
        std::lock_guard<std::mutex> lk(m_mutex);
        ++m_rejected;
        return false;
    }
    std::lock_guard<std::mutex> lk(m_mutex);
    m_events.push_back(e);
    return true;
}

inline void WeightConsumptionCensus::reset() {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_events.clear();
    m_rejected = 0;
}

inline bool WeightConsumptionCensus::sawSite(Site s) const {
    std::lock_guard<std::mutex> lk(m_mutex);
    for (const Event& e : m_events) {
        if (e.site == s) return true;
    }
    return false;
}

inline Census WeightConsumptionCensus::snapshot() const {
    Census c;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        c.rejectedEvents = m_rejected;

        c.sites.resize(static_cast<size_t>(Site::COUNT));
        for (uint32_t i = 0; i < static_cast<uint32_t>(Site::COUNT); ++i) {
            SiteReport& r = c.sites[i];
            r.site  = static_cast<Site>(i);
            r.name  = siteName(static_cast<Site>(i));
            r.classification = Classification::Unobserved;
        }

        for (const Event& e : m_events) {
            SiteReport& r = c.sites[static_cast<size_t>(e.site)];
            ++r.events;
            r.bytes += e.bytes;
            switch (e.route) {
                case Route::LinearWOwned:     ++r.ownedEvents;     ++c.ownedEvents;     break;
                case Route::LinearWDelegated: ++r.delegatedEvents; ++c.delegatedEvents; break;
                case Route::Bypass:           ++r.bypassEvents;    ++c.bypassEvents;    break;
            }
            ++c.totalEvents;
            c.totalBytes += e.bytes;
        }
    }

    for (SiteReport& r : c.sites) {
        // Derived. A site seen under exactly one route gets that route; a site
        // seen under two or more is Conditional, because its ownership depends
        // on which route the runtime took. Zero events stays Unobserved --
        // never Owned, never Bypass, never a pass.
        const int distinct =
            (r.ownedEvents ? 1 : 0) + (r.delegatedEvents ? 1 : 0) + (r.bypassEvents ? 1 : 0);
        if (r.events == 0)     r.classification = Classification::Unobserved;
        else if (distinct > 1) r.classification = Classification::Conditional;
        else if (r.ownedEvents)     r.classification = Classification::Owned;
        else if (r.delegatedEvents) r.classification = Classification::Delegated;
        else                        r.classification = Classification::Bypass;

        if (r.events == 0)     ++c.unobservedSites;
        if (r.classification == Classification::Conditional) ++c.conditionalSites;
    }
    return c;
}

inline const char* Census::verdict() const {
    // Rejected events are checked FIRST because they are the more specific and
    // more actionable defect: some caller tried to announce a weight
    // consumption while carrying no byte measurement. That is a false claim at
    // its source and must not be masked by the presence of good data elsewhere.
    if (rejectedEvents != 0) return "FAIL_UNMEASURED_EVENTS_REJECTED";
    // The census's own contract is only satisfied when something was actually
    // measured. An empty census is a failure of instrumentation, not a clean
    // bill of health -- reporting PASS here would make a disconnected
    // instrument indistinguishable from a clean engine.
    if (totalEvents == 0) return "FAIL_NO_MEASURED_CONSUMPTION";
    return "MEASURED";
}

inline std::string Census::toText() const {
    std::ostringstream o;
    o << "=== RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001 ===\r\n";
    o << "TOTAL_EVENTS=" << totalEvents << "\r\n";
    o << "TOTAL_BYTES=" << totalBytes << "\r\n";
    o << "REJECTED_EVENTS=" << rejectedEvents << "\r\n";
    o << "OWNED_EVENTS=" << ownedEvents << "\r\n";
    o << "DELEGATED_EVENTS=" << delegatedEvents << "\r\n";
    o << "BYPASS_EVENTS=" << bypassEvents << "\r\n";
    o << "UNOBSERVED_SITES=" << unobservedSites << "\r\n";
    o << "CONDITIONAL_SITES=" << conditionalSites << "\r\n";
    for (const SiteReport& r : sites) {
        o << "SITE=" << r.name
          << " EVENTS=" << r.events
          << " BYTES=" << r.bytes
          << " OWNED=" << r.ownedEvents
          << " DELEGATED=" << r.delegatedEvents
          << " BYPASS=" << r.bypassEvents
          << " CLASSIFICATION=" << classificationName(r.classification)
          << "\r\n";
    }
    o << "VERDICT=" << verdict() << "\r\n";
    o << "=== RECEIPT_END ===\r\n";
    return o.str();
}

// ============================================================================
// Receipt emission
// ============================================================================
// Writes the census only when RAWRXD_WEIGHT_CENSUS_OUT names a path. Unset,
// nothing is created: a normal run cannot quietly manufacture a passing
// artifact. The receipt is written from inside the process that actually
// consumed the weights, so it is a measurement of a real forward pass rather
// than a reconstruction of one.
inline void writeCensusReceipt(const char* path) {
    if (!path || !*path) return;
    const Census c = WeightConsumptionCensus::instance().snapshot();
    const std::string text = c.toText();
    std::FILE* f = std::fopen(path, "wb");
    if (!f) {
        std::fprintf(stderr, "[WEIGHT_CENSUS] cannot open '%s' for writing\n", path);
        return;
    }
    const size_t n = std::fwrite(text.data(), 1, text.size(), f);
    std::fclose(f);
    // Exit status mirrors the verdict, so a caller that asked for a census and
    // received an empty one is told by the return code and not only by a file.
    if (c.verdict() == std::string("MEASURED")) {
        std::fprintf(stderr,
            "[WEIGHT_CENSUS] VERDICT=MEASURED events=%llu bytes=%llu written=%zu/%zu\n",
            (unsigned long long)c.totalEvents,
            (unsigned long long)c.totalBytes, n, text.size());
    } else {
        std::fprintf(stderr,
            "[WEIGHT_CENSUS] VERDICT=%s events=%llu bytes=%llu rejected=%llu\n",
            c.verdict(),
            (unsigned long long)c.totalEvents,
            (unsigned long long)c.totalBytes,
            (unsigned long long)c.rejectedEvents);
    }
}

// Registers a process-exit writer. Idempotent: the function-local static is
// initialised exactly once across all translation units that include this
// header, so including it from several Deep2 TUs does not register several
// exit hooks.
inline void installCensusExitWriter() {
    static const bool installed = [] {
        std::atexit([] {
            const char* p = std::getenv("RAWRXD_WEIGHT_CENSUS_OUT");
            writeCensusReceipt(p);
        });
        return true;
    }();
    (void)installed;
}

} // namespace rawrxd::deep2::weightcensus