// ============================================================================
// WeightConsumptionCensus.hpp — RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001
//
// Records where model-weight bytes are ACTUALLY consumed during inference.
// Every record is an observation, not an assertion. The census is the
// authority for whether a weight reached a numeric kernel through the
// expected route or bypassed it.
//
// This file exists because LinearW() is a routing boundary, not a compute
// owner. A hook placed only inside LinearW misses embedToken, grouped GEMV,
// and the resident GPU graph. The census makes every bypass measurable.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <mutex>

namespace rawrxd::deep2::weightcensus {

enum class Site : uint8_t {
    Unknown = 0,
    EmbedToken,
    LinearW,
};

enum class Route : uint8_t {
    Unknown = 0,
    Bypass,           // weight consumed without passing through LinearW
    LinearWDelegated, // weight arithmetic performed by a callee of LinearW
    LinearWOwned,     // weight arithmetic performed by LinearW's own kernel
};

struct Event {
    Site        site   = Site::Unknown;
    Route       route  = Route::Unknown;
    std::string tensor;   // tensor name or identifier
    uint64_t    bytes  = 0; // bytes consumed at this site
};

struct CensusRecord {
    Event       event;
    uint64_t    sequence = 0; // insertion order
};

class WeightConsumptionCensus {
public:
    static WeightConsumptionCensus& instance();

    // Record a consumption event. Thread-safe.
    bool record(const Event& ev);

    // Retrieve all records. Thread-safe copy.
    std::vector<CensusRecord> records() const;

    // Clear all records.
    void reset();

    // Summary: counts per site/route.
    struct Summary {
        uint64_t totalEvents = 0;
        uint64_t bypassCount = 0;
        uint64_t delegatedCount = 0;
        uint64_t ownedCount = 0;
        uint64_t totalBytes = 0;
    };
    Summary summary() const;

private:
    WeightConsumptionCensus() = default;
    ~WeightConsumptionCensus() = default;
    WeightConsumptionCensus(const WeightConsumptionCensus&) = delete;
    WeightConsumptionCensus& operator=(const WeightConsumptionCensus&) = delete;

    mutable std::mutex mtx_;
    std::vector<CensusRecord> records_;
    uint64_t nextSeq_ = 1;
};

} // namespace rawrxd::deep2::weightcensus
