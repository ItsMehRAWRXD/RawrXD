#pragma once
// ============================================================================
// MachineMile.hpp — RAWRXD_PREDICTOR_MACHINE_MILE_001
// Extended with DREAM/REVERSE active calibration — RAWRXD_DREAM_REVERSE_ACTIVE_CALIBRATION_002
//
// PREDICT BEFORE EXECUTE.
//
// A benchmark measures after execution. This describes, before the token path
// is taken, how much effective machine travel one operation will require on the
// route it will actually take.
//
// The central distinction:
//
//     MODEL_BYTES  !=  MACHINE_MILES
//
// A 1.3 GB Q2_K tensor can require more machine travel per useful output than a
// 4.8 GB Q4_K tensor, because the decode and route costs are not proportional
// to file size. Model size is therefore NOT the primary predictor.
//
// Every component is exposed. There is deliberately no opaque single score:
// a caller that cannot see WHY a prediction is expensive cannot aim the Kernel
// Loom at the expensive edge.
//
// DREAM/REVERSE ACTIVE CALIBRATION:
// The predictor no longer runs a static sweep. It proposes DREAM cost models,
// REVERSE-engineers what unknown prevents reaching the target, and VALUE
// selects the highest-gain next measurement. BYTES_ONLY is a REQUIEM candidate.
// ============================================================================

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace Deep2 {
namespace mile {

// ---------------------------------------------------------------------------
// The route a kernel would take. Predicted first, then confirmed.
// ---------------------------------------------------------------------------
enum class Route : std::uint8_t {
    VULKAN_HOST_GEMV = 0,
    VULKAN_RESIDENT  = 1,
    VULKAN_GROUPED   = 2,
    CPU_PREBUILT     = 3,   // MASM / intrinsics kernel
    CPU_GENERIC      = 4,   // scalar fallback
    NONE_AVAILABLE   = 5,
};

const char* routeName(Route r);

enum class Isa : std::uint8_t {
    SCALAR = 0, AVX2 = 1, AVX512 = 2, AVX512VNNI = 3, GPU = 4,
};

const char* isaName(Isa i);

// ---------------------------------------------------------------------------
// QUANTIZATION TYPE ENUMERATION (stable indices for per-quant calibration)
// ---------------------------------------------------------------------------
enum class QuantType : std::uint8_t {
    F32       = 0,
    F16       = 1,
    Q8_0      = 2,
    Q6_K      = 3,
    Q5_K      = 4,
    Q4_K      = 5,
    Q4_0      = 6,
    Q2_K      = 7,
    COUNT     = 8
};

// ---------------------------------------------------------------------------
// GEOMETRY ENUMERATION (calibration matrix rows)
// ---------------------------------------------------------------------------
enum class GeometryCell : std::uint8_t {
    GEOM_A_128x4096 = 0,   // 128 x 4096
    GEOM_B_256x4096 = 1,   // 256 x 4096 (reference cell where F16=15.88x Q2_K)
    GEOM_C_512x4096 = 2,   // 512 x 4096
    GEOM_D_256x2048 = 3,   // 256 x 2048
    GEOM_E_256x8192 = 4,   // 256 x 8192
    COUNT           = 5
};

// ---------------------------------------------------------------------------
// DREAM COST HYPOTHESES (candidate models of what determines kernel cost)
// Each is a candidate cost law. DREAM proposes; REQUIEM discards.
// ---------------------------------------------------------------------------
enum class DreamHypothesis : std::uint8_t {
    DREAM_A_BYTES_ONLY           = 0,  // cost = bytes * bw^-1  (REQUIEM candidate)
    DREAM_B_QUANT_DECODE_PLUS_MATH = 1, // cost = decode(quant) + macs * rate
    DREAM_C_QUANT_EFFECTIVE_BW   = 2,  // cost = bytes / bw_eff(quant)
    DREAM_D_QUANT_ISA_GEOMETRY   = 3,  // cost = f(quant, ISA, geometry)
    DREAM_E_PIECEWISE_MACHINE_LOCAL = 4, // piecewise per (quant, ISA, geometry) cell
    COUNT                        = 5
};

const char* dreamName(DreamHypothesis d);

// ---------------------------------------------------------------------------
// One prospective operation cost. Every field is a component, not a summary.
// ---------------------------------------------------------------------------
struct MachineMile {
    // --- work ---
    std::uint64_t sourceBytes   = 0;   // representation bytes that must be read
    std::uint64_t decodeBytes   = 0;   // bytes produced by dequantisation
    std::uint64_t outputBytes   = 0;
    std::uint64_t macs          = 0;
    std::uint64_t quantBlocks   = 0;

    // --- shape of the journey ---
    std::uint32_t routeHops     = 0;
    std::uint32_t transforms    = 0;   // dequant / requantise / convert
    std::uint32_t syncPoints    = 0;
    std::uint32_t transfers     = 0;

    Route route = Route::NONE_AVAILABLE;
    Isa   isa   = Isa::SCALAR;
    int   device = -1;

    // --- the prediction, with its parts intact ---
    double readNs      = 0.0;
    double decodeNs    = 0.0;
    double computeNs   = 0.0;
    double transferNs  = 0.0;
    double syncNs      = 0.0;
    double routeNs     = 0.0;
    double estimatedNs = 0.0;   // sum of the above; never the only field read

    // --- DREAM attribution ---
    DreamHypothesis dream = DreamHypothesis::DREAM_E_PIECEWISE_MACHINE_LOCAL;
    double          dreamResidual = 0.0;  // prediction error under this hypothesis
};

// ---------------------------------------------------------------------------
// MACHINE-MILE OBSERVATION: decomposed latency from a real measurement.
// Exposes enough variables to distinguish WHY F16 crushes Q2_K.
// ---------------------------------------------------------------------------
struct MachineMileObservation {
    QuantType quant;

    uint32_t rows;
    uint32_t cols;

    Route actualRoute;
    Isa   actualISA;

    uint64_t sourceBytes;
    uint64_t quantBlocks;

    // Decomposed latency (in nanoseconds, measured via QueryPerformanceCounter or PMU)
    uint64_t decodeNs;
    uint64_t loadNs;
    uint64_t mathNs;
    uint64_t tailNs;

    // Execution shape
    uint64_t vectorIterations;
    uint64_t scalarIterations;

    // Cache/memory behavior (when PMU available)
    uint64_t l1Misses;
    uint64_t l2Misses;
    uint64_t branchCount;

    uint64_t totalNs;

    // DREAM attribution for this observation
    DreamHypothesis bestDream;
    double          bestDreamResidualPct;
};

// ---------------------------------------------------------------------------
// PROBE VALUE: what makes a cell worth measuring next?
// VALUE = disagreement * uncertainty * endpointRelevance / probeCost
// ---------------------------------------------------------------------------
struct ProbeValue {
    double modelDisagreement;    // max |pred_i - pred_j| across surviving DREAMs
    double uncertainty;          // calibration uncertainty for this cell
    double endpointRelevance;    // how much this cell affects the endpoint target
    double estimatedProbeNs;     // predicted cost to measure this cell

    double score() const {
        const double denom = std::max(estimatedProbeNs, 1.0);
        return modelDisagreement * uncertainty * endpointRelevance / denom;
    }
};

// ---------------------------------------------------------------------------
// Machine-local constants. Calibrated FROM MEASUREMENT on this machine; never
// taken from a vendor number or an internet benchmark.
// ---------------------------------------------------------------------------
struct MachineModel {
    double readBytesPerNs      = 0.0;   // host read bandwidth
    double deviceReadBytesPerNs = 0.0;
    double hostToDeviceBytesPerNs = 0.0;
    double macsPerNs           = 0.0;
    double decodeNsPerBlock    = 0.0;
    double syncNsPerPoint      = 0.0;
    double routePenaltyNs      = 0.0;

    // ---- per-representation calibration ----
    //
    // Measured: at ONE fixed geometry (256x4096), one fixed CPU and one call
    // site, the actual cost spread 15.88x ACROSS QUANT TYPES. A model built
    // from global scalars therefore cannot fit this data at any constant
    // choice -- the first attempt mispredicted by 85% on average and by 2807%
    // on F16, because it averaged a 42 GB/s kernel together with a 0.4 GB/s
    // one.
    //
    // The representation IS the predictor, so the model is per representation.
    // The global scalars above are only the fallback for a type never observed.
    struct PerQuant {
        double readBytesPerNs   = 0.0;
        double decodeNsPerBlock = 0.0;
        double macsPerNs        = 0.0;
        std::uint64_t samples   = 0;
    };
    std::vector<std::pair<std::uint32_t, PerQuant>> perQuant;

    const PerQuant* forQuant(std::uint32_t quantType) const;

    // --- DREAM-specific per-quant, per-geometry, per-ISA calibration ---
    // Key: (QuantType << 16) | (GeometryCell << 8) | Isa
    // Only populated when that cell is measured.
    struct DreamCalibration {
        double decodeNsPerBlock = 0.0;
        double macsPerNs        = 0.0;
        double readBytesPerNs   = 0.0;
        double uncertainty      = 1.0;   // 1.0 = unmeasured, decreases with samples
        uint64_t samples        = 0;
        DreamHypothesis activeDream = DreamHypothesis::DREAM_E_PIECEWISE_MACHINE_LOCAL;
    };
    std::vector<std::pair<uint32_t, DreamCalibration>> dreamCalib;

    const DreamCalibration* forDreamKey(uint32_t key) const;

    bool calibrated = false;
    std::string   note;
};

// ---------------------------------------------------------------------------
// Machine-local constants. Calibrated FROM MEASUREMENT on this machine; never
// taken from a vendor number or an internet benchmark.
// ---------------------------------------------------------------------------
struct MachineModel {
    double readBytesPerNs      = 0.0;   // host read bandwidth
    double deviceReadBytesPerNs = 0.0;
    double hostToDeviceBytesPerNs = 0.0;
    double macsPerNs           = 0.0;
    double decodeNsPerBlock    = 0.0;
    double syncNsPerPoint      = 0.0;
    double routePenaltyNs      = 0.0;

    // ---- per-representation calibration ----
    //
    // Measured: at ONE fixed geometry (256x4096), one fixed CPU and one call
    // site, the actual cost spread 15.88x ACROSS QUANT TYPES. A model built
    // from global scalars therefore cannot fit this data at any constant
    // choice -- the first attempt mispredicted by 85% on average and by 2807%
    // on F16, because it averaged a 42 GB/s kernel together with a 0.4 GB/s
    // one.
    //
    // The representation IS the predictor, so the model is per representation.
    // The global scalars above are only the fallback for a type never observed.
    struct PerQuant {
        double readBytesPerNs   = 0.0;
        double decodeNsPerBlock = 0.0;
        double macsPerNs        = 0.0;
        std::uint64_t samples   = 0;
    };
    std::vector<std::pair<std::uint32_t, PerQuant>> perQuant;

    const PerQuant* forQuant(std::uint32_t quantType) const;

    bool calibrated = false;
    std::string   note;
};

// ---------------------------------------------------------------------------
// The request. Enough to predict, not enough to execute.
// ---------------------------------------------------------------------------
struct MileRequest {
    std::uint32_t quantType   = 0;
    std::uint32_t blockElements = 0;
    std::uint32_t blockBytes  = 0;
    std::uint64_t rows = 0, cols = 0;

    bool     preferGpu = false;
    bool     hasGpu    = false;
    bool     prebuiltKernelAvailable = false;
    Isa      isa = Isa::SCALAR;
    int      device = -1;
    std::uint32_t syncPoints = 0;
    std::uint32_t transfers  = 0;
};

// Predict the route WITHOUT running anything.
Route predictRoute(const MileRequest& r);

// Predict the cost, component by component.
MachineMile predict(const MileRequest& r, const MachineModel& m);

// Convenience: predicted tokens/second for a forward graph made of these miles.
double predictTps(const std::vector<MachineMile>& miles);

// ---------------------------------------------------------------------------
// Machine-local calibration, keyed on the shape that actually determines cost.
// Keying on the quant type AND the route is what makes the model specific to
// THIS machine's kernels rather than generic.
// ---------------------------------------------------------------------------
class Calibration {
public:
    static Calibration& Instance();

    // Fold a real measurement into the model.
    void observe(const MileRequest& r, Route actualRoute, double actualNs);

    // Build the derived model from everything observed so far.
    MachineModel derive() const;

    // Prediction accuracy over everything observed, per component.
    struct Accuracy {
        std::uint64_t samples = 0;
        double meanAbsPct = 0.0;
        double maxAbsPct  = 0.0;
        double meanSignedPct = 0.0;   // positive == predictor was optimistic
    };
    Accuracy accuracy() const;

    std::size_t size() const;
    void clear();

private:
    Calibration() = default;
    struct Sample {
        MileRequest req;
        Route actual;
        double actualNs;
        double predictedNs;
        double bytes;
        double blocks;
        double macs;
    };
    std::vector<Sample> samples_;
};

// ---------------------------------------------------------------------------
// A prospective execution map for a whole model, produced BEFORE decode.
// This is what lets the Loom aim at the expensive edge instead of probing
// blindly.
// ---------------------------------------------------------------------------
struct ExecutionMap {
    std::vector<MachineMile> miles;
    std::vector<std::string> labels;
    double totalEstimatedNs = 0.0;

    // Percentage of total predicted cost, largest first. The point of the map is
    // to answer "where will the time go", so the share is the payload.
    struct Share { std::string label; double pct = 0.0; };
    std::vector<Share> shares() const;
};

} // namespace mile
} // namespace Deep2