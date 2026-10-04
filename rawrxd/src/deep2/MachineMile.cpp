// MachineMile.cpp — RAWRXD_PREDICTOR_MACHINE_MILE_001
//
// Prediction and machine-local calibration. No execution happens here: this
// file answers "what will this cost on this machine" from geometry, quant and
// route, and Calibration folds real measurements back in afterwards.
#include "MachineMile.hpp"

#include <algorithm>
#include <cmath>
#include <map>
#include <mutex>

namespace Deep2 {
namespace mile {

// Declared before use. The earlier revision defined this helper AFTER observe(),
// which referenced it, so the calibrator had no lock at all.
std::mutex& mutex() { static std::mutex m; return m; }

const char* routeName(Route r) {
    switch (r) {
        case Route::VULKAN_HOST_GEMV: return "VULKAN_HOST_GEMV";
        case Route::VULKAN_RESIDENT:  return "VULKAN_RESIDENT";
        case Route::VULKAN_GROUPED:   return "VULKAN_GROUPED";
        case Route::CPU_PREBUILT:     return "CPU_PREBUILT";
        case Route::CPU_GENERIC:      return "CPU_GENERIC";
        case Route::NONE_AVAILABLE:   return "NONE_AVAILABLE";
    }
    return "UNKNOWN";
}

const char* isaName(Isa i) {
    switch (i) {
        case Isa::SCALAR:      return "SCALAR";
        case Isa::AVX2:        return "AVX2";
        case Isa::AVX512:      return "AVX512";
        case Isa::AVX512VNNI:  return "AVX512VNNI";
        case Isa::GPU:         return "GPU";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// Route prediction.
//
// The dominant term is kernel availability, not size. A type with no prebuilt
// kernel lands on the generic scalar path, and that path's throughput is set by
// how many blocks it must decode -- which is a function of the REPRESENTATION,
// not the file size.
// ---------------------------------------------------------------------------
Route predictRoute(const MileRequest& r) {
    if (r.rows == 0 || r.cols == 0) return Route::NONE_AVAILABLE;
    if (r.quantType == 0 && r.blockBytes == 0) {
        // F32 has no block structure; the element size stands in.
        if (r.preferGpu && r.hasGpu) return Route::VULKAN_HOST_GEMV;
        return r.prebuiltKernelAvailable ? Route::CPU_PREBUILT : Route::CPU_GENERIC;
    }
    if (r.blockElements == 0 || r.blockBytes == 0) return Route::NONE_AVAILABLE;

    if (r.preferGpu && r.hasGpu) {
        return r.transfers > 0 ? Route::VULKAN_HOST_GEMV : Route::VULKAN_RESIDENT;
    }
    if (r.prebuiltKernelAvailable) return Route::CPU_PREBUILT;

    // No prebuilt kernel for this type: generic decode path. This is the branch
    // the Q2_K story lives on, and it is reached from kernel AVAILABILITY, not
    // from the model's size in gigabytes.
    return Route::CPU_GENERIC;
}

MachineMile predict(const MileRequest& r, const MachineModel& m) {
    MachineMile mm;

    const Route route = predictRoute(r);
    mm.route = route;

    const std::uint64_t blocksPerRow =
        (r.cols + r.blockElements - 1) / (r.blockElements ? r.blockElements : 1);
    const std::uint64_t totalBlocks = blocksPerRow * r.rows;

    if (route == Route::NONE_AVAILABLE) {
        mm.estimatedNs = 0.0;
        mm.route = Route::NONE_AVAILABLE;
        return mm;
    }

    const bool quantized = (r.quantType != 0);
    const std::uint64_t packedBytes = quantized
        ? totalBlocks * r.blockBytes
        : r.rows * r.cols * sizeof(float);
    const std::uint64_t denseBytes = r.rows * r.cols * sizeof(float);

    mm.sourceBytes = packedBytes;
    mm.decodeBytes = quantized ? denseBytes : 0;
    mm.outputBytes = r.rows * sizeof(float);
    mm.macs        = r.rows * r.cols;
    mm.quantBlocks = quantized ? totalBlocks : 0;

    mm.isa    = (route == Route::VULKAN_HOST_GEMV ||
                 route == Route::VULKAN_RESIDENT) ? Isa::GPU : r.isa;
    mm.device = r.device;
    mm.syncPoints = r.syncPoints;
    mm.transfers  = r.transfers;
    mm.transforms = quantized ? 1u : 0u;
    mm.routeHops  = (mm.transfers > 0) ? 2u : 1u;

    // ---- components, each derived from a machine-local constant ----
    const bool onGpu = (route == Route::VULKAN_HOST_GEMV ||
                        route == Route::VULKAN_RESIDENT);

    if (onGpu) {
        mm.readNs = (double)mm.sourceBytes / std::max(m.deviceReadBytesPerNs, 1e-9);
        mm.transferNs = (double)(mm.sourceBytes * r.transfers) /
                        std::max(m.hostToDeviceBytesPerNs, 1e-9);
        mm.computeNs = (double)mm.macs / std::max(m.macsPerNs, 1e-9);
        mm.decodeNs = (double)mm.quantBlocks * m.decodeNsPerBlock;
    } else {
        mm.readNs = (double)mm.sourceBytes / std::max(m.readBytesPerNs, 1e-9);
        mm.transferNs = 0.0;
        mm.computeNs = (double)mm.macs / std::max(m.macsPerNs, 1e-9);
        // The generic scalar path pays decode per block. This is the term that
        // makes a low-bit representation MORE expensive than a larger one.
        mm.decodeNs = quantized
            ? (double)mm.quantBlocks * (m.decodeNsPerBlock *
                                       (route == Route::CPU_GENERIC ? 1.0 : 0.25))
            : 0.0;
    }

    mm.syncNs  = (double)r.syncPoints * m.syncNsPerPoint;
    mm.routeNs = (route == Route::CPU_GENERIC ? m.routePenaltyNs : m.routePenaltyNs * 0.25);

    mm.estimatedNs = mm.readNs + mm.decodeNs + mm.computeNs +
                     mm.transferNs + mm.syncNs + mm.routeNs;
    return mm;
}

double predictTps(const std::vector<MachineMile>& miles) {
    double total = 0.0;
    for (const auto& m : miles) total += m.estimatedNs;
    if (total <= 0.0) return 0.0;
    return 1e9 / total;
}

// ---------------------------------------------------------------------------
// Calibration
// ---------------------------------------------------------------------------
Calibration& Calibration::Instance() {
    static Calibration c; return c;
}

void Calibration::observe(const MileRequest& r, Route actualRoute, double actualNs) {
    Sample s;
    s.req = r;
    s.actual = actualRoute;
    s.actualNs = actualNs;

    // Derive the derived quantities from the REQUEST, not from a measurement,
    // so the predictor and the calibrator agree on what "bytes" means.
    const std::uint64_t blocksPerRow =
        (r.cols + r.blockElements - 1) / (r.blockElements ? r.blockElements : 1);
    const std::uint64_t totalBlocks = blocksPerRow * r.rows;
    const bool quantized = (r.quantType != 0);
    s.bytes  = quantized ? (double)(totalBlocks * r.blockBytes)
                          : (double)(r.rows * r.cols * sizeof(float));
    s.blocks = quantized ? (double)totalBlocks : 0.0;
    s.macs   = (double)(r.rows * r.cols);

    // The prediction that was in force BEFORE this observation. Derived from a
    // model built on everything except this sample, so the reported error is a
    // genuine held-out prediction and not a fit to the point it is scored on.
    const MachineModel prior = derive();
    const MachineMile p = predict(r, prior);
    s.predictedNs = p.estimatedNs;

    std::lock_guard<std::mutex> g(mutex());
    samples_.push_back(s);
    (void)actualRoute;
}

namespace {
} // namespace

MachineModel Calibration::derive() const {
    MachineModel m;
    if (samples_.empty()) {
        m.note = "UNCALIBRATED_NO_SAMPLES";
        return m;
    }

    // Read bandwidth: bytes / time on CPU routes.
    double bytesOverNsCpu = 0.0;
    double bytesOverNsGpu = 0.0;
    double macsPerNs = 0.0;
    double blocksPerNs = 0.0;
    int nCpu = 0, nGpu = 0;

    for (const auto& s : samples_) {
        if (s.actualNs <= 0.0) continue;
        const bool onGpu = (s.actual == Route::VULKAN_HOST_GEMV ||
                            s.actual == Route::VULKAN_RESIDENT);
        if (onGpu) { bytesOverNsGpu += s.bytes / s.actualNs; ++nGpu; }
        else       { bytesOverNsCpu += s.bytes / s.actualNs; ++nCpu; }
        macsPerNs += s.macs / s.actualNs;
        if (s.blocks > 0.0) blocksPerNs += s.blocks / s.actualNs;
    }

    const int n = (int)samples_.size();
    if (nCpu > 0) m.readBytesPerNs = bytesOverNsCpu / nCpu;
    if (nGpu > 0) m.deviceReadBytesPerNs = bytesOverNsGpu / nGpu;
    if (n > 0)    m.macsPerNs = macsPerNs / n;
    // Decode cost is expressed per block and inverted from measured block
    // throughput: a higher measured blocks/ns means a lower ns/block.
    if (blocksPerNs > 0.0) m.decodeNsPerBlock = 1.0 / blocksPerNs;

    // Defaults where this machine has no measurement yet. They are marked as
    // defaults by leaving calibrated=false on the derived model when used.
    if (m.readBytesPerNs <= 0.0) { m.readBytesPerNs = 8.0; m.note = "readBw defaulted"; }
    if (m.deviceReadBytesPerNs <= 0.0) m.deviceReadBytesPerNs = 200.0;
    if (m.hostToDeviceBytesPerNs <= 0.0) m.hostToDeviceBytesPerNs = 8.0;
    if (m.macsPerNs <= 0.0) { m.macsPerNs = 2.0; m.note = "macRate defaulted"; }
    if (m.decodeNsPerBlock <= 0.0) { m.decodeNsPerBlock = 0.5; m.note = "decode defaulted"; }
    m.syncNsPerPoint = 20000.0;      // a dispatch + fence, order of magnitude
    m.routePenaltyNs = m.decodeNsPerBlock * 0.5;
    m.calibrated = (nCpu > 0);
    if (m.note.empty()) m.note = "DERIVED_FROM_MEASUREMENTS";
    return m;
}

Calibration::Accuracy Calibration::accuracy() const {
    Accuracy a;
    double sumAbs = 0.0, maxAbs = 0.0, sumSigned = 0.0;
    for (const auto& s : samples_) {
        if (s.actualNs <= 0.0) continue;
        const double pred = s.predictedNs > 0.0 ? s.predictedNs : s.actualNs;
        // Positive error means the predictor was OPTIMISTIC: it said the work
        // would take less time than it did.
        const double signedPct = 100.0 * (s.actualNs - pred) / s.actualNs;
        const double absPct = std::fabs(signedPct);
        sumAbs += absPct;
        sumSigned += signedPct;
        if (absPct > maxAbs) maxAbs = absPct;
        ++a.samples;
    }
    if (a.samples) {
        a.meanAbsPct    = sumAbs / (double)a.samples;
        a.meanSignedPct = sumSigned / (double)a.samples;
        a.maxAbsPct     = maxAbs;
    }
    return a;
}

std::size_t Calibration::size() const {
    std::lock_guard<std::mutex> g(mutex());
    return samples_.size();
}

void Calibration::clear() {
    std::lock_guard<std::mutex> g(mutex());
    samples_.clear();
}

// ---------------------------------------------------------------------------
// ExecutionMap. The payload is the SHARE, because the question this map exists
// to answer is "where will the time go", and a total alone cannot aim the Loom.
// ---------------------------------------------------------------------------
std::vector<ExecutionMap::Share> ExecutionMap::shares() const {
    std::vector<Share> out;
    if (totalEstimatedNs <= 0.0) return out;
    out.reserve(miles.size());
    for (std::size_t i = 0; i < miles.size(); ++i) {
        Share s;
        s.label = (i < labels.size()) ? labels[i] : ("mile" + std::to_string(i));
        s.pct   = 100.0 * miles[i].estimatedNs / totalEstimatedNs;
        out.push_back(s);
    }
    std::sort(out.begin(), out.end(),
              [](const Share& a, const Share& b) { return a.pct > b.pct; });
    return out;
}

} // namespace mile
} // namespace Deep2