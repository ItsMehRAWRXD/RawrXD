// machine_mile_probe.cpp — RAWRXD_PREDICTOR_MACHINE_MILE_001
//
// PREDICT -> EXECUTE -> MEASURE -> RECORD ERROR -> RECALIBRATE
//
// The falsifiable core is that the PREDICTION must be made before the kernel
// runs, and the error against the measurement must be recorded. A predictor
// fitted and scored on the same points is not a predictor.
//
// Design:
//   * The first CALIBRATION_CELLS cells are executed and used only to build the
//     machine model. Their own predictions were made from a model that did NOT
//     include them, so their errors are held out.
//   * The remaining cells are predicted from the calibrated model and executed
//     afterwards. Their predicted-vs-actual pair is the honest accuracy figure.
//   * Every cell prints PREDICTED_ROUTE and ACTUAL_ROUTE. Where they disagree,
//     that disagreement is the finding.
//
// Nothing here is a model of a machine. Every constant is derived from a
// measurement taken in this process.

#include "MachineMile.hpp"
#include "QuantKernelRegistry.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

using namespace Deep2;
using namespace Deep2::mile;

namespace {

struct Cell {
    int         quantType = 0;
    const char* name = "";
    std::uint32_t rows = 0, cols = 0;
    bool        gpuRoute = false;
    std::size_t calibIndex = 0;   // 0..CALIB-1 for calibration cells
};

// Describe which prebuilt kernel, if any, this machine resolves for the type.
bool hasPrebuilt(int qt) {
    return QuantKernelRegistry::Instance().GetGEMV(qt) != nullptr;
}

// Rebuild the request from a cell. Shared by the runner and the calibrator so
// the predictor and the recorder cannot disagree about what was predicted.
MileRequest makeRequest(const Cell& c) {
    MileRequest r;
    const auto* d = LookupQuantType((std::uint32_t)c.quantType);
    if (d) {
        r.quantType = c.quantType;
        r.blockElements = d->blockElements;
        r.blockBytes = d->blockBytes;
    }
    r.rows = c.rows;
    r.cols = c.cols;
    r.preferGpu = c.gpuRoute;
    r.hasGpu = false;
    r.prebuiltKernelAvailable = hasPrebuilt(c.quantType);
    r.isa = Isa::SCALAR;
    r.syncPoints = 1;
    return r;
}

struct Outcome {
    Route predicted = Route::NONE_AVAILABLE;
    Route actual = Route::NONE_AVAILABLE;
    double predictedNs = 0.0;
    double actualNs = 0.0;
    double signedPct = 0.0;
    bool   ran = false;
    std::string note;
};

Outcome runCell(const Cell& c, const MachineModel& model) {
    Outcome o;
    const auto* d = LookupQuantType((std::uint32_t)c.quantType);
    if (!d) { o.note = "UNKNOWN_TYPE"; return o; }

    MileRequest r;
    r.quantType = c.quantType;
    r.blockElements = d->blockElements;
    r.blockBytes = d->blockBytes;
    r.rows = c.rows;
    r.cols = c.cols;
    r.preferGpu = c.gpuRoute;
    r.hasGpu = false;                 // measured CPU-only for this probe
    r.prebuiltKernelAvailable = hasPrebuilt(c.quantType);
    r.isa = Isa::SCALAR;
    r.syncPoints = 1;

    // ---- PREDICT, BEFORE anything is executed ----
    const MachineMile p = predict(r, model);
    o.predicted = p.route;
    o.predictedNs = p.estimatedNs;

    // ---- only now execute ----
    auto gemv = QuantKernelRegistry::Instance().GetGEMV(c.quantType);
    auto deq  = QuantKernelRegistry::Instance().GetDequant(c.quantType);
    if (!gemv) { o.note = "NO_GEMV"; return o; }

    o.actual = r.prebuiltKernelAvailable ? Route::CPU_PREBUILT : Route::CPU_GENERIC;

    const std::uint64_t blocksPerRow =
        (c.cols + d->blockElements - 1) / (d->blockElements ? d->blockElements : 1);
    const std::uint64_t bytes =
        (c.quantType == 0)
            ? (std::uint64_t)c.rows * c.cols * 4u
            : blocksPerRow * c.rows * d->blockBytes;

    std::vector<std::uint8_t> w(bytes);
    std::mt19937 rng(99991 + (std::uint32_t)c.calibIndex);
    for (auto& b : w) b = (std::uint8_t)(rng() & 0xFF);
    std::vector<float> x(c.cols), y(c.rows);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    for (auto& v : x) v = dist(rng);
    for (auto& v : y) v = 0.0f;

    // Warm, then measure best-of.
    gemv(w.data(), x.data(), y.data(), c.rows, c.cols);

    LARGE_INTEGER f, t0, t1;
    QueryPerformanceFrequency(&f);
    double best = 1e300;
    const int reps = 8;
    for (int k = 0; k < 3; ++k) {
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < reps; ++i)
            gemv(w.data(), x.data(), y.data(), c.rows, c.cols);
        QueryPerformanceCounter(&t1);
        const double ns = (double)(t1.QuadPart - t0.QuadPart) * 1e9 /
                          (double)f.QuadPart / (double)reps;
        if (ns < best) best = ns;
    }
    o.actualNs = best;
    o.ran = true;

    if (o.actualNs > 0.0 && o.predictedNs > 0.0) {
        // Positive means the predictor was optimistic.
        o.signedPct = 100.0 * (o.actualNs - o.predictedNs) / o.actualNs;
    }
    return o;
}

} // namespace

int main(int argc, char** argv) {
    const std::uint32_t rows = (argc > 1) ? (std::uint32_t)std::atoi(argv[1]) : 256;
    const std::uint32_t cols = (argc > 2) ? (std::uint32_t)std::atoi(argv[2]) : 4096;
    const int CALIBRATION_CELLS = 6;

    std::printf("RAWRXD_PREDICTOR_MACHINE_MILE_001\n");
    std::printf("====================================\n");
    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();
    reg.ProbeCPU();
    const CPUFeatures& cf = reg.cpuFeatures();
    std::printf("ISA cpu: avx2=%d avx512f=%d avx512vnni=%d fma=%d\n",
                cf.avx2 ? 1 : 0, cf.avx512f ? 1 : 0, cf.avx512vnni ? 1 : 0, cf.fma ? 1 : 0);
    std::printf("GEOMETRY rows=%u cols=%u   CALIBRATION_CELLS=%d\n",
                rows, cols, CALIBRATION_CELLS);
    std::printf("MODEL_SIZE_PRIMARY_PREDICTOR=0\n");
    std::printf("PREDICT_BEFORE_EXECUTE=1\n");
    std::printf("------------------------\n");

    // Two geometry classes so the predictor is exercised on more than one shape,
    // and the same quant type appears at more than one size -- which is the point
    // that model size is not the predictor.
    std::vector<Cell> cells;
    const int qtOrder[] = {0, 2, 8, 12, 14, 13, 10, 1, 32, 34, 39};
    std::size_t idx = 0;
    for (int qt : qtOrder) {
        const auto* d = LookupQuantType((std::uint32_t)qt);
        if (!d) continue;
        if (d->blockElements == 0 || d->blockBytes == 0) continue;
        if ((cols % d->blockElements) != 0) continue;
        if (!reg.GetGEMV(qt)) continue;          // cannot execute it, so skip
        Cell c;
        c.quantType = qt;
        c.name = d->name ? d->name : "?";
        c.rows = rows;
        c.cols = cols;
        c.calibIndex = idx++;
        cells.push_back(c);
    }

    std::printf("CELLS=%zu\n", cells.size());

    // ---- PHASE 1: calibration. ----
    //
    // The first cell is a BOOTSTRAP and is deliberately NOT scored. It is
    // executed to measure bandwidth, and predicting it against an empty model
    // produced a 5.2e15 percent error, which is arithmetic noise rather than
    // evidence about the predictor. An uncalibrated model has no business being
    // graded.
    //
    // Cells after the bootstrap ARE scored, and their prediction is made from a
    // model that already contains the bootstrap but NOT themselves, so their
    // error is held out.
    std::printf("---- phase 1: calibration ----\n");
    std::printf("  (cell 0 is a bootstrap: measured to seed the model, not scored)\n");
    double sumAbs = 0.0, sumSigned = 0.0, maxAbs = 0.0;
    int calibN = 0;
    int routeDisagree = 0;
    int unscored = 0;

    for (std::size_t i = 0; i < cells.size() && i < (std::size_t)CALIBRATION_CELLS; ++i) {
        const Cell& c = cells[i];
        const MachineModel prior = Calibration::Instance().derive();
        const bool scored = prior.calibrated;   // false only for the bootstrap
        Outcome o = runCell(c, prior);

        std::printf("CALIB qt=%-3d %-10s pred_route=%-16s act_route=%-16s "
                    "pred_ns=%12.1f act_ns=%12.1f err=%+9.2f%%%s\n",
                    c.quantType, c.name, routeName(o.predicted), routeName(o.actual),
                    o.predictedNs, o.actualNs, o.signedPct,
                    scored ? "" : "   (bootstrap, unscored)");

        if (o.ran && scored) {
            sumAbs += std::fabs(o.signedPct);
            sumSigned += o.signedPct;
            if (std::fabs(o.signedPct) > maxAbs) maxAbs = std::fabs(o.signedPct);
            ++calibN;
        } else if (o.ran) {
            ++unscored;
        }
        if (scored && o.predicted != o.actual) ++routeDisagree;
        Calibration::Instance().observe(makeRequest(cells[i]), o.actual, o.actualNs);
    }

    // ---- PHASE 2: honest prediction from the calibrated model ----
    std::printf("---- phase 2: held-out prediction (model already calibrated) ----\n");
    std::printf("%-4s %-10s %-16s %-16s %12s %12s %9s %10s\n",
                "QT", "NAME", "PREDICTED_ROUTE", "ACTUAL_ROUTE",
                "PREDICTED_NS", "ACTUAL_NS", "ERROR%", "GB_PER_SEC");

    double heldAbs = 0.0, heldSigned = 0.0, heldMax = 0.0;
    int heldN = 0, heldDisagree = 0;
    Outcome fastest{}, slowest{};
    bool haveRange = false;

    int firstHeld = (int)cells.size(); if (firstHeld > CALIBRATION_CELLS) firstHeld = CALIBRATION_CELLS;
    for (int i = firstHeld; i < (int)cells.size(); ++i) {
        const Cell& c = cells[i];
        const MachineModel model = Calibration::Instance().derive();
        Outcome o = runCell(c, model);
        if (!o.ran) {
            std::printf("%-4d %-10s %-16s %-16s %12s %12s %9s %10s  %s\n",
                        c.quantType, c.name, routeName(o.predicted), "-", "-", "-",
                        "-", "-", o.note.c_str());
            continue;
        }
        const double bytes = (c.quantType == 0)
            ? (double)c.rows * c.cols * 4.0
            : (double)((c.cols + LookupQuantType((std::uint32_t)c.quantType)->blockElements - 1) /
                       LookupQuantType((std::uint32_t)c.quantType)->blockElements) *
                       c.rows * LookupQuantType((std::uint32_t)c.quantType)->blockBytes;
        const double gbs = bytes / (o.actualNs * 1e-9) / 1e9;

        std::printf("%-4d %-10s %-16s %-16s %12.1f %12.1f %+8.2f%% %10.3f\n",
                    c.quantType, c.name, routeName(o.predicted), routeName(o.actual),
                    o.predictedNs, o.actualNs, o.signedPct, gbs);

        heldAbs += std::fabs(o.signedPct);
        heldSigned += o.signedPct;
        if (std::fabs(o.signedPct) > heldMax) heldMax = std::fabs(o.signedPct);
        ++heldN;
        if (o.predicted != o.actual) ++heldDisagree;
        if (!haveRange || o.actualNs < fastest.actualNs) { fastest = o; haveRange = true; }
        if (!haveRange || o.actualNs > slowest.actualNs) { slowest = o; haveRange = true; }
    }

    Calibration::Accuracy acc = Calibration::Instance().accuracy();
    std::printf("------------------------\n");
    std::printf("CALIBRATION_SAMPLES=%d\n", calibN);
    std::printf("CALIBRATION_BOOTSTRAP_UNSCORED=%d\n", unscored);
    std::printf("CALIBRATION_MEAN_ABS_ERR_PCT=%.2f\n", calibN ? sumAbs / calibN : 0.0);
    std::printf("CALIBRATION_MEAN_SIGNED_ERR_PCT=%.2f\n", calibN ? sumSigned / calibN : 0.0);
    std::printf("CALIBRATION_MAX_ABS_ERR_PCT=%.2f\n", maxAbs);
    std::printf("HELD_OUT_SAMPLES=%d\n", heldN);
    std::printf("HELD_OUT_MEAN_ABS_ERR_PCT=%.2f\n", heldN ? heldAbs / heldN : 0.0);
    std::printf("HELD_OUT_MEAN_SIGNED_ERR_PCT=%.2f\n", heldN ? heldSigned / heldN : 0.0);
    std::printf("HELD_OUT_MAX_ABS_ERR_PCT=%.2f\n", heldMax);
    std::printf("ROUTE_DISAGREEMENTS_CALIB=%d\n", routeDisagree);
    std::printf("ROUTE_DISAGREEMENTS_HELD=%d\n", heldDisagree);
    std::printf("ACCURACY_SAMPLES=%llu\n", (unsigned long long)acc.samples);

    if (haveRange && fastest.actualNs > 0.0) {
        const double ratio = slowest.actualNs / fastest.actualNs;
        std::printf("SPREAD_SAME_GEOMETRY=%.2fx\n", ratio);
        std::printf("PREDICTOR_QUANT_AND_KERNEL=%s\n",
                    ratio >= 3.0 ? "DOMINANT" : "NOT_DOMINANT_AT_THIS_GEOMETRY");
        if (ratio >= 3.0) {
            std::printf("FALSIFIED_SIZE_AS_PRIMARY_PREDICTOR=1\n");
            std::printf("  reason: identical rows/cols, identical CPU, identical "
                        "call site, yet %.2fx spread between quant types\n", ratio);
        }
    }

    // An honest predictor states its own error. A large held-out error is a
    // result, not something to hide behind a verdict of PASS.
    const bool usable = (heldN > 0) && (heldMax <= 100.0);
    std::printf("PREDICTOR_USABLE_AT_THIS_MACHINE=%d\n", usable ? 1 : 0);
    std::printf("VERDICT=%s\n", usable ? "IMPLEMENTED_WITH_MEASURED_ERROR" : "NEEDS_CALIBRATION");
    return 0;
}