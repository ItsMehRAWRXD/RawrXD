#include "rawrxd/src/deep2/Deep2B36WaveDot.hpp"
#include "rawrxd/src/deep2/Deep2B37RegisterTune.hpp"
#include "rawrxd/src/deep2/Deep2B38CoopGemv.hpp"
#include "rawrxd/src/deep2/Deep2B39FamilySpecializer.hpp"
#include "rawrxd/src/deep2/Deep2B40PhysicalSeal.hpp"
#include <cstdio>
#include <vector>

using namespace Deep2;

static int fail(const char* x) {
    std::printf("FAIL=%s\n", x);
    return 1;
}

int main() {
    // B36 WaveDot
    B36WaveDotShape s36{16384, 8192, B36WaveMode::WAVE_64, 4, 32};
    auto p36 = B36WaveDot::make(s36);
    if (!p36.waveDotInstruction || !p36.crosslaneReduce || !p36.registerBlocking || !p36.noScalarFallback)
        return fail("B36");

    // B37 RegisterTune
    B37RegisterShape s37{};
    s37.cols = 8192; s37.waveWidth = 64; s37.bitsPerWeight = 4;
    s37.targetRegsPerLane = 64; s37.ldsBytesAvailable = 65536;
    auto p37 = B37RegisterTune::make(s37);
    if (!p37.registerTiled || !p37.fusedAccumulate)
        return fail("B37");
    if (B37RegisterTune::totalRegsUsed(p37) > s37.targetRegsPerLane)
        return fail("B37_REG_BUDGET");

    // B38 CoopGemv
    B38CoopShape s38{};
    s38.rows = 16384; s38.cols = 8192; s38.waveWidth = 64; s38.numWaves = 2; s38.bitsPerWeight = 4;
    auto p38 = B38CoopGemv::make(s38);
    if (!p38.cooperativeGemv || !p38.ldsReduction || !p38.noHostReduce || !p38.waveSpecialization)
        return fail("B38");
    if (p38.wavesCooperating != 2)
        return fail("B38_WAVES");

    // B39 FamilySpecializer
    B39FamilyShape s39{};
    s39.family = B39ArchFamily::CDNA3; s39.waveWidth = 64;
    s39.ldsBytes = 65536; s39.regCount = 256; s39.hasWaveDot = true; s39.hasVNNI = true;
    auto p39 = B39FamilySpecializer::specialize(s39);
    if (!p39.specialized || !p39.useWaveDot || !p39.useVNNI || !p39.useRegisterTiling)
        return fail("B39");
    if (B39FamilySpecializer::familyName(B39ArchFamily::CDNA3) != "CDNA3")
        return fail("B39_NAME");

    // B40 PhysicalSeal
    std::vector<B40PhysicalSample> samples;
    for (int i = 0; i < 144; ++i) {
        B40PhysicalSample s{};
        double wig = double((i % 11) - 5) * 0.06;
        s.tps = 62.0 + wig;
        s.achievedVsRoofline = .905 + double(i % 5) * .002;
        s.bandwidthFraction = .91 + double(i % 5) * .002;
        s.computeFraction = .86 + double(i % 4) * .003;
        s.overlap = .955 + double(i % 3) * .002;
        s.skew = .022 + double(i % 4) * .0015;
        s.hostSync = .006 + double(i % 3) * .001;
        s.reloadBytes = 0; s.hostMaterializations = 0; s.hostTokenCopies = 0;
        s.parity = true; s.stable = true;
        samples.push_back(s);
    }
    auto st = B40PhysicalSeal::summarize(samples);
    B40PhysicalGate gate{};
    gate.minSamples = 128;
    gate.minP10Tps = 60.0;
    gate.minMedianTps = 61.0;
    gate.minP10RooflineFraction = .88;
    gate.minMedianRooflineFraction = .90;
    gate.minP10Bandwidth = .88;
    gate.minP10Compute = .82;
    gate.minMedianOverlap = .94;
    gate.maxP90Skew = .035;
    gate.maxP90HostSync = .012;
    auto dec = B40PhysicalSeal::certify(st, gate);
    if (!dec.pass) return fail(dec.firstFailure);

    std::printf("DEEP2_BATCH36_40_SELFTEST=PASS\n");
    std::printf("B36_WAVE=%u DOT_PER_LANE=%u ROWS_PER_PASS=%u OPS_PER_CYCLE=%.6f\n",
        p36.waveWidth, p36.dotOpsPerLane, p36.rowsPerWavePass,
        B36WaveDot::dotOpsPerCycle(s36));
    std::printf("B37_REGS=%u VEC=%u ACC=%u WT=%u SPILL=%u TILE=%u\n",
        p37.regsPerLane, p37.vectorRegs, p37.accumulatorRegs,
        p37.weightRegs, p37.spillToLds, p37.tileCols);
    std::printf("B38_WAVES=%u ROWS_PER_WAVE=%u LDS=%u BARRIER=%u\n",
        p38.wavesCooperating, p38.rowsPerWave, p38.sharedLdsBytes, p38.barrierCount);
    std::printf("B39_FAMILY=%s WG=%u ROWS=%u STAGES=%u WAVE_DOT=%d VNNI=%d\n",
        B39FamilySpecializer::familyName(s39.family).c_str(),
        p39.workgroup, p39.rowsPerGroup, p39.stages,
        (int)p39.useWaveDot, (int)p39.useVNNI);
    std::printf("B40_SAMPLES=%zu P10_TPS=%.3f MEDIAN_TPS=%.3f P10_ROOF=%.6f MEDIAN_ROOF=%.6f\n",
        st.samples, st.p10Tps, st.medianTps, st.p10RooflineFraction, st.medianRooflineFraction);
    std::printf("B40_P10_BW=%.6f P10_COMPUTE=%.6f OVERLAP=%.6f P90_SKEW=%.6f P90_SYNC=%.6f\n",
        st.p10Bandwidth, st.p10Compute, st.medianOverlap, st.p90Skew, st.p90HostSync);
    std::printf("B40_CERT=%s\n", dec.firstFailure);
    return 0;
}
