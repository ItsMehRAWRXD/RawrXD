// Logic test for RAWRXD_DUAL_GPU_ADMISSION_TELEMETRY_001.
// Proves fail-closed admission and the measurement equations WITHOUT a GPU.
// This is unit-test evidence for the LOGIC, not hardware certification.
#include "DualGpuAdmissionTelemetry.hpp"
#include <cstdio>
#include <vector>

using namespace rawrxd::dualgpu;

static int g_fails = 0;
static void check(bool ok, const char* name) {
    std::printf("%s %s\n", ok ? "OK" : "FAIL", name);
    if (!ok) ++g_fails;
}

int main() {
    // DGL-03/04: 0 GPUs -> reject.
    { std::vector<DualGpuDevice> d; auto r = AdmitLockedProfile(d);
      check(!r.admitted, "0gpu_rejected"); }

    // DGL-04: exactly 1 GPU -> reject (single-GPU fallback rejected).
    { std::vector<DualGpuDevice> d{{"V:1:L","R9700",0x1002,0,640,32ull<<30,true,true}};
      auto r = AdmitLockedProfile(d);
      check(!r.admitted, "1gpu_fallback_rejected"); }

    // Device-count mismatch fix: 3 GPUs -> reject for a 2-lane lock.
    { std::vector<DualGpuDevice> d{{"V:1:L","R9700",0x1002,0,640,32ull<<30,true,true},
                                   {"V:2:L","RX7800XT",0x1002,0,624,16ull<<30,true,true},
                                   {"V:3:L","Other",0x1002,0,500,8ull<<30,true,true}};
      auto r = AdmitLockedProfile(d);
      check(!r.admitted, "3gpu_rejected"); }

    // DGL-01/02: two distinct identity-exact healthy GPUs with measured caps -> admit.
    { std::vector<DualGpuDevice> d{{"V:1:L","R9700",0x1002,0,640,32ull<<30,true,true},
                                   {"V:2:L","RX7800XT",0x1002,0,624,16ull<<30,true,true}};
      auto r = AdmitLockedProfile(d);
      check(r.admitted, "2gpu_admitted"); }

    // DGL-02: duplicate stable id -> reject.
    { std::vector<DualGpuDevice> d{{"V:1:L","A",0x1002,0,640,32ull<<30,true,true},
                                   {"V:1:L","B",0x1002,0,624,16ull<<30,true,true}};
      auto r = AdmitLockedProfile(d);
      check(!r.admitted, "duplicate_id_rejected"); }

    // DGL-05: missing measured budget -> reject.
    { std::vector<DualGpuDevice> d{{"V:1:L","A",0x1002,0,640,0,true,true},
                                   {"V:2:L","B",0x1002,0,624,16ull<<30,true,true}};
      auto r = AdmitLockedProfile(d);
      check(!r.admitted, "missing_budget_rejected"); }

    // Identity validation: enforce expected hardware, wrong GPU -> reject.
    { std::vector<DualGpuDevice> d{{"V:1:L","R9700",0x1002,0,640,32ull<<30,true,true},
                                   {"V:2:L","RX7800XT",0x1002,0,624,16ull<<30,true,true}};
      ExpectedHardware e; e.enforce = true;
      auto ok = AdmitLockedProfile(d, e); check(ok.admitted, "expected_hardware_match");
      d[1].name = "RX 6800"; // wrong secondary
      auto bad = AdmitLockedProfile(d, e); check(!bad.admitted, "unexpected_hardware_rejected"); }

    // DGL-10: aggregate PHYSICAL bandwidth = (B0+B1)/T_shared, counter-backed.
    { Telemetry t; t.BeginWindow();
      t.AddVramRead(0, 500000000000ull, /*counterBacked=*/true);
      t.AddVramRead(1, 500000000000ull, /*counterBacked=*/true);
      t.AddActive(0, 999000000ull); t.AddActive(1, 999000000ull);
      t.EndWindow(/*wallNs=*/1000000000ull);
      double bw = 0.0; bool measured = AggregatePhysicalBandwidthGbps(t, bw);
      std::printf("AGGREGATE_PHYSICAL_BANDWIDTH_GBPS=%.1f\n", bw);
      check(measured && bw > 999.0 && bw < 1001.0, "aggregate_bandwidth_1000"); }

    // Provenance: non-counter bytes are logical, physical stays UNMEASURED.
    { Telemetry t; t.BeginWindow();
      t.AddVramRead(0, 500000000000ull, /*counterBacked=*/false);
      t.AddVramRead(1, 500000000000ull, /*counterBacked=*/false);
      t.EndWindow(1000000000ull);
      double bw = -1.0; bool measured = AggregatePhysicalBandwidthGbps(t, bw);
      check(!measured, "physical_unmeasured_without_counters");
      double lbw = 0.0; bool lmeas = AggregateLogicalBandwidthGbps(t, lbw);
      std::printf("AGGREGATE_LOGICAL_BANDWIDTH_GBPS=%.1f\n", lbw);
      check(lmeas && lbw > 999.0 && lbw < 1001.0, "logical_bandwidth_1000"); }

    // DGL-09: overlap derived from actual intervals, clamped to shared window.
    { Telemetry t; t.BeginWindow();
      t.AddActiveInterval(0, 0ull, 1000000000ull);
      t.AddActiveInterval(1, 500000000ull, 1500000000ull);
      t.EndWindow(1000000000ull);
      double ov = 0.0; bool m = OverlapFraction(t, ov);
      std::printf("OVERLAP_FRACTION=%.2f\n", ov);
      check(m && ov > 0.49 && ov < 0.51, "overlap_0.5_from_intervals");
      check(BothDevicesContributed(t) == false, "no_active_time_no_contribution"); }

    // DGL-11: byte-weighted residency 950/1000 = 0.95, clamped to <= 1.
    { double r = ActiveWeightResidency(950, 1000);
      std::printf("ACTIVE_WEIGHT_RESIDENCY=%.2f\n", r);
      check(r > 0.949 && r < 0.951, "residency_0.95");
      check(ActiveWeightResidency(1200, 1000) == 1.0, "residency_clamped_to_1"); }

    // Lifecycle: physical bandwidth UNVERIFIED (false) when no window is set.
    { Telemetry t; double bw = -1.0; bool m = AggregatePhysicalBandwidthGbps(t, bw);
      check(!m, "physical_unverified_without_window"); }

    std::printf("FAILS=%d\n", g_fails);
    return g_fails ? 1 : 0;
}