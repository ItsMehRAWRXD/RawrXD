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
    { std::vector<DualGpuDevice> d{{"V:1:L","R9700",640,32ull<<30,true,true}};
      auto r = AdmitLockedProfile(d);
      check(!r.admitted, "1gpu_fallback_rejected"); }

    // DGL-01/02: two distinct identity-exact healthy GPUs with measured caps -> admit.
    { std::vector<DualGpuDevice> d{{"V:1:L","R9700",640,32ull<<30,true,true},
                                   {"V:2:L","RX7800XT",624,16ull<<30,true,true}};
      auto r = AdmitLockedProfile(d);
      check(r.admitted, "2gpu_admitted"); }

    // DGL-02: duplicate stable id -> reject.
    { std::vector<DualGpuDevice> d{{"V:1:L","A",640,32ull<<30,true,true},
                                   {"V:1:L","B",624,16ull<<30,true,true}};
      auto r = AdmitLockedProfile(d);
      check(!r.admitted, "duplicate_id_rejected"); }

    // DGL-05: missing measured budget -> reject.
    { std::vector<DualGpuDevice> d{{"V:1:L","A",640,0,true,true},
                                   {"V:2:L","B",624,16ull<<30,true,true}};
      auto r = AdmitLockedProfile(d);
      check(!r.admitted, "missing_budget_rejected"); }

    // DGL-10: aggregate physical bandwidth = (B0+B1)/T_shared.
    // 500 GB/s per device over a 1 s shared window = 1000 GB/s aggregate.
    { Telemetry t; t.BeginWindow();
      t.AddVramRead(0, 500000000000ull); t.AddVramRead(1, 500000000000ull);
      t.AddActive(0, 999000000ull); t.AddActive(1, 999000000ull);
      t.EndWindow(/*wallNs=*/1000000000ull, /*overlapNs=*/500000000ull);
      const double bw = AggregatePhysicalBandwidthGbps(t);
      std::printf("AGGREGATE_PHYSICAL_BANDWIDTH_GBPS=%.1f\n", bw);
      check(bw > 999.0 && bw < 1001.0, "aggregate_bandwidth_1000");
      const double ov = OverlapFraction(t);
      std::printf("OVERLAP_FRACTION=%.2f\n", ov);
      check(ov > 0.49 && ov < 0.51, "overlap_0.5");
      check(BothDevicesContributed(t), "both_devices_contributed"); }

    // DGL-11: byte-weighted residency 950/1000 = 0.95.
    { const double r = ActiveWeightResidency(950, 1000);
      std::printf("ACTIVE_WEIGHT_RESIDENCY=%.2f\n", r);
      check(r > 0.949 && r < 0.951, "residency_0.95"); }

    // Physical bandwidth stays 0 (UNVERIFIED) when no shared window is set.
    { Telemetry t; const double bw = AggregatePhysicalBandwidthGbps(t);
      check(bw == 0.0, "physical_unverified_without_window"); }

    std::printf("FAILS=%d\n", g_fails);
    return g_fails ? 1 : 0;
}