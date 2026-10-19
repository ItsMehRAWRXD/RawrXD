#include "d2_perf_authority.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t u64(const char* s) { return (uint64_t)strtoull(s, 0, 10); }
static double f64(const char* s) { return strtod(s, 0); }
static int i32(const char* s) { return (int)strtol(s, 0, 10); }

static const char* arg(int argc, char** argv, const char* name) {
    int i;
    for (i = 1; i + 1 < argc; ++i) if (strcmp(argv[i], name) == 0) return argv[i + 1];
    return 0;
}

static void projection(uint64_t bytes, double peak, double tps) {
    D2PerfProjection p = d2_perf_project(bytes, tps, peak);
    printf("TARGET_TPS=%.3f REQUIRED_WEIGHT_BW_GBS=%.3f PEAK_BW_UTILIZATION=%.4f IDEAL_WEIGHT_ONLY_MS=%.3f\n",
        p.target_tps, p.required_weight_bw_gbs, p.peak_bw_utilization, p.ideal_weight_only_ms_per_token);
}

int main(int argc, char** argv) {
    const char* mode = arg(argc, argv, "--mode");
    if (!mode || strcmp(mode, "project") == 0) {
        const char* wb = arg(argc, argv, "--weight-bytes");
        const char* pb = arg(argc, argv, "--peak-bw-gbs");
        uint64_t bytes = wb ? u64(wb) : 25000000000ULL;
        double peak = pb ? f64(pb) : 640.0;
        printf("MODE=PROJECTION FULL_MODEL_TPS_AUTHORITY=0\n");
        printf("TOUCHED_WEIGHT_BYTES_PER_TOKEN=%llu DEVICE_PEAK_BW_GBS=%.3f\n",
            (unsigned long long)bytes, peak);
        projection(bytes, peak, 12.0);
        projection(bytes, peak, 15.0);
        projection(bytes, peak, 20.0);
        projection(bytes, peak, 25.0);
        return 0;
    }

    if (strcmp(mode, "observe") == 0) {
        D2PerfObservation o = {0};
        D2PerfObservedResult r;
        const char* v;
#define GETU(field, flag) do { v = arg(argc, argv, flag); if (v) o.field = u64(v); } while (0)
#define GETI(field, flag) do { v = arg(argc, argv, flag); if (v) o.field = i32(v); } while (0)
        GETU(generated_tokens, "--tokens");
        GETU(wall_ns, "--wall-ns");
        GETU(touched_weight_bytes_total, "--weight-bytes-total");
        GETU(gpu0_weight_bytes_total, "--gpu0-weight-bytes");
        GETU(gpu1_weight_bytes_total, "--gpu1-weight-bytes");
        GETU(host_to_device_bytes_total, "--h2d-bytes");
        GETU(cross_gpu_bytes_total, "--xgpu-bytes");
        GETU(allocation_count_after_warmup, "--steady-allocs");
        GETU(sealed_logits_reuse_count, "--sealed-reuse");
        GETU(synthetic_logits_count, "--synthetic-logits");
        GETU(synthetic_weight_count, "--synthetic-weights");
        GETI(full_model_decode, "--full-model");
        GETI(all_blocks_every_token, "--all-blocks");
        GETI(device_lost, "--device-lost");
#undef GETU
#undef GETI
        r = d2_perf_observe(&o);
        printf("MODE=OBSERVATION\n");
        printf("GENERATED_TOKENS=%llu WALL_NS=%llu\n",
            (unsigned long long)o.generated_tokens, (unsigned long long)o.wall_ns);
        printf("MEASURED_TPS=%.6f MS_PER_TOKEN=%.6f EFFECTIVE_WEIGHT_BW_GBS=%.3f\n",
            r.measured_tps, r.ms_per_token, r.effective_weight_bw_gbs);
        printf("AUTHORITY_ELIGIBLE=%d\n", r.authority_eligible);
        printf("FULL_MODEL_TPS_AUTHORITY=0\n");
        printf("NOTE=This_tool_evaluates_measurements_but_does_not_mint_certification_authority\n");
        return r.authority_eligible ? 0 : 2;
    }

    fprintf(stderr, "unknown --mode; use project or observe\n");
    return 64;
}
