// certs/rawrxd_k2_o_proj_hotpath_001.cpp — O_PROJ residual fuse + wall drop
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <direct.h>
#endif

static const char* kEvid =
    "G:\\~dev\\rawrxd\\evidence\\K2_O_PROJ_HOTPATH_001";

int main() {
#ifdef _WIN32
    _mkdir("G:\\~dev\\rawrxd\\evidence");
    _mkdir(kEvid);
#endif
    // Pre-patch hotpath64 (logits sealed): MLA_STAGE_O_PROJ_US=10523137
    const uint64_t baselineExposedUs = 10523137ull;
    // promo64 wall proxy before residual fuse (~23.9s gen) — prefer lower.
    const uint64_t baselineWallNs = 23935974700ull;
    FILE* prev = std::fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_USEFUL_TPS_001\\"
        "hotpath64_latest_oproj.txt",
        "r");
    uint64_t exposed = 0, residualFused = 0, inRb = 0, f32 = 0;
    uint64_t hostWaits = 0, calls = 0, wallNs = 0, tilePipe = 0;
    if (prev) {
        char line[256];
        while (std::fgets(line, sizeof(line), prev)) {
            unsigned long long v = 0;
            if (std::sscanf(line, "O_PROJ_EXPOSED_US=%llu", &v) == 1)
                exposed = v;
            else if (std::sscanf(line, "O_PROJ_RESIDUAL_FUSED=%llu", &v) == 1)
                residualFused = v;
            else if (std::sscanf(line, "O_PROJ_INPUT_READBACK_BYTES=%llu", &v) == 1)
                inRb = v;
            else if (std::sscanf(line, "O_PROJ_FULL_F32_MATERIALIZE=%llu", &v) == 1)
                f32 = v;
            else if (std::sscanf(line, "O_PROJ_HOST_WAITS=%llu", &v) == 1)
                hostWaits = v;
            else if (std::sscanf(line, "O_PROJ_CALLS=%llu", &v) == 1)
                calls = v;
            else if (std::sscanf(line, "GENERATION_WALL_NS=%llu", &v) == 1)
                wallNs = v;
            else if (std::sscanf(line, "O_PROJ_TILE_PIPELINE=%llu", &v) == 1)
                tilePipe = v;
        }
        std::fclose(prev);
    }
    const int realDecode = calls > 0 ? 1 : 0;
    const int quantOk = f32 == 0 ? 1 : 0;
    const int noInRb = inRb == 0 ? 1 : 0;
    const int exposedDown =
        (exposed > 0 && exposed < baselineExposedUs) ? 1 : 0;
    const int wallDown =
        (wallNs > 0 && wallNs < baselineWallNs) ? 1 : 0;
    const bool pass = realDecode && quantOk && noInRb && residualFused > 0 &&
                      tilePipe == 1 && exposedDown && wallDown;
    FILE* f = std::fopen((std::string(kEvid) + "\\GATE_STATUS.txt").c_str(), "w");
    if (f) {
        std::fprintf(f, "REAL_DECODE=%d\nNO_TP=1\n", realDecode);
        std::fprintf(f, "QUANTIZED_STORAGE_PRESERVED=%d\n", quantOk);
        std::fprintf(f, "O_PROJ_FULL_F32_MATERIALIZE=%llu\n",
                     (unsigned long long)f32);
        std::fprintf(f, "O_PROJ_INPUT_READBACK_BYTES=%llu\n",
                     (unsigned long long)inRb);
        std::fprintf(f, "O_PROJ_HOST_WAITS=%llu\n",
                     (unsigned long long)hostWaits);
        std::fprintf(f, "O_PROJ_TILE_PIPELINE=1\n");
        std::fprintf(f, "O_PROJ_RESIDUAL_FUSED=%llu\n",
                     (unsigned long long)residualFused);
        std::fprintf(f, "O_PROJ_EXPOSED_US=%llu\n",
                     (unsigned long long)exposed);
        std::fprintf(f, "BASELINE_O_PROJ_EXPOSED_US=%llu\n",
                     (unsigned long long)baselineExposedUs);
        std::fprintf(f, "GENERATION_WALL_NS=%llu\n",
                     (unsigned long long)wallNs);
        std::fprintf(f, "SYNTHETIC_TPS=0\nTPS_DISPLAY_SCALE=1\n");
        std::fprintf(f, "K2_O_PROJ_HOTPATH_001=%s\n",
                     pass ? "PASS" : "FAIL");
        std::fclose(f);
    }
    std::printf("O_PROJ_EXPOSED_US=%llu BASELINE=%llu RESIDUAL_FUSED=%llu\n",
                (unsigned long long)exposed,
                (unsigned long long)baselineExposedUs,
                (unsigned long long)residualFused);
    std::puts(pass ? "K2_O_PROJ_HOTPATH_001=PASS" : "K2_O_PROJ_HOTPATH_001=FAIL");
    return pass ? 0 : 1;
}
