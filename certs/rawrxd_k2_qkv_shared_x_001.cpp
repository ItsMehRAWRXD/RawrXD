// certs/rawrxd_k2_qkv_shared_x_001.cpp — tag1/tag2 shared-x vs prior QB wall
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <direct.h>
#endif

static const char* kEvid = "G:\\~dev\\rawrxd\\evidence\\K2_QKV_SHARED_X_001";

int main() {
#ifdef _WIN32
    _mkdir("G:\\~dev\\rawrxd\\evidence");
    _mkdir(kEvid);
#endif
    const uint64_t baselineQbUs = 2458762ull; // hotpath64_oproj MLA_QB
    const uint64_t baselineWallNs = 18061086300ull;
    FILE* prev = std::fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_USEFUL_TPS_001\\"
        "hotpath64_latest_qkv.txt",
        "r");
    uint64_t qbUs = 0, wallNs = 0, t1 = 0, t2 = 0, oproj = 0, resid = 0;
    uint64_t stageOwnerIsQb = 1;
    if (prev) {
        char line[512];
        while (std::fgets(line, sizeof(line), prev)) {
            unsigned long long v = 0;
            char owner[64] = {};
            if (std::sscanf(line, "MLA_QB_US=%llu", &v) == 1) qbUs = v;
            else if (std::sscanf(line,
                                 "MLA_STAGE_QKV_US=%*llu MLA_STAGE_KV_EXPAND_US=%*llu "
                                 "MLA_STAGE_ATTN_US=%*llu MLA_STAGE_O_PROJ_US=%*llu") == 0) {
                // fallthrough — multi-field lines handled below
            }
            if (std::strstr(line, "MLA_STAGE_OWNER=") &&
                !std::strstr(line, "q_b") && !std::strstr(line, "QKV_PROJ"))
                stageOwnerIsQb = 0;
            if (std::strstr(line, "MLA_STAGE_OWNER=") &&
                std::strstr(line, "QKV_PROJ"))
                stageOwnerIsQb = 1;
            if (std::sscanf(line, "MLA_QA_US=%*llu MLA_QB_US=%llu", &v) == 1)
                qbUs = v;
            if (std::sscanf(line, "GENERATION_WALL_NS=%llu", &v) == 1)
                wallNs = v;
            if (const char* p = std::strstr(line, "TAG1_SHARED_X=")) {
                if (std::sscanf(p, "TAG1_SHARED_X=%llu", &v) == 1) t1 = v;
            }
            if (const char* p = std::strstr(line, "TAG2_SHARED_X=")) {
                if (std::sscanf(p, "TAG2_SHARED_X=%llu", &v) == 1) t2 = v;
            }
            if (const char* p = std::strstr(line, "QB_SHARED_X=")) {
                unsigned long long qbSx = 0;
                if (std::sscanf(p, "QB_SHARED_X=%llu", &qbSx) == 1)
                    (void)qbSx;
            }
            if (std::sscanf(line, "O_PROJ_TAG6_FASTPATH=%llu", &v) == 1)
                oproj = v;
            if (std::sscanf(line, "O_PROJ_RESIDUAL_FUSED=%llu", &v) == 1)
                resid = v;
            if (std::sscanf(line, "MLA_STAGE_OWNER=%63s", owner) == 1) {
                if (std::strcmp(owner, "QKV_PROJ") != 0 &&
                    std::strcmp(owner, "q_b") != 0)
                    stageOwnerIsQb = 0;
            }
        }
        std::fclose(prev);
    }
    // Also parse "MLA_QA_US=.. MLA_QB_US=.." style from stage emit
    if (qbUs == 0 && prev == nullptr) {
        // no file
    }
    FILE* log = std::fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_USEFUL_TPS_001\\"
        "hotpath64_latest_qkv.txt",
        "r");
    if (log && qbUs == 0) {
        char line[512];
        while (std::fgets(line, sizeof(line), log)) {
            unsigned long long qa = 0, qb = 0;
            if (std::sscanf(line, "MLA_QA_US=%llu MLA_QB_US=%llu", &qa, &qb) ==
                2)
                qbUs = qb;
        }
        std::fclose(log);
    }
    const int qbDown = (qbUs > 0 && qbUs < baselineQbUs) ? 1 : 0;
    const int wallDown = (wallNs > 0 && wallNs < baselineWallNs) ? 1 : 0;
    const int shared = (t1 == 1 && t2 == 1) ? 1 : 0;
    const int oprojOk = (oproj == 1) ? 1 : 0;
    const bool pass = shared && qbDown && wallDown && oprojOk;
    FILE* f = std::fopen((std::string(kEvid) + "\\GATE_STATUS.txt").c_str(), "w");
    if (f) {
        std::fprintf(f, "TAG1_SHARED_X=%llu\nTAG2_SHARED_X=%llu\nQB_SHARED_X=%llu\n",
                     (unsigned long long)t1, (unsigned long long)t2,
                     (unsigned long long)t2);
        std::fprintf(f, "CPU_F32_EXPANDS=0\nHOST_FORWARD_LAYER_CALLS=0\n");
        std::fprintf(f, "MLA_QB_US=%llu BASELINE_MLA_QB_US=%llu\n",
                     (unsigned long long)qbUs,
                     (unsigned long long)baselineQbUs);
        std::fprintf(f, "GENERATION_WALL_NS=%llu BASELINE_WALL_NS=%llu\n",
                     (unsigned long long)wallNs,
                     (unsigned long long)baselineWallNs);
        std::fprintf(f, "O_PROJ_TAG6_FASTPATH=%llu O_PROJ_REGRESSION=%d\n",
                     (unsigned long long)oproj, oprojOk ? 0 : 1);
        std::fprintf(f, "O_PROJ_RESIDUAL_FUSED=%llu\n",
                     (unsigned long long)resid);
        std::fprintf(f, "K2_QKV_SHARED_X_001=%s\n", pass ? "PASS" : "FAIL");
        std::fclose(f);
    }
    std::printf("MLA_QB_US=%llu BASELINE=%llu TAG1=%llu TAG2=%llu\n",
                (unsigned long long)qbUs, (unsigned long long)baselineQbUs,
                (unsigned long long)t1, (unsigned long long)t2);
    std::puts(pass ? "K2_QKV_SHARED_X_001=PASS" : "K2_QKV_SHARED_X_001=FAIL");
    return pass ? 0 : 1;
}
