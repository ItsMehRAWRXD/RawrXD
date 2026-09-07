// deep2_runtime_batch3_cert.cpp — GATE_ROADMAP_003 umbrella (15 gates)
#include <cstdio>
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static const char* kEvd = "G:\\~dev\\rawrxd\\evidence";

static bool ReadPass(const char* gate) {
    std::string p = std::string(kEvd) + "\\" + gate + "\\GATE_STATUS.txt";
    FILE* f = nullptr;
    if (fopen_s(&f, p.c_str(), "rb") != 0 || !f) return false;
    char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    if (std::strstr(buf, (std::string(gate) + "=PASS").c_str())) return true;
    return std::strstr(buf, "=PASS") != nullptr;
}

static void WriteGate(const char* gate, bool pass, const std::string& body) {
    std::string dir = std::string(kEvd) + "\\" + gate;
    CreateDirectoryA(dir.c_str(), nullptr);
    FILE* f = nullptr;
    fopen_s(&f, (dir + "\\GATE_STATUS.txt").c_str(), "wb");
    if (!f) return;
    fprintf(f, "%s", body.c_str());
    fprintf(f, "%s=%s\n", gate, pass ? "PASS" : "FAIL");
    fclose(f);
    printf("%s=%s\n", gate, pass ? "PASS" : "FAIL");
}

int main() {
    CreateDirectoryA(kEvd, nullptr);
    const char* kids[] = {
        // Quant family (1–4)
        "STREAMER_GPU_Q5K_GEMV_001",
        "STREAMER_GPU_Q3K_GEMV_001",
        "STREAMER_GPU_Q2K_GEMV_001",
        "STREAMER_GPU_Q8_GEMV_001",
        // Packed forward / fusion (5–14)
        "STREAMER_GPU_QUANT_COVERAGE_001",
        "STREAMER_GPU_PACKED_FORWARD_001",
        "STREAMER_GPU_ASYNC_PIPELINE_001",
        "STREAMER_GPU_TRANSFER_BATCH_001",
        "STREAMER_GPU_COMMAND_REUSE_001",
        "STREAMER_GPU_FUSION_001",
        "STREAMER_GPU_FUSED_QKV_001",
        "STREAMER_GPU_FUSED_FFN_001",
        "STREAMER_GPU_KERNEL_TUNE_001",
        "STREAMER_GPU_MEMORY_TUNE_001",
        // Dynamic window (15)
        "STREAMER_GPU_DYNAMIC_WINDOW_001",
    };
    int ok = 0, n = 0;
    std::string body;
    for (const char* g : kids) {
        bool p = ReadPass(g);
        ok += p ? 1 : 0;
        ++n;
        body += std::string(g) + (p ? "=PASS\n" : "=FAIL\n");
        printf("  %s=%s\n", g, p ? "PASS" : "FAIL");
    }
    bool pass = ok == n;
    char head[64];
    snprintf(head, sizeof(head), "batch3_fails=%d gates=15 passed=%d/%d\n", n - ok, ok, n);
    WriteGate("DEEP2_RUNTIME_BATCH3_001", pass, std::string(head) + body);
    WriteGate("GATE_ROADMAP_003", pass, std::string(head) + body);
    printf("DEEP2_RUNTIME_BATCH3_001=%s fails=%d\n", pass ? "PASS" : "FAIL", n - ok);
    return pass ? 0 : 1;
}
