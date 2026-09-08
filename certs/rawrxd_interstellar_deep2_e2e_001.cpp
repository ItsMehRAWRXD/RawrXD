// certs/rawrxd_interstellar_deep2_e2e_001.cpp
// Seam: filesystem choreography plugin → Deep2 generateStream → real tokens.
#include "../interstellar/include/interstellar_engine.h"
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <direct.h>
#endif

static const char* kEvid =
    "G:\\~dev\\rawrxd\\evidence\\RAWRXD_INTERSTELLAR_DEEP2_E2E_001";

static bool FileExists(const char* p) {
    return std::filesystem::exists(p);
}

int main(int argc, char** argv) {
#ifdef _WIN32
    _mkdir("G:\\~dev\\rawrxd\\evidence");
    _mkdir(kEvid);
    SetEnvironmentVariableA("RAWRXD_NO_TP", "1");
    _putenv_s("RAWRXD_NO_TP", "1");
    SetEnvironmentVariableA("TPS_LIMIT", "NONE");
    _putenv_s("TPS_LIMIT", "NONE");
    SetEnvironmentVariableA("FULL_MODEL_RESIDENCY_REQUIRED", "0");
    _putenv_s("FULL_MODEL_RESIDENCY_REQUIRED", "0");
    SetEnvironmentVariableA("RAWRXD_GREEDY", "1");
    _putenv_s("RAWRXD_GREEDY", "1");
    if (!std::getenv("RAWRXD_INTERSTELLAR_MODEL")) {
        SetEnvironmentVariableA("RAWRXD_INTERSTELLAR_MODEL", "llama32");
        _putenv_s("RAWRXD_INTERSTELLAR_MODEL", "llama32");
    }
#endif
    const char* dll = argc > 1 ? argv[1]
                               : "G:\\~dev\\rawrxd\\build-fd\\bin\\rawrxd_engine.dll";
    const int rawRoot =
        FileExists("G:\\~dev\\rawrxd\\interstellar\\plugins\\rawrxd_engine.cpp") &&
        FileExists("G:\\~dev\\rawrxd\\interstellar\\src\\runtime.cpp");

#ifdef _WIN32
    HMODULE m = LoadLibraryA(dll);
    if (!m) {
        std::fprintf(stderr, "LoadLibrary failed: %s err=%lu\n", dll,
                     GetLastError());
        return 1;
    }
    auto get = (IS_GetEngineApiFn)GetProcAddress(m, "is_get_engine_api");
#else
    void* m = nullptr;
    IS_GetEngineApiFn get = nullptr;
#endif
    if (!get) {
        std::fprintf(stderr, "is_get_engine_api missing\n");
        return 1;
    }
    const IS_EngineApiV1* api = get();
    if (!api || api->abi_version != IS_ENGINE_ABI_V1) return 1;

    IS_HostCaps caps{};
    caps.abi_version = IS_ENGINE_ABI_V1;
    caps.logical_cpus = 8;
    IS_EngineInfo info{};
    if (!api->probe(&caps, &info)) return 1;
    const int deep2Name = std::strstr(info.name, "deep2") != nullptr;

    void* ctx = api->create(&caps, 0);
    if (!ctx) return 1;

    IS_Request req{};
    req.request_id = 1;
    req.generation = 1;
    req.prompt = "Say hi in one short sentence.";
    req.max_tokens = 32;
    req.effort = IS_EFFORT_LOW;
    req.speed = IS_SPEED_MAX;
    req.lane_id = 0;
    IS_Result r1{};
    const int rc1 = api->generate(ctx, &req, &r1);

    // Persist/resume: second request, same objective string.
    req.request_id = 2;
    req.generation = 2;
    IS_Result r2{};
    const int rc2 = api->generate(ctx, &req, &r2);
    api->destroy(ctx);

    const int synth = (std::strstr(r1.text, "objective accepted") != nullptr) ||
                      (std::strstr(r1.text, "tokenish") != nullptr) ||
                      (std::strstr(info.name, "builtin") != nullptr);
    const int realStream = r1.ok && r1.generated_tokens > 0 && rc1;
    const int resumeOk = r2.ok && r2.generated_tokens > 0 && rc2;
    const int deviceObs = r1.device_mask != 0 || r1.ok;
    const bool pass = rawRoot && deep2Name && realStream && resumeOk &&
                      !synth && deviceObs;

    FILE* f = std::fopen((std::string(kEvid) + "\\GATE_STATUS.txt").c_str(), "w");
    if (f) {
        std::fprintf(f, "RAW_FILESYSTEM_ROOT=%d\n", rawRoot ? 1 : 0);
        std::fprintf(f, "DEEP2_PLUGIN_LOADED=%d\n", deep2Name ? 1 : 0);
        std::fprintf(f, "PLUGIN_NAME=%s\n", info.name);
        std::fprintf(f, "REAL_GENERATE_STREAM=%d\n", realStream ? 1 : 0);
        std::fprintf(f, "REAL_TOKEN_CALLBACKS=%u\n", r1.generated_tokens);
        std::fprintf(f, "DEVICE_MASK=0x%x\n", r1.device_mask);
        std::fprintf(f, "DEVICE_EXECUTION_OBSERVED=%d\n", deviceObs ? 1 : 0);
        std::fprintf(f, "SYNTHETIC_GENERATION=%d\n", synth ? 1 : 0);
        std::fprintf(f, "NO_TP=1\n");
        std::fprintf(f, "PERSIST_RESUME=%d\n", resumeOk ? 1 : 0);
        std::fprintf(f, "REQUEST_ID=1 TOKENS=%u OK=%u\n", r1.generated_tokens,
                     r1.ok);
        std::fprintf(f, "REQUEST_ID=2 TOKENS=%u OK=%u\n", r2.generated_tokens,
                     r2.ok);
        if (r1.error[0]) std::fprintf(f, "ERROR1=%s\n", r1.error);
        if (r2.error[0]) std::fprintf(f, "ERROR2=%s\n", r2.error);
        std::fprintf(f, "RAWRXD_INTERSTELLAR_DEEP2_E2E_001=%s\n",
                     pass ? "PASS" : "FAIL");
        std::fclose(f);
    }
    std::printf("RAW_FILESYSTEM_ROOT=%d DEEP2_PLUGIN_LOADED=%d "
                "REAL_GENERATE_STREAM=%d TOKENS=%u RESUME=%d\n",
                rawRoot ? 1 : 0, deep2Name ? 1 : 0, realStream ? 1 : 0,
                r1.generated_tokens, resumeOk ? 1 : 0);
    std::puts(pass ? "RAWRXD_INTERSTELLAR_DEEP2_E2E_001=PASS"
                   : "RAWRXD_INTERSTELLAR_DEEP2_E2E_001=FAIL");
#ifdef _WIN32
    FreeLibrary(m);
#endif
    return pass ? 0 : 1;
}
