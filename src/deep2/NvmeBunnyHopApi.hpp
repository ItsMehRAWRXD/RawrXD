// NvmeBunnyHopApi.hpp — HTTP policy for NVMe reverse-chunk hotpatch bunnyhop
#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif

namespace Deep2 {
namespace NvmeBunnyHopApi {

inline bool EnvOn(const char* k) {
    const char* v = std::getenv(k);
    return v && v[0] && v[0] != '0';
}

inline void SetEnv(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
#else
    setenv(k, v, 1);
#endif
}

inline bool ForceEnabled() { return EnvOn("RAWRXD_NVME_REVERSE_BUNNYHOP"); }

inline std::string StatusJson() {
    const bool force = ForceEnabled();
    const char* chunk = std::getenv("RAWRXD_NVME_BUNNYHOP_CHUNK_MIB");
    const int mib = (chunk && *chunk) ? std::atoi(chunk) : 4;
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "{\"feature\":\"nvme_reverse_bunnyhop\","
        "\"mode\":\"UNLAIDOUT_REVERSE_CHUNK_HOTPATCH_BUNNYHOP\","
        "\"force\":%s,\"unlaidout\":true,\"hotpatch_relive\":true,"
        "\"chunk_mib\":%d,\"fallback_policy\":\"FORCE_ON_MMAP_FAIL\","
        "\"endpoints\":[\"/api/nvme/bunnyhop/status\","
        "\"/api/nvme/bunnyhop/arm\",\"/api/nvme/bunnyhop/disarm\"],"
        "\"files\":[\"NVMeStream.cpp\",\"NVMeReverseBunnyHop.hpp\","
        "\"NVMeReverseBunnyHop.cpp\",\"Deep2Engine.cpp\"]}",
        force ? "true" : "false", mib > 0 ? mib : 4);
    return std::string(buf);
}

// Apply from generate JSON fragment containing "nvme_bunnyhop":{...}
inline bool ApplyFromGenerateBody(const std::string& body) {
    size_t p = body.find("\"nvme_bunnyhop\"");
    if (p == std::string::npos) p = body.find("\"nvmeBunnyHop\"");
    if (p == std::string::npos) return ForceEnabled();
    const size_t end = body.find('}', p);
    const std::string frag = (end == std::string::npos) ? body.substr(p)
        : body.substr(p, end - p + 1);
    const bool en = frag.find("\"enabled\":true") != std::string::npos ||
                    frag.find("\"enabled\": true") != std::string::npos ||
                    frag.find("\"force\":true") != std::string::npos ||
                    frag.find("\"force\": true") != std::string::npos;
    if (en) {
        SetEnv("RAWRXD_NVME_REVERSE_BUNNYHOP", "1");
        SetEnv("RAWRXD_UNREVERSE_HOTPATCH", "1");
        return true;
    }
    SetEnv("RAWRXD_NVME_REVERSE_BUNNYHOP", "0");
    return false;
}

inline std::string ArmJson(bool arm, int chunkMib = 4) {
    if (arm) {
        SetEnv("RAWRXD_NVME_REVERSE_BUNNYHOP", "1");
        SetEnv("RAWRXD_UNREVERSE_HOTPATCH", "1");
        char m[16]; std::snprintf(m, sizeof(m), "%d", chunkMib > 0 ? chunkMib : 4);
        SetEnv("RAWRXD_NVME_BUNNYHOP_CHUNK_MIB", m);
    } else {
        SetEnv("RAWRXD_NVME_REVERSE_BUNNYHOP", "0");
    }
    return StatusJson();
}

} // namespace NvmeBunnyHopApi
} // namespace Deep2
