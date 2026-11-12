// ProductExtensionRuntime_Probe.cpp — C43 ExtensionHost runtime probe.
#include "ProductExtensionRuntime.hpp"
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <windows.h>

namespace ProductExtensionRuntime {
namespace {

std::string LogDir() {
    const char* d = std::getenv("RAWRXD_LOG_DIR");
    return (d && *d) ? std::string(d) : "F:\\rawrxd\\evidence";
}

std::string ExeDirectory() {
    char exe[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    return std::filesystem::path(exe).parent_path().string();
}

} // namespace

void ProbeExtHostRuntime() {
    const std::string log = LogDir() + "\\TOP25_C43_EXTHOST.log";
    const std::string fixture =
        "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\fixtures\\ext_hello";
    const std::string receipt = LogDir() + "\\C43_EXT_HOST_RECEIPT.txt";
    SetEnvironmentVariableA("RAWRXD_EXT_HOST_RECEIPT", receipt.c_str());
    SetRoots("F:\\rawrxd", ExeDirectory());
    KillHost();
    std::string load = LoadManifestPath(fixture);
    int loadOk = load.find("\"success\":true") != std::string::npos ? 1 : 0;
    std::string act = Activate("rawrxd.ext-hello");
    int actOk = act.find("\"success\":true") != std::string::npos ? 1 : 0;
    std::string status = HostStatusJson();
    int running = status.find("\"running\":true") != std::string::npos ? 1 : 0;
    int hostPid = 0;
    auto hp = status.find("\"host_pid\":");
    if (hp != std::string::npos) hostPid = std::atoi(status.c_str() + hp + 11);
    int receiptLoad = 0, receiptAct = 0;
    for (int i = 0; i < 40 && !(receiptLoad && receiptAct); ++i) {
        Sleep(50);
        FILE* rf = nullptr;
        if (fopen_s(&rf, receipt.c_str(), "r") == 0 && rf) {
            char buf[1024] = {};
            size_t n = fread(buf, 1, sizeof(buf) - 1, rf);
            buf[n] = 0;
            fclose(rf);
            receiptLoad = std::strstr(buf, "LOAD_OK=1") ? 1 : 0;
            receiptAct = std::strstr(buf, "ACTIVATE_OK=1") ? 1 : 0;
        }
    }
    FILE* f = nullptr;
    if (fopen_s(&f, log.c_str(), "w") == 0 && f) {
        fprintf(f,
                "load_ok=%d activate_ok=%d host_running=%d host_pid=%d "
                "receipt_load=%d receipt_activate=%d fixture=%s\n",
                loadOk, actOk, running, hostPid, receiptLoad, receiptAct,
                fixture.c_str());
        fclose(f);
    }
}

} // namespace ProductExtensionRuntime
