// C43 CLI product ExtensionHost — ProductExtensionRuntime /api/extensions.
// Real load/activate/API — PROMOTE=0 CERTIFIED=0 TIP_CLIMB=HOLD.
#include "cli/rawr_cli_extensions.hpp"
#include "ProductExtensionRuntime.hpp"
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <windows.h>

namespace fs = std::filesystem;
static void emit(const std::string& s) { std::cout << s << "\n"; }

static std::string ExeDirectory() {
    char exe[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    return fs::path(exe).parent_path().string();
}

int rawrCliExtensionsCommand(const std::vector<std::string>& args, bool json) {
    if (args.empty() || args[0] != "probe") {
        emit("usage: rawr extensions probe [--fixture PATH]");
        return 1;
    }
    std::string fixture =
        "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\fixtures\\ext_hello";
    for (size_t i = 1; i + 1 < args.size(); ++i)
        if (args[i] == "--fixture") fixture = args[i + 1];
    const char* logEnv = std::getenv("RAWRXD_LOG_DIR");
    const std::string logDir =
        (logEnv && *logEnv) ? std::string(logEnv) : "F:\\rawrxd\\evidence";
    const std::string receipt = logDir + "\\CLI_C43_EXT_HOST_RECEIPT.txt";
    SetEnvironmentVariableA("RAWRXD_EXT_HOST_RECEIPT", receipt.c_str());

    ProductExtensionRuntime::SetRoots("F:\\rawrxd", ExeDirectory());
    ProductExtensionRuntime::KillHost();
    const std::string load =
        ProductExtensionRuntime::LoadManifestPath(fixture);
    const int loadOk = load.find("\"success\":true") != std::string::npos;
    const std::string act =
        ProductExtensionRuntime::Activate("rawrxd.ext-hello");
    const int actOk = act.find("\"success\":true") != std::string::npos;
    const std::string listApi = ProductExtensionRuntime::HandleRoute(
        "GET", "/api/extensions", "");
    const int apiOk =
        listApi.find("product_extension_runtime") != std::string::npos;
    const std::string status = ProductExtensionRuntime::HandleRoute(
        "GET", "/api/extensions/host/status", "");
    const int running = status.find("\"running\":true") != std::string::npos;
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
    ProductExtensionRuntime::KillHost();
    const int pass =
        (loadOk && actOk && apiOk && running && receiptLoad && receiptAct) ? 1 : 0;
    if (json) {
        emit("{\"load_ok\":" + std::to_string(loadOk) +
             ",\"activate_ok\":" + std::to_string(actOk) +
             ",\"api_ok\":" + std::to_string(apiOk) +
             ",\"host_running\":" + std::to_string(running) +
             ",\"host_pid\":" + std::to_string(hostPid) +
             ",\"receipt_load\":" + std::to_string(receiptLoad) +
             ",\"receipt_activate\":" + std::to_string(receiptAct) +
             ",\"PRODUCT_API\":" + std::to_string(pass) + "}");
    } else {
        emit("load_ok=" + std::to_string(loadOk) +
             " activate_ok=" + std::to_string(actOk) +
             " api_ok=" + std::to_string(apiOk) +
             " host_running=" + std::to_string(running) +
             " host_pid=" + std::to_string(hostPid) +
             " receipt_load=" + std::to_string(receiptLoad) +
             " receipt_activate=" + std::to_string(receiptAct) +
             " PRODUCT_API=" + std::to_string(pass) +
             " adapter=product_extension_runtime");
    }
    return pass ? 0 : 1;
}
