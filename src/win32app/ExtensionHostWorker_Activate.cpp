// ExtensionHostWorker_Activate.cpp — real manifest load + activate receipt.
#include "ExtensionHostWorker_Activate.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

static std::string grabJson(const std::string& j, const char* key) {
    std::string k = std::string("\"") + key + "\"";
    size_t p = j.find(k);
    if (p == std::string::npos) return {};
    p = j.find(':', p);
    if (p == std::string::npos) return {};
    p = j.find('"', p);
    if (p == std::string::npos) return {};
    size_t e = j.find('"', p + 1);
    if (e == std::string::npos) return {};
    return j.substr(p + 1, e - p - 1);
}

int ExtHost_LoadAndActivate(ExtHostActivateResult* io) {
    if (!io) return 0;
    io->loadOk = 0;
    io->activateOk = 0;
    io->mainPresent = 0;
    if (!io->extensionPath[0]) {
        std::snprintf(io->detail, sizeof(io->detail), "missing --extension-path");
        return 0;
    }
    fs::path dir(io->extensionPath);
    fs::path pkg = dir / "package.json";
    if (!fs::exists(pkg)) {
        std::snprintf(io->detail, sizeof(io->detail), "package.json missing");
        return 0;
    }
    std::ifstream in(pkg.string(), std::ios::binary);
    if (!in) {
        std::snprintf(io->detail, sizeof(io->detail), "package.json unreadable");
        return 0;
    }
    std::string json((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    std::string name = grabJson(json, "name");
    std::string pub = grabJson(json, "publisher");
    std::string main = grabJson(json, "main");
    if (name.empty()) {
        std::snprintf(io->detail, sizeof(io->detail), "manifest name missing");
        return 0;
    }
    if (!io->extensionId[0]) {
        std::string id = pub.empty() ? name : (pub + "." + name);
        std::snprintf(io->extensionId, sizeof(io->extensionId), "%s", id.c_str());
    }
    io->loadOk = 1;
    if (!main.empty()) {
        fs::path mainPath = dir / main;
        io->mainPresent = fs::exists(mainPath) ? 1 : 0;
    }
    // Native activate: manifest + main present (JS engine = tip_ext lane).
    if (io->mainPresent) {
        io->activateOk = 1;
        std::snprintf(io->detail, sizeof(io->detail), "native_activate main_ok");
    } else {
        std::snprintf(io->detail, sizeof(io->detail), "main entry missing");
    }
    return io->activateOk;
}

void ExtHost_WriteReceipt(const ExtHostActivateResult& r) {
    const char* env = std::getenv("RAWRXD_EXT_HOST_RECEIPT");
    const char* path = (env && env[0]) ? env
        : "F:\\rawrxd\\evidence\\EXT_HOST_WORKER_RECEIPT.txt";
    FILE* f = nullptr;
    if (fopen_s(&f, path, "w") != 0 || !f) return;
    fprintf(f,
            "LOAD_OK=%d\nACTIVATE_OK=%d\nMAIN_PRESENT=%d\nPROCESS_ALIVE=%d\n"
            "EXTENSION_ID=%s\nEXTENSION_PATH=%s\nDETAIL=%s\nPROMOTE=0\n",
            r.loadOk, r.activateOk, r.mainPresent, r.processAlive,
            r.extensionId, r.extensionPath, r.detail);
    fclose(f);
}
