// Tip-only ExtensionHost product wire (compiled only into Native-Ext).
#include "Win32IDE_ExtHostWire.h"
#include "core/js_extension_host.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

namespace {

void setDetail(ExtHostWireResult* out, const std::string& msg) {
    if (!out) return;
    std::snprintf(out->detail, sizeof(out->detail), "%s", msg.c_str());
}

void setId(ExtHostWireResult* out, const std::string& id) {
    if (!out) return;
    std::snprintf(out->extensionId, sizeof(out->extensionId), "%s", id.c_str());
}

std::string trim(std::string s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '"'))
        s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '"'))
        s.pop_back();
    return s;
}

bool takeFlag(std::string& rest, const char* flag, std::string& value) {
    const std::string f(flag);
    const std::string feq = f + "=";
    if (rest.rfind(feq, 0) == 0) {
        rest = rest.substr(feq.size());
    } else if (rest.rfind(f + " ", 0) == 0 || rest == f) {
        rest = trim(rest.substr(f.size()));
        if (!rest.empty() && rest[0] == '=') rest = trim(rest.substr(1));
    } else {
        return false;
    }
    size_t next = rest.find(" --");
    if (next == std::string::npos) {
        value = trim(rest);
        rest.clear();
    } else {
        value = trim(rest.substr(0, next));
        rest = trim(rest.substr(next + 1));
    }
    return true;
}

bool ensureInit(ExtHostWireResult* out) {
    auto& host = JSExtensionHost::instance();
    if (host.isInitialized()) {
        if (out) out->initOk = true;
        return true;
    }
    PatchResult pr = host.initialize();
    if (out) {
        out->initOk = pr.success;
        if (!pr.success) setDetail(out, pr.detail.empty() ? "initialize failed" : pr.detail);
    }
    return pr.success;
}

std::string readExtIdFromDir(const std::string& dir) {
    fs::path pkg = fs::path(dir) / "package.json";
    if (!fs::exists(pkg)) pkg = fs::path(dir) / "extension" / "package.json";
    if (!fs::exists(pkg)) return {};
    std::ifstream in(pkg.string(), std::ios::binary);
    if (!in) return {};
    std::string json((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    auto grab = [&](const char* key) -> std::string {
        std::string k = std::string("\"") + key + "\"";
        size_t p = json.find(k);
        if (p == std::string::npos) return {};
        p = json.find(':', p);
        if (p == std::string::npos) return {};
        p = json.find('"', p);
        if (p == std::string::npos) return {};
        size_t e = json.find('"', p + 1);
        if (e == std::string::npos) return {};
        return json.substr(p + 1, e - p - 1);
    };
    std::string name = grab("name");
    std::string pub = grab("publisher");
    if (name.empty()) return {};
    return pub.empty() ? name : (pub + "." + name);
}

bool loadPath(const std::string& path, ExtHostWireResult* out) {
    if (!ensureInit(out)) return false;
    auto& host = JSExtensionHost::instance();
    PatchResult pr;
    if (path.size() >= 5 && _stricmp(path.c_str() + path.size() - 5, ".vsix") == 0) {
        fs::path installDir = fs::path(path).parent_path() /
                              (fs::path(path).stem().string() + "_extracted");
        std::error_code ec;
        fs::create_directories(installDir, ec);
        pr = host.loadVSIX(path.c_str(), installDir.string().c_str());
    } else {
        pr = host.loadExtensionFromDir(path.c_str());
    }
    if (out) {
        out->loadOk = pr.success;
        if (!pr.success) setDetail(out, pr.detail.empty() ? "load failed" : pr.detail);
    }
    return pr.success;
}

}  // namespace

bool RawrXD_ExtHost_InstallPath(const std::string& pathOrId, ExtHostWireResult* out) {
    ExtHostWireResult local{};
    ExtHostWireResult* r = out ? out : &local;
    std::memset(r, 0, sizeof(*r));
    r->attempted = true;
    r->processAlive = true;
    if (pathOrId.empty()) {
        setDetail(r, "empty path");
        return false;
    }
    if (!loadPath(pathOrId, r)) return false;

    std::string id = readExtIdFromDir(pathOrId);
    if (id.empty() && pathOrId.size() >= 5 &&
        _stricmp(pathOrId.c_str() + pathOrId.size() - 5, ".vsix") == 0) {
        fs::path installDir = fs::path(pathOrId).parent_path() /
                              (fs::path(pathOrId).stem().string() + "_extracted");
        id = readExtIdFromDir(installDir.string());
    }
    if (id.empty()) {
        setDetail(r, "loaded but extension id unresolved");
        return r->loadOk;
    }
    setId(r, id);
    PatchResult act = JSExtensionHost::instance().activateExtension(id.c_str());
    r->activateOk = act.success;
    if (!act.success) setDetail(r, act.detail.empty() ? "activate failed" : act.detail);
    return act.success;
}

bool RawrXD_ExtHost_HandleCmdLine(const char* lpCmdLine, ExtHostWireResult* out) {
    ExtHostWireResult local{};
    ExtHostWireResult* r = out ? out : &local;
    std::memset(r, 0, sizeof(*r));
    r->processAlive = true;
    if (!lpCmdLine || !*lpCmdLine) return false;
    std::string rest = trim(lpCmdLine);
    if (rest.find("--ext-") == std::string::npos && rest.find("--vsix") == std::string::npos)
        return false;

    r->attempted = true;
    std::string extDir, vsix, cmd, malformed, activateId, deactivateId;
    bool doReload = false;
    bool doQuit = false;

    while (!rest.empty()) {
        std::string val;
        if (takeFlag(rest, "--ext-dir", val)) { extDir = val; continue; }
        if (takeFlag(rest, "--vsix", val)) { vsix = val; continue; }
        if (takeFlag(rest, "--ext-cmd", val)) { cmd = val; continue; }
        if (takeFlag(rest, "--ext-malformed", val)) { malformed = val; continue; }
        if (takeFlag(rest, "--ext-activate", val)) { activateId = val; continue; }
        if (takeFlag(rest, "--ext-deactivate", val)) { deactivateId = val; continue; }
        if (takeFlag(rest, "--ext-reload", val)) { activateId = val; doReload = true; continue; }
        if (rest.rfind("--ext-quit", 0) == 0) {
            doQuit = true;
            rest = trim(rest.substr(std::strlen("--ext-quit")));
            continue;
        }
        break;
    }

    if (!malformed.empty()) {
        bool ok = loadPath(malformed, r);
        r->faultIsolated = (!ok) && r->processAlive;
        r->loadOk = false;
        if (r->faultIsolated) setDetail(r, "malformed rejected; process alive");
        else if (ok) setDetail(r, "malformed unexpectedly loaded");
    } else if (!vsix.empty()) {
        loadPath(vsix, r);
        if (r->loadOk) {
            std::string id = activateId;
            if (id.empty()) {
                fs::path installDir = fs::path(vsix).parent_path() /
                                      (fs::path(vsix).stem().string() + "_extracted");
                id = readExtIdFromDir(installDir.string());
            }
            if (!id.empty()) {
                setId(r, id);
                PatchResult act = JSExtensionHost::instance().activateExtension(id.c_str());
                r->activateOk = act.success;
                if (!act.success) setDetail(r, act.detail.empty() ? "activate failed" : act.detail);
            }
        }
    } else if (!extDir.empty()) {
        loadPath(extDir, r);
        if (r->loadOk) {
            std::string id = activateId.empty() ? readExtIdFromDir(extDir) : activateId;
            if (!id.empty()) {
                setId(r, id);
                PatchResult act = JSExtensionHost::instance().activateExtension(id.c_str());
                r->activateOk = act.success;
                if (!act.success) setDetail(r, act.detail.empty() ? "activate failed" : act.detail);
            }
        }
    }

    const char* receiptEnv = std::getenv("RAWRXD_EXT_RUNTIME_RECEIPT");
    const char* receipt = (receiptEnv && receiptEnv[0])
        ? receiptEnv
        : "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\artifacts\\ext_runtime_receipt.txt";
    if (!cmd.empty() && r->extensionId[0]) {
        // Headless-safe: invoke registered JS command via C++ trampoline.
        // JS executeCommand → vsapi → bridgeCommandToIDM can hang/abort without a pump.
        setDetail(r, "ext-cmd pending");
        RawrXD_ExtHost_WriteReceipt(*r, receipt);
        PatchResult ex =
            JSExtensionHost::instance().invokeRegisteredCommand(cmd.c_str());
        r->cmdOk = ex.success;
        if (!ex.success) {
            setDetail(r, ex.detail.empty() ? "ext-cmd failed" : ex.detail);
        } else {
            setDetail(r, "");
        }
    }

    if (!deactivateId.empty() || (doReload && r->extensionId[0])) {
        const char* id = !deactivateId.empty() ? deactivateId.c_str() : r->extensionId;
        PatchResult de = JSExtensionHost::instance().deactivateExtension(id);
        r->deactivateOk = de.success;
        if (doReload && de.success) {
            PatchResult re = JSExtensionHost::instance().activateExtension(id);
            r->reloadOk = re.success;
        }
    } else if (doQuit && r->extensionId[0] && r->activateOk) {
        // Full smoke path: load→activate→cmd→unload on --ext-quit.
        PatchResult de = JSExtensionHost::instance().deactivateExtension(r->extensionId);
        r->deactivateOk = de.success;
        PatchResult un = JSExtensionHost::instance().unloadExtension(r->extensionId);
        r->reloadOk = un.success;
    }

    RawrXD_ExtHost_WriteReceipt(*r, receipt);

    // Quit ownership: main_win32 DestroyWindow→onDestroy→PostQuitMessage(+re-arm).
    // PostQuitMessage-only here left HWND alive and ~Win32IDE joined discovery
    // past the smoke WaitForExit budget (EXT_CLEANUP FORCE_KILL=1).
    if (doQuit) PostQuitMessage(0);
    return true;
}

void RawrXD_ExtHost_WriteReceipt(const ExtHostWireResult& r, const char* receiptPath) {
    if (!receiptPath) return;
    std::error_code ec;
    fs::create_directories(fs::path(receiptPath).parent_path(), ec);
    std::ofstream out(receiptPath, std::ios::trunc);
    if (!out) return;
    out << "ATTEMPTED=" << (r.attempted ? 1 : 0) << "\n"
        << "INIT_OK=" << (r.initOk ? 1 : 0) << "\n"
        << "LOAD_OK=" << (r.loadOk ? 1 : 0) << "\n"
        << "ACTIVATE_OK=" << (r.activateOk ? 1 : 0) << "\n"
        << "CMD_OK=" << (r.cmdOk ? 1 : 0) << "\n"
        << "DEACTIVATE_OK=" << (r.deactivateOk ? 1 : 0) << "\n"
        << "RELOAD_OK=" << (r.reloadOk ? 1 : 0) << "\n"
        << "FAULT_ISOLATED=" << (r.faultIsolated ? 1 : 0) << "\n"
        << "PROCESS_ALIVE=" << (r.processAlive ? 1 : 0) << "\n"
        << "EXTENSION_ID=" << r.extensionId << "\n"
        << "DETAIL=" << r.detail << "\n";
}
