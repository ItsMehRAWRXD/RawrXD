// RAWRXD_EXTENSION_HOST_001 — certification for the VS Code extension runtime.
//
// This certifies the REAL runtime, built from TRACKED source:
//
//   1. the shared VSCodeExtensionAPI runtime initializes against the
//      ExtensionHostBridge — the one narrow interface the IDE and the CLI
//      both implement,
//   2. a native command registers and executes,
//   3. a JavaScript extension registers a command through
//      vscode.commands.registerCommand and that command executes,
//   4. the two paths share ONE registry, not two runtimes,
//   5. the seven native commands the IDE bridge registers are present in the
//      tracked source with real handlers.
//
// Nothing here is a stub: the API, the JS host and the QuickJS runtime are
// the production sources.

#include "core/js_extension_host.hpp"
#include "core/patch_result.hpp"
#include "modules/vscode_extension_api.h"
#include "modules/extension_host_bridge.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

using PatchResult = ::PatchResult;
using JSExtensionHost = ::JSExtensionHost;
using VSCodeExtensionAPI = vscode::VSCodeExtensionAPI;
using VSCodeAPIResult = ::VSCodeAPIResult;

// ---------------------------------------------------------------------------
// A bridge adapter.
//
// The bridge is the only way into the host application. This adapter records
// what the runtime asks the host to do, so the certification can prove the
// runtime really uses the seam rather than reaching around it.
// ---------------------------------------------------------------------------
class CertBridge final : public ExtensionHostBridge {
public:
    void addOutputTab(const std::string& name) override {
        outputTabs.push_back(name);
    }
    void appendToOutput(const std::string& text, const std::string& tabName) override {
        output.push_back(text);
        (void)tabName;
    }
    void addProblem(const std::string& file, int line, int col,
                    const std::string& message, int severity) override {
        problems.push_back(file + ":" + std::to_string(line) + ":" + std::to_string(col) +
                           " " + message + " (" + std::to_string(severity) + ")");
    }
    HTREEITEM addTreeItem(HTREEITEM parent, const std::string& text,
                           const std::string& fullPath, bool isDirectory) override {
        (void)parent; (void)text; (void)fullPath; (void)isDirectory;
        return nullptr;
    }
    HWND getStatusBar() override { return nullptr; }
    bool isDebugActive() const override { return false; }
    std::string getDebugCurrentFile() const override { return {}; }
    ExtensionHostSettings getSettings() const override { return settings; }
    bool setSetting(const std::string& key, const std::string& value) override {
        settings.fontName = key;
        return true;
    }
    void* terminalContext() override { return nullptr; }

    std::vector<std::string> outputTabs;
    std::vector<std::string> output;
    std::vector<std::string> problems;
    ExtensionHostSettings settings;
};

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------
struct Result {
    std::string name;
    bool passed = false;
    std::string detail;
};
static std::vector<Result> g_results;

static void check(const char* name, bool passed, const std::string& detail) {
    g_results.push_back({name, passed, detail});
    std::cout << (passed ? "  [PASS] " : "  [FAIL] ") << name << " - " << detail << "\n";
}

static bool g_nativeHandlerRan = false;
static void nativeHandler(void* ctx) {
    (void)ctx;
    g_nativeHandlerRan = true;
}

static bool g_jsHandlerRan = false;

// ---------------------------------------------------------------------------
// A JavaScript extension that registers a command through the VS Code API.
// ---------------------------------------------------------------------------
static bool writeJsExtension(const fs::path& dir) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    {
        std::ofstream pkg(dir / "package.json");
        pkg << "{\n"
            << "  \"name\": \"cert-extension\",\n"
            << "  \"version\": \"1.0.0\",\n"
            << "  \"main\": \"./extension.js\",\n"
            << "  \"engines\": { \"vscode\": \"^1.0.0\" }\n"
            << "}\n";
    }
    {
        std::ofstream js(dir / "extension.js");
        // The host binds the API as a GLOBAL (`vscode`), not as a module that
        // require() can resolve, so the extension uses the global directly and
        // only falls back to require() if that is ever not the case.
        js << "var api = (typeof vscode !== 'undefined') ? vscode : null;\n"
            << "if (!api) { try { api = require('vscode'); } catch (e) { api = null; } }\n"
            << "if (api && api.commands) {\n"
            << "  api.commands.registerCommand('cert.js.command', function () {\n"
            << "    return 'js-handler-ran';\n"
            << "  });\n"
            << "}\n";
    }
    return true;
}

// ---------------------------------------------------------------------------
// The IDE's native command set.
//
// These are the seven commands the IDE registers through the same API the JS
// runtime uses. The certification reads the tracked source so the assertion
// is about the source that is actually committed.
// ---------------------------------------------------------------------------
static const char* const kNativeCommandIds[] = {
    "rawrxd.openFile", "rawrxd.saveFile", "rawrxd.toggleTerminal",
    "rawrxd.hotpatchStatus", "rawrxd.lspStart", "rawrxd.editorEngineCycle",
    "rawrxd.extensionAPIStats",
};

static std::string readAll(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

int main(int argc, char** argv) {
    const fs::path repo = (argc > 1) ? fs::path(argv[1]) : fs::current_path();
    const fs::path work = fs::temp_directory_path() / "rawrxd_ext_host_cert";

    std::cout << "==========================================================\n";
    std::cout << " RAWRXD_EXTENSION_HOST_001\n";
    std::cout << "==========================================================\n";

    CertBridge bridge;
    VSCodeExtensionAPI& api = VSCodeExtensionAPI::instance();

    // ---- 1. the shared runtime initializes against the bridge -------------
    const VSCodeAPIResult init = api.initialize(&bridge, nullptr);
    check("the shared runtime initializes against the ExtensionHostBridge",
          init.success && api.isInitialized(),
          std::string("initialize -> ") + (init.detail ? init.detail : "ok"));

    // ---- 2. a native command registers ------------------------------------
    const size_t before = api.getCommandCount();
    const VSCodeAPIResult reg =
        api.registerCommand("cert.native.command", nativeHandler, nullptr);
    check("registerCommand accepts a native command",
          reg.success && api.getCommandCount() == before + 1,
          std::string("command_count ") + std::to_string(before) + " -> " +
              std::to_string(api.getCommandCount()));

    // ---- 3. executeCommand runs it ----------------------------------------
    g_nativeHandlerRan = false;
    const VSCodeAPIResult exec = api.executeCommand("cert.native.command");
    check("executeCommand runs the native handler",
          exec.success && g_nativeHandlerRan,
          std::string("handler_ran=") + (g_nativeHandlerRan ? "yes" : "no"));

    // ---- 4. an unknown command fails without crashing ---------------------
    g_nativeHandlerRan = false;
    const VSCodeAPIResult unknown = api.executeCommand("cert.no.such.command");
    check("an unknown command fails cleanly",
          !unknown.success && !g_nativeHandlerRan,
          std::string("errorCode=") + std::to_string(unknown.errorCode));

    // ---- 5. a JavaScript extension registers a command ---------------------
    std::error_code ec;
    fs::remove_all(work, ec);
    const fs::path extDir = work / "cert-extension";
    writeJsExtension(extDir);

    JSExtensionHost& host = JSExtensionHost::instance();
    const PatchResult hostInit = host.initialize();
    const size_t beforeJs = api.getCommandCount();
    const PatchResult loaded = host.loadExtensionFromDir(extDir.string().c_str());

    // The extension body runs at activation, not at load, so the command is
    // registered when the extension is activated.
    std::string extensionId;
    {
        JSExtensionState states[16] = {};
        size_t count = 0;
        host.getLoadedExtensions(states, 16, &count);
        for (size_t i = 0; i < count; ++i) {
            if (states[i].extensionId[0] != '\0') { extensionId = states[i].extensionId; break; }
        }
    }
    PatchResult activated;
    if (!extensionId.empty()) {
        activated = host.activateExtension(extensionId.c_str());
    }
    const size_t afterJs = api.getCommandCount();

    check("a JavaScript extension loads and registers a command",
          loaded.success && activated.success && afterJs > beforeJs,
          std::string("load -> ") + loaded.detail + "; activate -> " + activated.detail +
              "; extension_id=" + (extensionId.empty() ? "(none)" : extensionId) +
              "; command_count " + std::to_string(beforeJs) + " -> " +
              std::to_string(afterJs));

    // ---- 6. the JS-registered command executes through the SAME registry ---
    // A probe in the extension's own context says exactly how far the JS got,
    // so a failure names its cause rather than just its symptom.
    std::string probeDetail;
    {
        char buf[256] = {0};
        const char* probes[] = {
            "typeof vscode",
            "typeof vscode.commands",
            "typeof vscode.commands.registerCommand",
        };
        for (const char* p : probes) {
            const PatchResult r = host.executeScript(extensionId.c_str(), p, buf, sizeof(buf));
            probeDetail += std::string(p) + "=" +
                (r.success && buf[0] ? buf : "(failed)") + "; ";
        }
    }
    const VSCodeAPIResult jsExec = api.executeCommand("cert.js.command");
    check("the JS-registered command is executable through the same API",
          jsExec.success,
          std::string("executeCommand(cert.js.command) -> ") +
              (jsExec.success ? "ok" : (jsExec.detail ? jsExec.detail : "failed")) +
              " | probe: " + probeDetail);

    // ---- 7. the seven IDE native commands are in the tracked source -------
    {
        const fs::path bridgeSource = repo / "src" / "win32app" / "Win32IDE_VSCodeExtAPI.cpp";
        const std::string text = readAll(bridgeSource);
        int found = 0;
        std::string missing;
        for (const char* id : kNativeCommandIds) {
            const std::string needle = std::string("api.registerCommand(\"") + id + "\"";
            if (text.find(needle) != std::string::npos) ++found;
            else missing += std::string(missing.empty() ? "" : ", ") + id;
        }
        check("all seven native commands are registered in the tracked source",
              found == 7,
              std::to_string(found) + "/7 found" +
                  (missing.empty() ? "" : ("; missing: " + missing)));
    }

    // ---- 8. one runtime, not two ------------------------------------------
    {
        // The extension API is defined once and the bridge is its only route
        // into the host. A second definition would be a parallel runtime.
        const std::string header = readAll(repo / "src" / "modules" / "vscode_extension_api.h");
        const bool usesBridge = header.find("extension_host_bridge.h") != std::string::npos;
        int definitions = 0;
        for (const char* f : {"src/modules/vscode_extension_api.h", "src/core/js_extension_host.hpp",
                              "src/modules/quickjs_extension_host.h"}) {
            const std::string t = readAll(repo / f);
            // A forward declaration is not a definition. Only a class with a
            // body counts, so a second runtime cannot hide behind one.
            if (t.find("class VSCodeExtensionAPI {") != std::string::npos) ++definitions;
        }
        check("there is one extension runtime, reached through the bridge",
              usesBridge && definitions == 1,
              std::string("bridge_included=") + (usesBridge ? "yes" : "no") +
                  " api_definitions=" + std::to_string(definitions));
    }

    // ---- summary ----------------------------------------------------------
    int passed = 0, failed = 0;
    for (const Result& r : g_results) {
        if (r.passed) ++passed; else ++failed;
    }
    std::cout << "\n--------------------------------------------------------\n";
    std::cout << "RAWRXD_EXTENSION_HOST_001: " << passed << " passed, " << failed << " failed\n";
    std::cout << "--------------------------------------------------------\n";

    fs::remove_all(work, ec);
    return failed == 0 ? 0 : 1;
}
