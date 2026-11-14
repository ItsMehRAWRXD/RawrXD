#include "rawr_commands.hpp"
#include "rawr_output_router.hpp"
#include "rawr_console_repl.hpp"
#include "rawr_session_store.hpp"
#include "../deep2/RawrRunSession.hpp"
#include "../deep2/GpuPreflight.hpp"
#include "../deep2/lavapath/ProductRun.hpp"
#include "../deep2/lavapath/ProductStreamerPrep.hpp"
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
struct QuietStdout {
    int saved = -1;
    QuietStdout() {
        fflush(stdout);
        saved = _dup(1);
        if (saved >= 0) _dup2(2, 1);
    }
    ~QuietStdout() {
        if (saved >= 0) {
            fflush(stdout);
            _dup2(saved, 1);
            _close(saved);
        }
    }
};
#endif

namespace rawr {

void PrintUsage() {
    Diag("Usage:\n");
    Diag("  rawr list [--verbose] [--refresh]\n");
    Diag("  rawr show <model>\n");
    Diag("  rawr paths\n");
    Diag("  rawr run <model> [prompt|-p P|--prompt P] [--max-tokens N]\n");
    Diag("  rawr run <model> --reap <params>/<experts> [-p P] [--receipt R]\n");
    Diag("  rawr run <model> --size <params>/<experts> [-p P] [--receipt R]\n");
    Diag("             live size alias: working-set budget + MoE top-k\n");
    Diag("  rawr run <model> [--verbose|--trace]  # stdin if prompt empty\n");
    Diag("  rawr chat|agent|steer|resume|term|serve|debug ...\n");
    Diag("  rawr agent status [session_id]\n");
    Diag("  rawr resume <session_id> [-p prompt] [--max-tokens N] [--vulkan]\n");
    Diag("  rawr serve [--help] [--pipe NAME] [--http] [--port N]\n");
    Diag("  rawr debug [status|dap|help]  # CLI debugger front door\n");
}

int CmdChat(const CliArgs& a) {
    if (a.model.empty()) { PrintUsage(); return ExitCode::Usage; }
    if (!Deep2::ProductStreamerPrep()) return ExitCode::Runtime;
    /* Match CmdRun: GPU preflight + Vulkan arm before OpenSession.
     * Without enableVulkan, InitFromPath can INITIALIZE_OK then POST_LOAD
     * gguf=0 (isModelLoaded=0) — chat oneshot NO_RUN_STATE. */
    if (!GpuPreflightCheck(!a.vulkan)) return ExitCode::Runtime;
    SessionState s{};
    s.id = NewSessionId();
    s.modelAlias = a.model;
    s.workspace = a.workspace;
    s.autonomy = a.autoLevel;
    Deep2::Deep2Engine engine;
    {
        const char* host = std::getenv("RAWRXD_HOST_DECODE");
        const bool cpuOpt = (host && host[0] == '1');
        engine.enableVulkan(!cpuOpt);
    }
    Deep2::rawr_run::RunWitness w{};
    {
#ifdef _WIN32
        QuietStdout q;
#endif
        if (!Deep2::rawr_run::OpenSession(engine, a.model.c_str(), w))
            return ExitCode::ModelLoad;
        s.modelPath = w.modelPath;
    }
    Diag("session=%s model=%s\n", s.id.c_str(), a.model.c_str());
    auto runOne = [&](const std::string& line) {
        s.history.push_back({"user", line});
        std::string acc;
        {
#ifdef _WIN32
            QuietStdout q;
#endif
            rawr::product_run::Request req{};
            req.modelAlias = a.model.c_str();
            req.prompt = line.c_str();
            req.maxTokens = a.maxTokens ? a.maxTokens : 256u;
            req.engine = &engine;
            req.keepOpen = 1;
            acc = rawr::product_run::ProductRun(req).text;
        }
        OutTextLn(acc);
        s.history.push_back({"assistant", acc});
        SaveSession(s);
    };
    /* One-shot: -p/--prompt or non-TTY stdin (ParseArgs ReadStdinPrompt).
     * Empty prompt + TTY → REPL; empty + redirected EOF → fail-closed (no
     * CLEAN_EXIT_NO_TOKENS / NO_RUN_STATE false pass). */
    if (!a.prompt.empty()) {
        runOne(a.prompt);
    } else {
#ifdef _WIN32
        if (!_isatty(_fileno(stdin))) {
            Diag("rawr chat: empty prompt on non-TTY stdin (NO_RUN_STATE)\n");
            return ExitCode::Usage;
        }
#endif
        std::string line;
        while (ReadReplLine(line)) {
            if (line == "/quit" || line == "/exit") break;
            runOne(line);
        }
    }
#ifdef _WIN32
    { QuietStdout q; engine.unloadModel(); }
#else
    engine.unloadModel();
#endif
    Diag("saved session %s\n", s.id.c_str());
    return ExitCode::Ok;
}

int CmdDebug(const CliArgs& a) {
    const std::string sub = a.model.empty() ? "status" : a.model;
    Diag("rawr debug RUNTIME_REACHED=1\n");
    if (sub == "help" || a.help) {
        Diag("usage: rawr debug [status|dap|help]\n");
        Diag("  status  session root + recent sessions (disk)\n");
        Diag("  dap     probe sibling DAP adapter binary\n");
        return ExitCode::Ok;
    }
    if (sub == "dap") {
        char self[MAX_PATH] = {};
        DWORD n = GetModuleFileNameA(nullptr, self, MAX_PATH);
        std::string dir = (n && n < MAX_PATH) ? self : "";
        size_t slash = dir.find_last_of("\\/");
        if (slash != std::string::npos) dir.resize(slash + 1);
        else dir.clear();
        const char* names[] = {
            "RawrXDScriptDAPAdapter.exe", "rawrxd_script_dap_adapter.exe",
            "BeaconDAPServer.exe", nullptr};
        int found = 0;
        for (int i = 0; names[i]; ++i) {
            std::string p = dir + names[i];
            DWORD attr = GetFileAttributesA(p.c_str());
            const int ok = (attr != INVALID_FILE_ATTRIBUTES &&
                            !(attr & FILE_ATTRIBUTE_DIRECTORY));
            Diag("DAP_PROBE path=%s present=%d\n", p.c_str(), ok);
            found += ok;
        }
        Diag("DAP_ADAPTER_PRESENT=%d DAP_ATTACH_E2E=NOT_RUN\n", found > 0);
        Diag("DISPOSITION=%s\n",
             found > 0 ? "DAP_BINARY_PROBED" : "DAP_BINARY_ABSENT");
        return ExitCode::Ok;
    }
    /* status (default): non-hang disk inspect */
    const std::string root = DefaultSessionRoot();
    Diag("SESSION_ROOT=%s\n", root.c_str());
    int nSess = 0;
#ifdef _WIN32
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA((root + "\\*.session").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            Diag("SESSION=%s\n", fd.cFileName);
            if (++nSess >= 8) break;
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#endif
    Diag("SESSION_COUNT_SHOWN=%d\n", nSess);
    Diag("DEBUG_SURFACE=CLI_STATUS DAP_ATTACH_E2E=NOT_RUN\n");
    return ExitCode::Ok;
}

} // namespace rawr
