#include "rawr_commands.hpp"
#include "rawr_output_router.hpp"
#include "rawr_console_repl.hpp"
#include "rawr_session_store.hpp"
#include "../deep2/RawrRunSession.hpp"
#include "../deep2/lavapath/ProductRun.hpp"
#include "../deep2/lavapath/ProductStreamerPrep.hpp"
#include <string>

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
    Diag("  rawr run <model> [--verbose|--trace]  # stdin if prompt empty\n");
    Diag("  rawr chat|agent|steer|resume|term|serve ...\n");
}

int CmdChat(const CliArgs& a) {
    if (a.model.empty()) { PrintUsage(); return ExitCode::Usage; }
    if (!Deep2::ProductStreamerPrep()) return ExitCode::Runtime;
    SessionState s{};
    s.id = NewSessionId();
    s.modelAlias = a.model;
    s.workspace = a.workspace;
    s.autonomy = a.autoLevel;
    Deep2::Deep2Engine engine;
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
    std::string line;
    while (ReadReplLine(line)) {
        if (line == "/quit" || line == "/exit") break;
        s.history.push_back({"user", line});
        std::string acc;
        {
#ifdef _WIN32
            QuietStdout q;
#endif
            rawr::product_run::Request req{};
            req.modelAlias = a.model.c_str();
            req.prompt = line.c_str();
            req.maxTokens = 256;
            req.engine = &engine;
            req.keepOpen = 1;
            acc = rawr::product_run::ProductRun(req).text;
        }
        OutTextLn(acc);
        s.history.push_back({"assistant", acc});
        SaveSession(s);
    }
#ifdef _WIN32
    { QuietStdout q; engine.unloadModel(); }
#else
    engine.unloadModel();
#endif
    Diag("saved session %s\n", s.id.c_str());
    return ExitCode::Ok;
}

} // namespace rawr
