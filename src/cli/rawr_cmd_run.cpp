// rawr_cmd_run.cpp — product rawr run via Deep2StreamSession
#include "rawr_commands.hpp"
#include "rawr_output_router.hpp"
#include "rawr_model_registry.hpp"
#include "rawr_out_gate.hpp"
#include "../deep2/Deep2Engine.h"
#include "../deep2/daily/d2_stream_session.h"
#include "../deep2/daily/d2_deep2_binding.h"
#include "../deep2/daily/d2_session_engine.h"
#include "../deep2/lavapath/ProductStreamerPrep.hpp"
#include <cstdlib>
#include <string>

namespace rawr {
namespace {
int OnTok(void* user, uint32_t, const char* text, size_t n) {
    if (user) static_cast<OutGate*>(user)->emit(text, n);
    return 1;
}
} // namespace

int CmdRun(const CliArgs& a) {
    if (a.model.empty()) { PrintUsage(); return ExitCode::Usage; }
    if (a.verbose) _putenv_s("RAWRXD_D2_SESSION_TRACE", "1");
    auto& reg = ModelRegistry::instance();
    reg.scan(a.refresh);
    ModelEntry ent;
    if (!reg.resolve(a.model, ent) || ent.path.empty()) {
        Diag("rawr: model resolve failed: %s\n", a.model.c_str());
        return ExitCode::ModelResolve;
    }
    if (a.prompt.empty()) {
        Diag("rawr: prompt required (-p/--prompt/stdin)\n");
        return ExitCode::Usage;
    }
    uint32_t maxTok = a.maxTokens ? a.maxTokens : 64u;
    if (const char* e = std::getenv("RAWRXD_RUN_MAX_TOKENS"))
        if (e[0] && !a.maxTokens) maxTok = (uint32_t)std::atoi(e);

    /* Gate before ProductStreamerPrep — prep/engine noise → stderr. */
    OutGate gate;
    if (!Deep2::ProductStreamerPrep()) return ExitCode::Runtime;
    Deep2::Deep2Engine engine;
    Deep2StreamSession* s = d2_session_create();
    if (!s) return ExitCode::Runtime;
    if (a.verbose) d2_session_set_trace(s, 1);
    if (!d2_session_bind_deep2_engine_ptr(s, &engine) ||
        d2_session_backend_is_mock(s)) {
        Diag("rawr: REAL_BIND failed (mock backend)\n");
        d2_session_destroy(s);
        return ExitCode::Runtime;
    }
    if (!d2_session_open_model(s, ent.path.c_str())) {
        Diag("rawr: model open failed: %s\n", ent.path.c_str());
        d2_session_destroy(s);
        return ExitCode::ModelLoad;
    }
    D2GenerateRequest req{};
    req.prompt = a.prompt.c_str();
    req.max_tokens = maxTok;
    req.temperature = 0.f;
    req.seed = 42;
    int ok = d2_session_generate(s, &req, OnTok, &gate);
    d2_session_close_model(s);
    d2_session_destroy(s);
    if (!ok) { Diag("rawr: generate failed\n"); return ExitCode::Runtime; }
    return ExitCode::Ok;
}
} // namespace rawr
