#include "inference_backend.h"
#include "rawr_engine.h"

namespace RawrXD::Serve {

namespace {
// Single global engine instance for the serve binary.
static RawrEngine g_engine;
}

bool RawrEngineBackend::loadModel(const std::string& ggufPath) {
    // RawrEngine::load(path, tok_path, merge_path)
    // For GGUF models, tokenizer is embedded; pass empty strings for tok/merge.
    bool ok = g_engine.load(ggufPath.c_str(), "", "");
    if (!ok) return false;

    m_loaded = true;
    auto slash = ggufPath.find_last_of("/\\");
    auto stem = (slash == std::string::npos) ? ggufPath : ggufPath.substr(slash + 1);
    auto dot = stem.find_last_of('.');
    m_modelName = (dot == std::string::npos) ? stem : stem.substr(0, dot);
    return true;
}

void RawrEngineBackend::generate(
    const GenerateRequest& req,
    TokenCallback cb) {
    if (!m_loaded) {
        GenerationChunk err;
        err.done = true;
        err.finish_reason = "error";
        cb(err);
        return;
    }

    // Adapt RawrEngine's const char* callback to our TokenCallback
    auto adapter = [&cb](const char* tok) {
        GenerationChunk c;
        if (tok) c.token = tok;
        cb(c);
    };

    g_engine.generate(req.prompt, req.num_predict, adapter);

    // Final chunk
    GenerationChunk done;
    done.done = true;
    done.finish_reason = "stop";
    cb(done);
}

} // namespace RawrXD::Serve
