#include "GenerationBouncer.hpp"
#include "shared/SharedModelRuntime.hpp"
#include "../serve/rawrxd_serve.h"
#include <future>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <fstream>

namespace RawrXD {

// Minimal stub Logger to avoid missing header
namespace Logging {
    class Logger {
    public:
        static Logger& Instance() {
            static Logger instance;
            return instance;
        }
        void Info(const char* msg) { (void)msg; }
        void Error(const char* msg) { (void)msg; }
    };
}

using namespace Serve::Shared;

class GenerationBouncer::Impl {
public:
    std::unique_ptr<SharedModelRuntime> runtime;
    bool model_loaded = false;
    ModelStats stats;
    std::string model_path;

    Impl() {
        runtime = std::make_unique<SharedModelRuntime>();
    }

    bool LoadModel(const std::string& path) {
        model_path = path;

        if (!runtime->initialize({16ULL * 1024 * 1024 * 1024, 32ULL * 1024 * 1024 * 1024})) {
            return false;
        }

        if (!runtime->loadModel(path)) {
            return false;
        }

        model_loaded = true;
        stats.num_parameters = 0;
        stats.num_layers = 0;
        stats.vocab_size = 0;
        stats.context_length = 0;
        stats.model_type = "unknown";

        return true;
    }

    GenerationResult RunPipeline(const GenerationRequest& req) {
        GenerationResult result;
        auto start_time = std::chrono::high_resolution_clock::now();

        if (!runtime || !runtime->isModelLoaded()) {
            result.error = "Runtime not initialized";
            result.success = false;
            return result;
        }

        uint64_t seq = runtime->beginSequence();
        auto cleanup = [&]() {
            runtime->endSequence(seq);
        };

        // Build a GenerateRequest compatible with SharedModelRuntime
        Serve::GenerateRequest genReq;
        genReq.prompt       = req.prompt;
        genReq.num_predict  = req.max_tokens;
        genReq.temperature  = req.temperature;
        genReq.top_p        = req.top_p;
        genReq.top_k        = req.top_k;
        genReq.repeat_penalty = req.repetition_penalty;

        std::string generated = runtime->generate(genReq,
            [&](const std::string& token, bool done) {
                if (req.on_token)
                    req.on_token(token);
                (void)done;
            });

        cleanup();

        result.text = std::move(generated);
        result.tokens_generated = static_cast<int>(result.text.length() / 4);

        auto end_time = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(
            end_time - start_time).count();

        result.tokens_per_second = (elapsed_ms > 0)
            ? (result.tokens_generated * 1000.0 / elapsed_ms)
            : 0.0;
        result.time_to_first_token_ms = elapsed_ms * 0.1;
        result.success = true;

        return result;
    }
};

// ============================================================================
// Public API
// ============================================================================

GenerationBouncer::GenerationBouncer() 
    : pimpl_(std::make_unique<Impl>()) {
}

GenerationBouncer::~GenerationBouncer() = default;

bool GenerationBouncer::Initialize(const std::string& model_path) {
    return pimpl_->LoadModel(model_path);
}

void GenerationBouncer::Shutdown() {
    if (pimpl_->runtime) {
        pimpl_->runtime->unloadModel();
        pimpl_->runtime->shutdown();
    }
    pimpl_->model_loaded = false;
}

bool GenerationBouncer::IsReady() const {
    return pimpl_->model_loaded;
}

GenerationResult GenerationBouncer::Generate(const GenerationRequest& req) {
    if (!IsReady()) {
        GenerationResult result;
        result.error = "Model not loaded. Call Initialize() first.";
        result.success = false;
        return result;
    }

    return pimpl_->RunPipeline(req);
}

GenerationResult GenerationBouncer::GenerateStreaming(GenerationRequest req) {
    if (!req.on_token) {
        GenerationResult result;
        result.error = "Streaming requires on_token callback";
        result.success = false;
        return result;
    }

    req.stream = true;
    return Generate(req);
}

GenerationBouncer::ModelStats GenerationBouncer::GetModelStats() const {
    return pimpl_->stats;
}

} // namespace RawrXD
