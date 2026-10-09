//=============================================================================
// ModelGenieRuntime - C API over the certified Deep2 IR executor
// RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001
//
// Thin, ownership-explicit wrapper around the IR executor in
// src/modelgenie/ModelGenieExecutor.cpp. It performs no inference of its own:
// every token is produced by the same 300-operation IR dispatch table that the
// standalone rawrxd_modelgenie_ir_executor harness drives, so standalone and
// DLL outputs are derived from one implementation.
//=============================================================================

#include "ModelGenieExecutor.hpp"

#include "ModelGenieRuntime.h"

#include "gguf_embedded_tokenizer.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <utility>
#include <vector>

#ifndef MG_KV_CACHE_MAX_SEQ
#define MG_KV_CACHE_MAX_SEQ 1024
#endif

struct mg_model_t
{
    std::string gguf_path;
    mg_model_config_t config;
    std::unique_ptr<RawrXD::GGUFEmbeddedTokenizer> vocab;
    uint32_t eos_id;
    uint32_t bos_id;
    size_t vocab_size;
    size_t embedding_dim;
    std::mutex mutex;
};

struct mg_context_t
{
    mg_model_t* model;
    std::unique_ptr<IRExecutor> executor;
    std::vector<float> logits;
    size_t position;
    std::vector<uint32_t> last_tokens;
};

//=============================================================================
// Model lifecycle
//=============================================================================
MG_RUNTIME_API mg_error_t mg_model_load(
    const char* gguf_path,
    const mg_model_config_t* config,
    mg_model_t** out_model)
{
    if (!out_model || !gguf_path) return MG_ERROR_INVALID_ARGUMENT;
    *out_model = nullptr;

    FILE* probe = std::fopen(gguf_path, "rb");
    if (!probe) return MG_ERROR_FILE_NOT_FOUND;
    std::fclose(probe);

    mg_model_t* model = nullptr;
    try {
        model = new mg_model_t();
        model->gguf_path = gguf_path;
        model->config = config ? *config : mg_model_config_t();
        if (model->config.max_seq_len == 0) {
            model->config.max_seq_len = MG_KV_CACHE_MAX_SEQ;
        }
        model->vocab_size = GEN::ModelConfig::kVocabSize;
        model->embedding_dim = GEN::ModelConfig::kEmbeddingLength;
    } catch (...) {
        delete model;
        return MG_ERROR_OUT_OF_MEMORY;
    }

    // DeepSeek-V2-Lite fall-backs; corrected from the model's own metadata below.
    model->bos_id = 3;    // token 3 = the <SOS> control token
    model->eos_id = 100001;

    // Verify the IR ROM table resolves before handing the handle back. This is
    // the same check the standalone executor performs, so a model the runtime
    // accepts is a model the executor can execute. Entries 0 and 1 are the LM
    // head (output.weight) and the token embedding table - both are exercised
    // on every position of every layer.
    {
        ROMResolver resolver(model->gguf_path);
        if (!resolver.Resolve(GEN::kTensorROMTable[0].tensorId) ||
            !resolver.Resolve(GEN::kTensorROMTable[1].tensorId)) {
            delete model;
            return MG_ERROR_GGUF_PARSE;
        }
    }

    // Vocabulary drives text<->id on both sides. Without it the runtime still
    // executes, but a caller must supply token ids directly.
    try {
        model->vocab.reset(new RawrXD::GGUFEmbeddedTokenizer());
        if (model->vocab->LoadFromGGUF(model->gguf_path)) {
            model->vocab_size = model->vocab->VocabSize();
            if (model->vocab->BosToken() >= 0) {
                model->bos_id = static_cast<uint32_t>(model->vocab->BosToken());
            }
            if (model->vocab->EosToken() >= 0) {
                model->eos_id = static_cast<uint32_t>(model->vocab->EosToken());
            }
        } else {
            model->vocab.reset();
        }
    } catch (...) {
        model->vocab.reset();
    }

    *out_model = model;
    return MG_SUCCESS;
}

MG_RUNTIME_API void mg_model_free(mg_model_t* model)
{
    delete model;
}

MG_RUNTIME_API size_t mg_model_vocab_size(const mg_model_t* model)
{
    return model ? model->vocab_size : 0;
}

MG_RUNTIME_API uint32_t mg_model_eos_token_id(const mg_model_t* model)
{
    return model ? model->eos_id : 0;
}

MG_RUNTIME_API uint32_t mg_model_bos_token_id(const mg_model_t* model)
{
    return model ? model->bos_id : 0;
}

MG_RUNTIME_API size_t mg_model_max_seq_len(const mg_model_t* model)
{
    return model ? model->config.max_seq_len : 0;
}

MG_RUNTIME_API size_t mg_model_embedding_dim(const mg_model_t* model)
{
    return model ? model->embedding_dim : 0;
}

//=============================================================================
// Context lifecycle
//=============================================================================
MG_RUNTIME_API mg_error_t mg_context_create(
    mg_model_t* model,
    mg_context_t** out_context)
{
    if (!model || !out_context) return MG_ERROR_INVALID_ARGUMENT;
    *out_context = nullptr;

    try {
        mg_context_t* ctx = new mg_context_t();
        ctx->model = model;
        ctx->executor.reset(new IRExecutor(model->gguf_path, model->bos_id));
        if (!ctx->executor) {
            delete ctx;
            return MG_ERROR_OUT_OF_MEMORY;
        }
        *out_context = ctx;
        return MG_SUCCESS;
    } catch (...) {
        return MG_ERROR_OUT_OF_MEMORY;
    }
}

MG_RUNTIME_API void mg_context_free(mg_context_t* context)
{
    delete context;
}

MG_RUNTIME_API size_t mg_context_position(const mg_context_t* context)
{
    return context ? context->position : 0;
}

MG_RUNTIME_API void mg_context_reset(mg_context_t* context)
{
    if (!context) return;
    if (context->executor) context->executor->ResetPosition();
    context->position = 0;
    context->logits.clear();
    context->last_tokens.clear();
}

MG_RUNTIME_API const float* mg_context_logits(const mg_context_t* context, size_t* out_count)
{
    if (!context) return nullptr;
    if (out_count) *out_count = context->logits.size();
    return context->logits.empty() ? nullptr : context->logits.data();
}

MG_RUNTIME_API const char* mg_runtime_version(void)
{
    return "ModelGenieRuntime/1.0 (RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001)";
}

//=============================================================================
// Text <-> tokens
//=============================================================================
static const char* mg_token_text(const mg_model_t* model, uint32_t id)
{
    if (!model || !model->vocab) return nullptr;
    const std::string& s = model->vocab->Token(id);
    return s.empty() ? nullptr : s.c_str();
}

MG_RUNTIME_API mg_error_t mg_model_tokenize(
    mg_model_t* model,
    const char* text,
    uint32_t* out_tokens,
    size_t* in_out_count)
{
    if (!model || !text || !in_out_count) return MG_ERROR_INVALID_ARGUMENT;
    if (!model->vocab) return MG_ERROR_INVALID_STATE;

    std::vector<uint32_t> ids;
    if (!model->vocab->EncodeLongestMatch(text, ids)) {
        *in_out_count = 0;
        return MG_ERROR_INVALID_ARGUMENT;
    }

    if (!out_tokens || *in_out_count < ids.size()) {
        // Report the required capacity so the caller can size the buffer.
        *in_out_count = ids.size();
        return MG_ERROR_INVALID_ARGUMENT;
    }
    std::memcpy(out_tokens, ids.data(), ids.size() * sizeof(uint32_t));
    *in_out_count = ids.size();
    return MG_SUCCESS;
}

MG_RUNTIME_API bool mg_model_token_text(
    const mg_model_t* model,
    uint32_t token_id,
    char* out_buf,
    size_t out_buf_size)
{
    if (!out_buf || out_buf_size == 0) return false;
    out_buf[0] = '\0';
    const char* text = mg_token_text(model, token_id);
    if (!text) return false;
    const size_t len = std::strlen(text);
    if (len + 1 > out_buf_size) return false;
    std::memcpy(out_buf, text, len + 1);
    return true;
}

//=============================================================================
// Generation
//=============================================================================
MG_RUNTIME_API mg_error_t mg_context_generate(
    mg_context_t* context,
    const uint32_t* prompt_tokens,
    size_t prompt_token_count,
    const mg_generation_config_t* config,
    mg_token_callback_t callback,
    void* callback_user_data)
{
    if (!context || !context->executor || !prompt_tokens || !config) {
        return MG_ERROR_INVALID_ARGUMENT;
    }
    if (prompt_token_count == 0 || config->max_tokens == 0) {
        return MG_ERROR_INVALID_ARGUMENT;
    }

    std::vector<uint32_t> prompt(prompt_tokens, prompt_tokens + prompt_token_count);
    std::vector<uint32_t> produced = context->executor->Generate(
        prompt, static_cast<uint32_t>(config->max_tokens));
    if (produced.empty()) return MG_ERROR_EXECUTION_FAILED;

    const std::vector<float>* logits = context->executor->GetLogits();
    if (logits && !logits->empty()) {
        context->logits.assign(logits->begin(), logits->end());
    }
    context->position = context->executor->Position();
    context->last_tokens = produced;

    for (uint32_t id : produced) {
        if (!callback) break;
        if (!callback(id, mg_token_text(context->model, id), callback_user_data)) break;
    }
    return MG_SUCCESS;
}

//=============================================================================
// Production-runtime surface (introspection + one-step evaluation)
//=============================================================================
MG_RUNTIME_API mg_error_t mg_context_capture_tokens(
    mg_context_t* context,
    const uint32_t* prompt_tokens,
    size_t prompt_token_count,
    uint32_t max_tokens,
    uint32_t* out_tokens,
    size_t out_capacity,
    size_t* out_count)
{
    if (!context || !context->executor || !prompt_tokens || !out_count) {
        if (out_count) *out_count = 0;
        return MG_ERROR_INVALID_ARGUMENT;
    }
    if (prompt_token_count == 0 || max_tokens == 0) {
        *out_count = 0;
        return MG_ERROR_INVALID_ARGUMENT;
    }

    std::vector<uint32_t> prompt(prompt_tokens, prompt_tokens + prompt_token_count);
    std::vector<uint32_t> produced =
        context->executor->Generate(prompt, max_tokens);
    if (produced.empty()) {
        *out_count = 0;
        return MG_ERROR_EXECUTION_FAILED;
    }

    const std::vector<float>* logits = context->executor->GetLogits();
    if (logits && !logits->empty()) {
        context->logits.assign(logits->begin(), logits->end());
    }
    context->position = context->executor->Position();
    context->last_tokens = produced;

    *out_count = produced.size();
    if (out_tokens && out_capacity) {
        const size_t n = produced.size() < out_capacity ? produced.size() : out_capacity;
        std::memcpy(out_tokens, produced.data(), n * sizeof(uint32_t));
    }
    return MG_SUCCESS;
}

MG_RUNTIME_API mg_error_t mg_context_eval_buffer(
    mg_context_t* context,
    const uint32_t* prompt_tokens,
    size_t prompt_token_count,
    float* out_logits,
    size_t* in_out_count)
{
    if (!context || !context->executor || !prompt_tokens || !in_out_count) {
        return MG_ERROR_INVALID_ARGUMENT;
    }
    if (prompt_token_count == 0) return MG_ERROR_INVALID_ARGUMENT;

    std::vector<uint32_t> prompt(prompt_tokens, prompt_tokens + prompt_token_count);
    if (!context->executor->Prefill(prompt)) return MG_ERROR_EXECUTION_FAILED;

    const std::vector<float>* logits = context->executor->GetLogits();
    if (!logits || logits->empty()) return MG_ERROR_EXECUTION_FAILED;

    context->logits.assign(logits->begin(), logits->end());
    context->position = context->executor->Position();
    context->last_tokens.clear();
    context->last_tokens.push_back(context->executor->SampleToken());

    if (out_logits) {
        if (*in_out_count < logits->size()) {
            *in_out_count = logits->size();
            return MG_ERROR_INVALID_ARGUMENT;
        }
        std::memcpy(out_logits, logits->data(), logits->size() * sizeof(float));
    }
    *in_out_count = logits->size();
    return MG_SUCCESS;
}

MG_RUNTIME_API mg_error_t mg_context_generate_text(
    mg_context_t* context,
    const char* prompt_text,
    const mg_generation_config_t* config,
    mg_token_callback_t callback,
    void* callback_user_data)
{
    if (!context || !context->model || !prompt_text || !config) {
        return MG_ERROR_INVALID_ARGUMENT;
    }
    if (!context->model->vocab) return MG_ERROR_INVALID_STATE;

    std::vector<uint32_t> prompt;
    if (!context->model->vocab->EncodeLongestMatch(prompt_text, prompt) || prompt.empty()) {
        return MG_ERROR_INVALID_ARGUMENT;
    }

    std::vector<uint32_t> produced = context->executor->Generate(
        prompt, static_cast<uint32_t>(config->max_tokens));
    if (produced.empty()) return MG_ERROR_EXECUTION_FAILED;

    const std::vector<float>* logits = context->executor->GetLogits();
    if (logits && !logits->empty()) {
        context->logits.assign(logits->begin(), logits->end());
    }
    context->position = context->executor->Position();
    context->last_tokens = produced;

    for (uint32_t id : produced) {
        if (!callback) break;
        if (!callback(id, mg_token_text(context->model, id), callback_user_data)) break;
    }
    return MG_SUCCESS;
}

MG_RUNTIME_API mg_error_t mg_context_last_tokens(
    const mg_context_t* context,
    uint32_t* out_tokens,
    size_t out_capacity,
    size_t* out_count)
{
    if (!context || !out_count) return MG_ERROR_INVALID_ARGUMENT;
    *out_count = context->last_tokens.size();
    if (out_tokens && out_capacity) {
        const size_t n = context->last_tokens.size() < out_capacity
                             ? context->last_tokens.size()
                             : out_capacity;
        std::memcpy(out_tokens, context->last_tokens.data(), n * sizeof(uint32_t));
    }
    return MG_SUCCESS;
}

MG_RUNTIME_API size_t mg_context_token_count(const mg_context_t* context)
{
    return context ? context->last_tokens.size() : 0;
}

MG_RUNTIME_API uint32_t mg_context_ops_dispatched(const mg_context_t* context)
{
    return (context && context->executor) ? context->executor->Dispatched() : 0;
}

MG_RUNTIME_API uint32_t mg_context_ops_skipped(const mg_context_t* context)
{
    return (context && context->executor) ? context->executor->Skipped() : 0;
}

MG_RUNTIME_API uint32_t mg_context_ops_visited(const mg_context_t* context)
{
    return (context && context->executor) ? context->executor->Visited() : 0;
}

// Execute exactly one forward step and expose its logits. Kept so the DLL can
// prove one-token equivalence against the standalone harness.
MG_RUNTIME_API mg_error_t mg_context_eval(
    mg_context_t* context,
    uint32_t token_id,
    float* out_logits,
    size_t* in_out_logits)
{
    if (!context || !context->executor || !in_out_logits) return MG_ERROR_INVALID_ARGUMENT;

    context->executor->SetTokenId(token_id);
    context->executor->ClearArena();
    if (!context->executor->Execute()) return MG_ERROR_EXECUTION_FAILED;
    context->executor->AdvancePosition();

    const std::vector<float>* logits = context->executor->GetLogits();
    if (!logits || logits->empty()) return MG_ERROR_EXECUTION_FAILED;
    context->logits.assign(logits->begin(), logits->end());
    context->position = context->executor->Position();
    context->last_tokens.clear();
    context->last_tokens.push_back(context->executor->SampleToken());

    if (out_logits) {
        if (*in_out_logits < logits->size()) {
            *in_out_logits = logits->size();
            return MG_ERROR_INVALID_ARGUMENT;
        }
        std::memcpy(out_logits, logits->data(), logits->size() * sizeof(float));
    }
    *in_out_logits = logits->size();
    return MG_SUCCESS;
}

//=============================================================================
// Logging
//=============================================================================
static mg_log_callback_t g_log_callback = nullptr;
static void* g_log_user_data = nullptr;

MG_RUNTIME_API void mg_set_log_callback(mg_log_callback_t callback, void* user_data)
{
    g_log_callback = callback;
    g_log_user_data = user_data;
}

MG_RUNTIME_API void mg_set_log_level(mg_log_level_t) {}
