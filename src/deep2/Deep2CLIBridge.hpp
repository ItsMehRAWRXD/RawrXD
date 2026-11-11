#pragma once
// Deep2CLIBridge.hpp — Minimal C interface to Deep2Engine for CLI use.
// Avoids pulling Deep2Engine.h (with its many heavy dependencies) into
// rawrxd_cli_v2.cpp. Implemented in Deep2CLIBridge.cpp which is compiled
// as part of deep2_engine_lib (where all includes resolve).

#include <string>
#include <cstdint>

struct Deep2EngineHandle;  // opaque

// Load a GGUF model into a new Deep2Engine instance.
// Returns nullptr on failure.
extern "C" Deep2EngineHandle* deep2_load_model(const char* ggufPath);

// Generate text from a loaded model. Returns false on failure.
extern "C" bool deep2_generate(Deep2EngineHandle* engine,
                               const char* prompt,
                               size_t maxTokens,
                               std::string& outText);

// Token streaming bridge used by the native CLI.  The callback returns false
// to cancel generation.  The bridge keeps the engine opaque to CLI callers.
using Deep2TokenCallback = bool (*)(int32_t tokenId, const char* text,
                                    size_t textBytes, void* user);
extern "C" bool deep2_generate_stream(Deep2EngineHandle* engine,
                                       const char* prompt,
                                       size_t maxTokens,
                                       Deep2TokenCallback callback,
                                       void* user,
                                       std::string& outText);

// Format a single chat turn using the loaded model's GGUF metadata.  This is
// intentionally kept in the opaque bridge so callers cannot accidentally
// apply a template from a different model family.
extern "C" bool deep2_format_chat_prompt(Deep2EngineHandle* engine,
                                          const char* systemPrompt,
                                          const char* userPrompt,
                                          std::string& outPrompt);

// Describe a generation that produced no visible text.  A zero-token result
// is a failure; an EOS token may legitimately produce an empty text payload.
extern "C" uint32_t deep2_generation_stop_reason(Deep2EngineHandle* engine);
extern "C" const char* deep2_generation_stop_reason_name(Deep2EngineHandle* engine);
extern "C" uint64_t deep2_generation_token_count(Deep2EngineHandle* engine);

// Free a Deep2Engine instance.
extern "C" void deep2_free(Deep2EngineHandle* engine);

// Get model dimensions for CLI reporting.
extern "C" unsigned deep2_hidden_dim(Deep2EngineHandle* engine);
extern "C" unsigned deep2_vocab_size(Deep2EngineHandle* engine);
extern "C" size_t deep2_num_layers(Deep2EngineHandle* engine);
