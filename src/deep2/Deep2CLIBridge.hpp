#pragma once
// Deep2CLIBridge.hpp — Minimal C interface to Deep2Engine for CLI use.
// Avoids pulling Deep2Engine.h (with its many heavy dependencies) into
// rawrxd_cli_v2.cpp. Implemented in Deep2CLIBridge.cpp which is compiled
// as part of deep2_engine_lib (where all includes resolve).

#include <string>

struct Deep2EngineHandle;  // opaque

// Load a GGUF model into a new Deep2Engine instance.
// Returns nullptr on failure.
extern "C" Deep2EngineHandle* deep2_load_model(const char* ggufPath);

// Generate text from a loaded model. Returns false on failure.
extern "C" bool deep2_generate(Deep2EngineHandle* engine,
                               const char* prompt,
                               size_t maxTokens,
                               std::string& outText);

// Free a Deep2Engine instance.
extern "C" void deep2_free(Deep2EngineHandle* engine);

// Get model dimensions for CLI reporting.
extern "C" unsigned deep2_hidden_dim(Deep2EngineHandle* engine);
extern "C" unsigned deep2_vocab_size(Deep2EngineHandle* engine);
extern "C" size_t deep2_num_layers(Deep2EngineHandle* engine);
