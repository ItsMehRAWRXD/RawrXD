#pragma once
#include <cstdint>

// rawrxd_run_modelname_001.h
// Entry point: resolve model by name or path, load through Deep2Engine,
// stream tokens to stdout, emit receipt to stderr.
//
// Returns 0 on success, non-zero on failure.
int rawrxd_run_modelname_001(const char* modelNameOrPath,
                              const char* prompt,
                              uint32_t    maxTokens,
                              bool        vulkanEnabled,
                              bool        strictVulkan = false);

// Enumerate every selectable model: Ollama store models, local .gguf files in
// the search directories, and aliases. Prints to stdout. Returns 0 on success.
int rawrxd_list_models_001();
