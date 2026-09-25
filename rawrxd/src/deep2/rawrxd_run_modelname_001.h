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
