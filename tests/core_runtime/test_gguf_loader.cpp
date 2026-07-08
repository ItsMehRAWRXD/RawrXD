// Core Runtime Test - GGUF Loader
// Minimal test for GGUF loader functionality

#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/gguf_loader.h"
#include <cstdio>

bool test_gguf_loader() {
    printf("[TEST] GGUF Loader...\n");
    RawrXD::Core::GGUFLoader loader;
    bool result = loader.Load("test.gguf");
    printf("[PASS] GGUF Loader\n");
    return result;
}
