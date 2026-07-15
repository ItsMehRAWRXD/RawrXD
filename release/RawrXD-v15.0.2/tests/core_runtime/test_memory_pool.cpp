// Core Runtime Test - Memory Pool
// Minimal test for memory pool functionality

#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/memory_pool.h"
#include <cstdio>

bool test_memory_pool() {
    printf("[TEST] Memory Pool...\n");
    RawrXD::Core::MemoryPool pool;
    bool result = pool.Initialize(1024 * 1024);
    printf("[PASS] Memory Pool\n");
    return result;
}
