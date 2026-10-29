#include "deep2/TensorResidencyCache.hpp"

#include <cstdio>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

int main() {
    namespace fs = std::filesystem;
    const fs::path path = fs::temp_directory_path() / "rawrxd_tensor_residency_budget_test.bin";
    {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file) {
            std::cerr << "RESIDENCY_BUDGET_TEMPFILE_FAIL\n";
            return 1;
        }
        file.seekp(256 * 1024 - 1);
        file.put('\0');
    }
    gguf_shard_cache::TensorResidencyCache::Config config;
    config.max_active = 8;
    config.max_resident_bytes = 128 * 1024;
    auto cache = std::make_unique<gguf_shard_cache::TensorResidencyCache>(config);
    if (!cache->register_shard(0, path.string())) {
        std::cerr << "RESIDENCY_BUDGET_REGISTER_FAIL\n";
        cache.reset();
        fs::remove(path);
        return 2;
    }

    // Keep the first view pinned. On Windows the first request includes its
    // allocation-granularity delta, so the second view must fail closed when
    // the exact mapped bytes exceed the configured budget.
    auto* first = cache->acquire(0, 1, 64 * 1024);
    if (!first || cache->resident_bytes() != first->map_len ||
        cache->resident_budget_bytes() != 128 * 1024) {
        std::cerr << "RESIDENCY_BUDGET_FIRST_ACQUIRE_FAIL\n";
        cache.reset();
        fs::remove(path);
        return 3;
    }
    auto* secondWhilePinned = cache->acquire(0, 64 * 1024, 64 * 1024);
    if (secondWhilePinned != nullptr) {
        std::cerr << "RESIDENCY_BUDGET_PINNED_OVERADMIT_FAIL\n";
        cache.reset();
        fs::remove(path);
        return 4;
    }

    cache->release(first);
    auto* second = cache->acquire(0, 64 * 1024, 64 * 1024);
    if (!second || cache->resident_bytes() > cache->resident_budget_bytes()) {
        std::cerr << "RESIDENCY_BUDGET_RECLAIM_FAIL\n";
        cache.reset();
        fs::remove(path);
        return 5;
    }

    cache->clear();
    cache.reset();
    fs::remove(path);
    std::cout << "TENSOR_RESIDENCY_BUDGET_TEST_PASS\n";
    return 0;
}
