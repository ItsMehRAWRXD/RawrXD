#include "native_resident_tensor_cache.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <vector>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "cache check failed at %d: %s\\n", __LINE__, #x); return 1; } } while (false)

static rawrxd::compression::ResidentTensorCache::Ptr make_tensor(
    const std::vector<std::uint8_t>& bytes, const char* path) {
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("cannot create cache fixture");
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        if (!out) throw std::runtime_error("cannot write cache fixture");
    }
    auto tensor = std::make_shared<rawrxd::compression::ResidentCompressedTensor>(4096);
    {
        rawrxd::compression::FileTensorReader reader(path, 0, bytes.size());
        tensor->load(reader);
    }
    std::remove(path);
    return tensor;
}

int main() {
    using rawrxd::compression::ResidentTensorCache;
    const char* pathA = "resident_tensor_cache_a.bin";
    const char* pathB = "resident_tensor_cache_b.bin";
    const std::vector<std::uint8_t> repeatedA(8192, 0x41);
    const std::vector<std::uint8_t> repeatedB(8192, 0x42);
    auto sourceA = make_tensor(repeatedA, pathA);
    auto sourceB = make_tensor(repeatedB, pathB);
    const auto bytesA = sourceA->resident_bytes();
    const auto bytesB = sourceB->resident_bytes();
    CHECK(bytesA > 0 && bytesB > 0);

    ResidentTensorCache cache(bytesA + bytesB);
    auto leaseA = cache.GetOrLoad("a", [&] { return sourceA; });
    CHECK(leaseA && cache.entry_count() == 1);
    CHECK(cache.resident_bytes() == bytesA);

    // Shrinking the budget cannot erase accounting while a request owns A.
    cache.SetBudget(0);
    CHECK(cache.entry_count() == 1);
    CHECK(cache.resident_bytes() == bytesA);

    // A second miss remains request-scoped when all cached bytes are leased.
    auto requestB = cache.GetOrLoad("b", [&] { return sourceB; });
    CHECK(requestB && requestB->size() == repeatedB.size());
    CHECK(cache.entry_count() == 1);
    CHECK(cache.resident_bytes() == bytesA);

    leaseA.reset();
    cache.SetBudget(bytesB);
    CHECK(cache.entry_count() == 0);
    CHECK(cache.resident_bytes() == 0);

    // Once capacity is available, B is admitted and remains accurately sized.
    cache.SetBudget(bytesB);
    auto cachedB = cache.GetOrLoad("b", [&] { return sourceB; });
    CHECK(cachedB);
    CHECK(cache.entry_count() == 1);
    CHECK(cache.resident_bytes() == bytesB);
    CHECK(cachedB->size() == repeatedB.size());

    cachedB.reset();
    requestB.reset();
    sourceA.reset();
    sourceB.reset();
    cache.Clear();
    CHECK(cache.entry_count() == 0);
    CHECK(cache.resident_bytes() == 0);

    std::puts("LEASE_AWARE_COMPRESSED_CACHE=PASS");
    return 0;
}
