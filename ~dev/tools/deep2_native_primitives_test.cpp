#include "deep2/RawrExpertPager.hpp"
#include "deep2/RawrNativeCompiler.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cassert>
#include <atomic>
#include <exception>
#include <filesystem>
#include <fstream>
#include <thread>
#include <vector>

namespace {

extern "C" int __cdecl trampolineTarget() noexcept { return 41; }

}

int main() {
    const auto path = std::filesystem::temp_directory_path() / "rawrxd_native_primitives.bin";
    std::vector<unsigned char> fixture(3 * Deep2::RawrExpertPager::PageBytes, 0);
    for (std::size_t i = 0; i < Deep2::RawrExpertPager::PageBytes; ++i) {
        fixture[i] = 0x11;
        fixture[Deep2::RawrExpertPager::PageBytes + i] = 0x22;
        fixture[2 * Deep2::RawrExpertPager::PageBytes + i] = 0x33;
    }
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char*>(fixture.data()), static_cast<std::streamsize>(fixture.size()));
    }

    Deep2::RawrExpertPager pager;
    if (!pager.open(path, {.capacityPages = 2, .queueDepth = 4, .prefetchDistance = 1}))
        return 4;
    const Deep2::RawrExpertPager::ExpertPage page0{0, 0, 0, Deep2::RawrExpertPager::PageBytes};
    const Deep2::RawrExpertPager::ExpertPage page1{0, 1, Deep2::RawrExpertPager::PageBytes,
                                                   Deep2::RawrExpertPager::PageBytes};
    if (!pager.registerPage(page0) || !pager.registerPage(page1))
        return 5;
    const auto first = pager.acquire(page0);
    if (!first || first.bytes->front() != 0x11 || first.bytes->back() != 0x11)
        return 6;
    if (!pager.prefetch(page1))
        return 7;
    Sleep(25);
    const auto second = pager.acquire(page1);
    if (!second || second.bytes->front() != 0x22 || second.bytes->back() != 0x22)
        return 8;

    std::vector<std::thread> readers;
    std::atomic<bool> concurrentFailure{false};
    for (int i = 0; i < 8; ++i) {
        readers.emplace_back([&pager, &concurrentFailure, page0, page1] {
            for (int iteration = 0; iteration < 16; ++iteration) {
                const auto page = (iteration & 1) ? page0 : page1;
                const auto lease = pager.acquire(page);
                if (!lease || lease.bytes->size() != Deep2::RawrExpertPager::PageBytes)
                    concurrentFailure.store(true);
            }
        });
    }
    for (auto& reader : readers)
        reader.join();
    if (concurrentFailure.load())
        return 3;

    const auto stats = pager.stats();
    if (stats.bytesRead < 2 * Deep2::RawrExpertPager::PageBytes || stats.hits == 0)
        return 9;
    pager.close();

    Deep2::RawrNativeTrampoline trampoline;
    if (trampoline.compileJump(nullptr))
        return 10;
    if (!trampoline.compileJump(reinterpret_cast<void*>(&trampolineTarget)))
        return 1;
    const auto function = reinterpret_cast<int(__cdecl*)()>(trampoline.entry());
    if (function() != 41)
        return 2;
    trampoline.reset();
    std::error_code error;
    std::filesystem::remove(path, error);
    return 0;
}
