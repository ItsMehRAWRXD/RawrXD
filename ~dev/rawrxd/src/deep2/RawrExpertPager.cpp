#include "RawrExpertPager.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace Deep2 {
namespace {

struct PageKey {
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
    bool operator==(const PageKey& other) const noexcept {
        return offset == other.offset && length == other.length;
    }
};

struct PageKeyHash {
    std::size_t operator()(const PageKey& key) const noexcept {
        const auto a = std::hash<std::uint64_t>{}(key.offset);
        const auto b = std::hash<std::uint64_t>{}(key.length);
        return a ^ (b + static_cast<std::size_t>(0x9e3779b97f4a7c15ull) + (a << 6) + (a >> 2));
    }
};

struct Entry {
    std::shared_ptr<const std::vector<std::uint8_t>> bytes;
    std::uint64_t generation = 0;
    std::uint64_t lastUse = 0;
};

}

struct RawrExpertPager::Impl {
    Config config{};
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = nullptr;
    std::uint64_t fileSize = 0;
    std::unordered_map<PageKey, Entry, PageKeyHash> cache;
    std::unordered_map<std::uint64_t, ExpertPage> routePages;
    std::deque<ExpertPage> queue;
    std::unordered_map<PageKey, bool, PageKeyHash> queued;
    mutable std::mutex mutex;
    std::condition_variable wake;
    std::thread worker;
    bool stopping = false;
    std::uint64_t clock = 0;
    std::uint64_t generation = 0;
    Stats counters{};
    std::string error;

    ~Impl() { shutdown(); }

    void shutdown() noexcept {
        {
            std::lock_guard lock(mutex);
            stopping = true;
        }
        wake.notify_all();
        if (worker.joinable())
            worker.join();
        if (mapping)
            CloseHandle(mapping);
        if (file != INVALID_HANDLE_VALUE)
            CloseHandle(file);
        mapping = nullptr;
        file = INVALID_HANDLE_VALUE;
        cache.clear();
        queue.clear();
        queued.clear();
        routePages.clear();
    }

    static PageKey key(const ExpertPage& page) noexcept {
        return {page.fileOffset, page.byteLength};
    }

    bool rangeValid(const ExpertPage& page) const noexcept {
        return page.byteLength != 0 && page.fileOffset <= fileSize &&
               page.byteLength <= fileSize - page.fileOffset;
    }

    std::shared_ptr<const std::vector<std::uint8_t>> read(const ExpertPage& page) {
        if (!rangeValid(page)) {
            error = "expert page is outside the mapped file";
            return {};
        }
        auto result = std::make_shared<std::vector<std::uint8_t>>(
            static_cast<std::size_t>(page.byteLength));
        LARGE_INTEGER position{};
        position.QuadPart = static_cast<LONGLONG>(page.fileOffset);
        if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) {
            error = "SetFilePointerEx failed";
            return {};
        }
        std::size_t done = 0;
        while (done < result->size()) {
            const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(
                result->size() - done, 1u << 20));
            DWORD actual = 0;
            if (!ReadFile(file, result->data() + done, chunk, &actual, nullptr) || actual == 0) {
                error = "ReadFile failed while loading expert page";
                return {};
            }
            done += actual;
        }
        counters.bytesRead += result->size();
        return result;
    }

    void insert(const ExpertPage& page, std::shared_ptr<const std::vector<std::uint8_t>> bytes) {
        const PageKey pageKey = key(page);
        while (cache.size() >= config.capacityPages) {
            auto victim = cache.end();
            for (auto it = cache.begin(); it != cache.end(); ++it) {
                if (it->second.bytes.use_count() == 1 &&
                    (victim == cache.end() || it->second.lastUse < victim->second.lastUse))
                    victim = it;
            }
            if (victim == cache.end())
                break;
            cache.erase(victim);
            ++counters.evictions;
        }
        cache[pageKey] = Entry{std::move(bytes), ++generation, ++clock};
    }

    void loop() {
        for (;;) {
            ExpertPage page{};
            {
                std::unique_lock lock(mutex);
                wake.wait(lock, [&] { return stopping || !queue.empty(); });
                if (stopping && queue.empty())
                    return;
                page = queue.front();
                queue.pop_front();
                queued.erase(key(page));
            }
            std::lock_guard lock(mutex);
            const PageKey pageKey = key(page);
            if (cache.find(pageKey) != cache.end())
                continue;
            auto bytes = read(page);
            if (bytes)
                insert(page, std::move(bytes));
        }
    }
};

RawrExpertPager::RawrExpertPager() : impl_(std::make_unique<Impl>()) {}
RawrExpertPager::~RawrExpertPager() = default;

bool RawrExpertPager::open(const std::filesystem::path& path, Config config) {
    close();
    if (config.capacityPages == 0 || config.queueDepth == 0)
        return false;
    impl_->config = config;
    impl_->file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (impl_->file == INVALID_HANDLE_VALUE) {
        impl_->error = "CreateFileW failed";
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(impl_->file, &size) || size.QuadPart <= 0) {
        impl_->error = "GetFileSizeEx failed";
        close();
        return false;
    }
    impl_->fileSize = static_cast<std::uint64_t>(size.QuadPart);
    impl_->stopping = false;
    impl_->worker = std::thread([this] { impl_->loop(); });
    return true;
}

void RawrExpertPager::close() noexcept {
    if (impl_)
        impl_->shutdown();
}

bool RawrExpertPager::valid() const noexcept {
    return impl_ && impl_->file != INVALID_HANDLE_VALUE;
}

bool RawrExpertPager::registerPage(const ExpertPage& page) {
    if (!valid() || !impl_->rangeValid(page))
        return false;
    const std::uint64_t routeKey = (static_cast<std::uint64_t>(page.layer) << 32) | page.expert;
    std::lock_guard lock(impl_->mutex);
    impl_->routePages[routeKey] = page;
    return true;
}

bool RawrExpertPager::prefetch(const ExpertPage& page) {
    if (!valid() || !impl_->rangeValid(page))
        return false;
    const PageKey pageKey = Impl::key(page);
    std::lock_guard lock(impl_->mutex);
    ++impl_->counters.requests;
    if (impl_->cache.find(pageKey) != impl_->cache.end() || impl_->queued.count(pageKey))
        return true;
    if (impl_->queue.size() >= impl_->config.queueDepth)
        return false;
    impl_->queue.push_back(page);
    impl_->queued.emplace(pageKey, true);
    ++impl_->counters.queued;
    impl_->wake.notify_one();
    return true;
}

RawrExpertPager::Lease RawrExpertPager::acquire(const ExpertPage& page) {
    if (!valid() || !impl_->rangeValid(page))
        return {};
    const PageKey pageKey = Impl::key(page);
    std::lock_guard lock(impl_->mutex);
    ++impl_->counters.requests;
    auto it = impl_->cache.find(pageKey);
    if (it != impl_->cache.end()) {
        ++impl_->counters.hits;
        it->second.lastUse = ++impl_->clock;
        return {it->second.bytes, it->second.generation};
    }
    ++impl_->counters.misses;
    auto bytes = impl_->read(page);
    if (!bytes)
        return {};
    impl_->insert(page, bytes);
    const auto inserted = impl_->cache.find(pageKey);
    return inserted == impl_->cache.end() ? Lease{} : Lease{inserted->second.bytes, inserted->second.generation};
}

void RawrExpertPager::observeRoute(std::uint32_t layer, std::uint32_t expert) {
    if (!valid())
        return;
    std::vector<ExpertPage> candidates;
    {
        std::lock_guard lock(impl_->mutex);
        for (std::size_t distance = 0; distance <= impl_->config.prefetchDistance; ++distance) {
            const std::uint32_t candidateLayer = layer + static_cast<std::uint32_t>(distance);
            const std::uint64_t routeKey = (static_cast<std::uint64_t>(candidateLayer) << 32) | expert;
            const auto it = impl_->routePages.find(routeKey);
            if (it != impl_->routePages.end())
                candidates.push_back(it->second);
        }
    }
    for (const ExpertPage& page : candidates) {
        if (!prefetch(page))
            break;
    }
}

RawrExpertPager::Stats RawrExpertPager::stats() const noexcept {
    if (!impl_)
        return {};
    std::lock_guard lock(impl_->mutex);
    return impl_->counters;
}

std::string RawrExpertPager::lastError() const {
    if (!impl_)
        return "pager is not initialized";
    std::lock_guard lock(impl_->mutex);
    return impl_->error;
}

}
