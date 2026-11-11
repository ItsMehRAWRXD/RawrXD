#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace Deep2 {

class RawrExpertPager {
public:
    static constexpr std::size_t PageBytes = 64u * 1024u;

    struct Config {
        std::size_t capacityPages = 256;
        std::size_t queueDepth = 128;
        std::size_t prefetchDistance = 2;
    };

    struct ExpertPage {
        std::uint32_t layer = 0;
        std::uint32_t expert = 0;
        std::uint64_t fileOffset = 0;
        std::uint64_t byteLength = 0;
    };

    struct Lease {
        std::shared_ptr<const std::vector<std::uint8_t>> bytes;
        std::uint64_t generation = 0;
        explicit operator bool() const noexcept { return static_cast<bool>(bytes); }
    };

    struct Stats {
        std::uint64_t requests = 0;
        std::uint64_t hits = 0;
        std::uint64_t misses = 0;
        std::uint64_t queued = 0;
        std::uint64_t evictions = 0;
        std::uint64_t bytesRead = 0;
    };

    RawrExpertPager();
    ~RawrExpertPager();
    RawrExpertPager(const RawrExpertPager&) = delete;
    RawrExpertPager& operator=(const RawrExpertPager&) = delete;

    bool open(const std::filesystem::path& path, Config config = {});
    void close() noexcept;
    bool valid() const noexcept;
    bool registerPage(const ExpertPage& page);
    bool prefetch(const ExpertPage& page);
    Lease acquire(const ExpertPage& page);
    void observeRoute(std::uint32_t layer, std::uint32_t expert);
    Stats stats() const noexcept;
    std::string lastError() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
