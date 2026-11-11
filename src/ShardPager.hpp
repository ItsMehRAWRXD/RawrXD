#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <list>
#include <mutex>
#include <atomic>
#include <functional>
#include <future>
#include <utility>

namespace deep2 {

// A single page of weight storage resident in RAM, backed by one shard file.
// Pages are fixed size and keyed by (shard, pageNo within shard data section).
struct Page {
    uint32_t shard = 0;
    uint64_t pageNo = 0;
    uint64_t fileOffset = 0;   // absolute offset in the shard file
    std::vector<std::uint8_t> data;
    std::atomic<uint32_t> leaseCount{0};
    bool inCache = true;
    std::list<Page*>::iterator lruIt;
};

// Bounded, LRU paged weight store for the TensorROM.
// - Capacity is a hard byte budget (default a few GiB; configurable).
// - Pages are leased (pinned) while a tensor is in use; only unleased pages are evicted.
// - Reads may span multiple pages; copies are assembled page by page.
// - Prefetch is fire-and-forget asynchronous I/O.
class PageCache {
public:
    using Reader = std::function<bool(uint32_t shard, uint64_t fileOffset,
                                      std::uint8_t* buf, std::size_t size)>;

    PageCache(std::size_t capacityBytes, std::size_t pageSize = 256 * 1024);
    ~PageCache();

    PageCache(const PageCache&) = delete;
    PageCache& operator=(const PageCache&) = delete;

    // Supply storage read callback: read `size` bytes at shard file offset `fileOffset` into `buf`.
    void setReader(Reader reader);

    // Pin a page in cache, issuing a storage read if it is not resident.
    // Evicts least-recently-used unleased pages to respect the capacity budget.
    Page* acquire(uint32_t shard, uint64_t pageNo);

    // Release one lease on a page. Unleased pages become eviction candidates.
    void release(Page* page);

    // Read [offset, offset+size) bytes of shard data section into caller buffer.
    // Spans page boundaries automatically. Pages are acquired/released around the copy.
    bool readRange(uint32_t shard, uint64_t offset, std::uint64_t size, std::uint8_t* out);

    // Fire-and-forget asynchronous prefetch of a data range (bounded concurrency).
    void prefetch(uint32_t shard, uint64_t offset, std::uint64_t size);

    std::size_t capacityBytes() const { return m_capacityBytes; }
    std::size_t pageSize() const { return m_pageSize; }
    std::size_t residentBytes() const { return m_residentBytes; }
    std::size_t pageCount() const;
    std::size_t leaseCount() const;

    // Evict every unleased page (useful between layer groups).
    void evictUnleasedAll();

private:
    using Key = std::uint64_t;
    static Key makeKey(uint32_t shard, uint64_t pageNo) {
        return (static_cast<Key>(shard) << 32) | (pageNo & 0xFFFFFFFFull);
    }

    void touch(Page* page);              // move to front of LRU
    bool loadPage(Page* page);
    void evictToFit(std::size_t neededBytes);

    std::size_t m_pageSize;
    std::size_t m_capacityBytes;
    std::size_t m_residentBytes = 0;

    mutable std::mutex m_mutex;
    std::list<Page*> m_lru;              // front = most recently used
    std::unordered_map<Key, Page*> m_index;

    Reader m_reader;

    // Bounded async prefetch
    std::mutex m_prefetchMutex;
    std::vector<std::future<void>> m_prefetchFutures;
    static constexpr int kMaxConcurrentPrefetch = 2;
};

// RAII lease over one tensor's byte range inside a shard.
// All pages covering [offset, offset+size) are pinned for the lease lifetime.
class TensorLease {
public:
    TensorLease() = default;
    TensorLease(PageCache& cache, uint32_t shard, uint64_t offset, uint64_t size);
    ~TensorLease();

    TensorLease(const TensorLease&) = delete;
    TensorLease& operator=(const TensorLease&) = delete;
    TensorLease(TensorLease&& other) noexcept = default;
    TensorLease& operator=(TensorLease&& other) noexcept = default;

    explicit operator bool() const { return m_ok; }
    uint32_t shard() const { return m_shard; }
    uint64_t offset() const { return m_offset; }
    uint64_t size() const { return m_size; }

    // Copy [relOffset, relOffset+size) from resident pages into `out`.
    bool read(uint64_t relOffset, std::uint64_t size, std::uint8_t* out) const;

    // Direct pointer into resident storage for a single-page contiguous range, else nullptr.
    const std::uint8_t* direct(uint64_t relOffset, std::uint64_t size) const;

private:
    PageCache* m_cache;   // not owned; must outlive the lease
    uint32_t m_shard = 0;
    uint64_t m_offset = 0;
    uint64_t m_size = 0;
    std::vector<Page*> m_pages;
    bool m_ok = false;
};

} // namespace deep2
