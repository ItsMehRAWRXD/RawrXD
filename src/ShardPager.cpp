#include "ShardPager.hpp"

#include <algorithm>
#include <cstring>
#include <thread>

namespace deep2 {

PageCache::PageCache(std::size_t capacityBytes, std::size_t pageSize)
    : m_pageSize(pageSize == 0 ? 256 * 1024 : pageSize)
    , m_capacityBytes(capacityBytes) {}

PageCache::~PageCache() {
    { std::lock_guard<std::mutex> lock(m_prefetchMutex); m_prefetchFutures.clear(); }
    evictUnleasedAll();
}

void PageCache::setReader(Reader reader) { m_reader = std::move(reader); }

void PageCache::touch(Page* page) {
    m_lru.erase(page->lruIt);
    m_lru.push_front(page);
    page->lruIt = m_lru.begin();
}

bool PageCache::loadPage(Page* page) {
    if (!m_reader) return false;
    page->data.assign(m_pageSize, 0);
    bool ok = m_reader(page->shard, page->pageNo, page->data.data(), m_pageSize);
    if (!ok) {
        page->data.clear();
        return false;
    }
    return true;
}

void PageCache::evictToFit(std::size_t neededBytes) {
    while (m_residentBytes + neededBytes > m_capacityBytes && !m_lru.empty()) {
        Page* victim = m_lru.back();
        if (victim->leaseCount.load(std::memory_order_acquire) > 0) {
            // Leased pages cannot be evicted: rotate them to the front so we make
            // progress toward unleased candidates. Must refresh the stored iterator.
            m_lru.pop_back();
            m_lru.push_front(victim);
            victim->lruIt = m_lru.begin();
            bool allLeased = true;
            for (auto* p : m_lru) {
                if (p->leaseCount.load(std::memory_order_acquire) == 0) { allLeased = false; break; }
            }
            if (allLeased) break;
            continue;
        }
        m_lru.pop_back();
        m_index.erase(makeKey(victim->shard, victim->pageNo));
        m_residentBytes -= victim->data.size();
        victim->inCache = false;
        victim->data.clear();
        delete victim;
    }
}

Page* PageCache::acquire(uint32_t shard, uint64_t pageNo) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (pageNo > 0xFFFFFFFFull || m_pageSize > m_capacityBytes) return nullptr;
    Key key = makeKey(shard, pageNo);
    auto it = m_index.find(key);
    if (it != m_index.end()) {
        Page* page = it->second;
        page->leaseCount.fetch_add(1, std::memory_order_release);
        touch(page);
        return page;
    }

    // We need to compute fileOffset here: pageNo is relative to shard data section,
    // but the reader callback receives absolute file offsets. The caller (TensorROM)
    // passes pageNo relative to data section... To keep this layer generic, the reader
    // callback is responsible for translating; here pageNo is stored and fileOffset
    // is filled by loadPage through the reader? We need fileOffset before reading.
    // Simplest: caller computes absolute file offset and stores it... Page.fileOffset
    // is set by TensorROM when creating pages via a custom path. Instead, compute here
    // requires dataOffset knowledge. Store dataOffset per shard outside? Keep simple:
    // pageNo IS the absolute page index into the file for the reader when reader uses
    // TensorROM's helper (fileOffset = shardDataOffset + pageNo*pageSize). To honor that,
    // TensorROM wraps acquire with absolute offset computation. But PageCache.acquire
    // signature only takes pageNo. Set fileOffset = pageNo * pageSize here and let the
    // reader callback add the shard data base (closure captures ROM). Convention:
    // PageCache.pageNo is an opaque page index; fileOffset = pageNo * pageSize is the
    // default mapping, overridden by readers that need shard bases.
    Page* page = new Page();
    page->shard = shard;
    page->pageNo = pageNo;
    page->fileOffset = pageNo * m_pageSize;
    page->leaseCount.store(1, std::memory_order_release);

    if (!loadPage(page)) {
        delete page;
        return nullptr;
    }

    evictToFit(m_pageSize);
    if (m_residentBytes > m_capacityBytes || m_pageSize > m_capacityBytes - m_residentBytes) {
        delete page;
        return nullptr;
    }
    m_residentBytes += m_pageSize;

    m_lru.push_front(page);
    page->lruIt = m_lru.begin();
    m_index[key] = page;
    return page;
}

void PageCache::release(Page* page) {
    if (!page) return;
    // Synchronize the final unpin with eviction and acquisition.
    std::lock_guard<std::mutex> lock(m_mutex);
    const uint32_t count = page->leaseCount.load(std::memory_order_relaxed);
    if (count == 0) return;
    page->leaseCount.store(count - 1, std::memory_order_release);
    if (count == 1 && page->inCache) touch(page);
}

bool PageCache::readRange(uint32_t shard, uint64_t offset, std::uint64_t size, std::uint8_t* out) {
    if (size == 0) return true;
    if (!out || offset > UINT64_MAX - size) return false;
    // Hold one page at a time: a tensor can exceed the entire RAM cache budget.
    // The caller's output is the only full-range allocation.
    std::uint64_t copied = 0;
    while (copied < size) {
        const std::uint64_t absolute = offset + copied;
        const std::uint64_t pageNo = absolute / m_pageSize;
        const std::size_t within = static_cast<std::size_t>(absolute % m_pageSize);
        const std::size_t take = static_cast<std::size_t>(
            std::min<std::uint64_t>(size - copied, m_pageSize - within));
        Page* page = acquire(shard, pageNo);
        if (!page) return false;
        std::memcpy(out + copied, page->data.data() + within, take);
        release(page);
        copied += take;
    }
    return true;
}

void PageCache::prefetch(uint32_t shard, uint64_t offset, std::uint64_t size) {
    if (size == 0 || !m_reader || offset > UINT64_MAX - size) return;
    std::size_t firstPage = static_cast<std::size_t>(offset / m_pageSize);
    std::size_t lastPage = static_cast<std::size_t>((offset + size - 1) / m_pageSize);

    auto work = [this, shard, firstPage, lastPage]() {
        // Throttle concurrency by joining the oldest futures opportunistically.
        for (std::size_t p = firstPage; p <= lastPage; ++p) {
            Page tmp; // not inserted; just issue the read into a scratch page
            tmp.shard = shard;
            tmp.pageNo = static_cast<uint64_t>(p);
            tmp.fileOffset = tmp.pageNo * m_pageSize;
            tmp.data.assign(m_pageSize, 0);
            if (m_reader(shard, tmp.pageNo, tmp.data.data(), m_pageSize)) {
                std::lock_guard<std::mutex> lock(m_mutex);
                Key key = makeKey(shard, static_cast<uint64_t>(p));
                auto it = m_index.find(key);
                if (it != m_index.end()) {
                    // Already resident: refresh not needed; keep existing.
                    m_residentBytes += 0;
                } else {
                    Page* page = new Page();
                    page->shard = shard;
                    page->pageNo = tmp.pageNo;
                    page->fileOffset = tmp.fileOffset;
                    page->data = std::move(tmp.data);
                    evictToFit(m_pageSize);
                    if (m_residentBytes > m_capacityBytes || m_pageSize > m_capacityBytes - m_residentBytes) {
                        delete page;
                        continue;
                    }
                    m_residentBytes += m_pageSize;
                    m_lru.push_front(page);
                    page->lruIt = m_lru.begin();
                    m_index[key] = page;
                    evictToFit(0);
                }
            }
        }
    };

    {
        std::lock_guard<std::mutex> plock(m_prefetchMutex);
        // Drop completed futures.
        std::vector<std::future<void>> live;
        live.reserve(m_prefetchFutures.size());
        for (auto& f : m_prefetchFutures) {
            if (f.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                f.get();
            } else {
                live.push_back(std::move(f));
            }
        }
        m_prefetchFutures = std::move(live);
        if (static_cast<int>(m_prefetchFutures.size()) < kMaxConcurrentPrefetch) {
            m_prefetchFutures.emplace_back(std::async(std::launch::async, std::move(work)));
        }
    }
}

std::size_t PageCache::pageCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_index.size();
}

std::size_t PageCache::leaseCount() const {
    std::size_t total = 0;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& kv : m_index) total += kv.second->leaseCount.load(std::memory_order_acquire);
    return total;
}

void PageCache::evictUnleasedAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_lru.begin(); it != m_lru.end();) {
        Page* victim = *it;
        if (victim->leaseCount.load(std::memory_order_acquire) != 0) { ++it; continue; }
        it = m_lru.erase(it);
        m_index.erase(makeKey(victim->shard, victim->pageNo));
        m_residentBytes -= victim->data.size();
        delete victim;
    }
}

// ---------------- TensorLease ----------------

TensorLease::TensorLease(PageCache& cache, uint32_t shard, uint64_t offset, uint64_t size)
    : m_cache(&cache), m_shard(shard), m_offset(offset), m_size(size) {
    if (size == 0) { m_ok = true; return; }
    if (offset > UINT64_MAX - size) return;
    uint64_t firstPage = offset / m_cache->pageSize();
    uint64_t lastPage = (offset + size - 1) / m_cache->pageSize();
    for (uint64_t p = firstPage; p <= lastPage; ++p) {
        Page* pg = m_cache->acquire(shard, p);
        if (!pg) {
            for (Page* rel : m_pages) m_cache->release(rel);
            m_pages.clear();
            return;
        }
        m_pages.push_back(pg);
    }
    m_ok = true;
}

TensorLease::TensorLease(TensorLease&& other) noexcept
    : m_cache(other.m_cache), m_shard(other.m_shard),
      m_offset(other.m_offset), m_size(other.m_size),
      m_pages(std::move(other.m_pages)), m_ok(other.m_ok) {
    other.m_pages.clear();
    other.m_cache = nullptr;
    other.m_ok = false;
}

TensorLease& TensorLease::operator=(TensorLease&& other) noexcept {
    if (this == &other) return *this;
    if (m_cache) for (Page* pg : m_pages) m_cache->release(pg);
    m_cache = other.m_cache;
    m_shard = other.m_shard;
    m_offset = other.m_offset;
    m_size = other.m_size;
    m_pages = std::move(other.m_pages);
    m_ok = other.m_ok;
    other.m_pages.clear();
    other.m_cache = nullptr;
    other.m_ok = false;
    return *this;
}

TensorLease::~TensorLease() {
    for (Page* pg : m_pages) m_cache->release(pg);
}

bool TensorLease::read(uint64_t relOffset, std::uint64_t size, std::uint8_t* out) const {
    if (!m_ok || relOffset > m_size || size > m_size - relOffset || (!out && size)) return false;
    if (size == 0) return true;
    uint64_t absOffset = m_offset + relOffset;
    return m_cache->readRange(m_shard, absOffset, size, out);
}

const std::uint8_t* TensorLease::direct(uint64_t relOffset, std::uint64_t size) const {
    if (!m_ok || size == 0 || relOffset > m_size || size > m_size - relOffset) return nullptr;
    if (m_pages.size() != 1) return nullptr;
    Page* pg = m_pages[0];
    uint64_t pageBase = m_offset + relOffset;
    uint64_t pageStart = pg->pageNo * m_cache->pageSize();
    uint64_t pageEnd = pageStart + pg->data.size();
    if (pageBase < pageStart || pageBase + size > pageEnd) return nullptr;
    return pg->data.data() + (pageBase - pageStart);
}

} // namespace deep2
