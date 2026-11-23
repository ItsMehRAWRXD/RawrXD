#include "ShardPager.hpp"

#include <algorithm>
#include <cstring>
#include <thread>
#include <limits>

namespace deep2 {

PageCache::PageCache(std::size_t capacityBytes, std::size_t pageSize)
    : m_pageSize(pageSize == 0 ? 256 * 1024 : pageSize)
    // A cache must hold at least one complete page; smaller configured
    // budgets are rounded up rather than allowing every acquisition to exceed
    // capacity by an entire page.
    , m_capacityBytes(std::max(capacityBytes, m_pageSize)) {}

PageCache::~PageCache() {
    // Async prefetch workers capture this and may still insert pages. Join
    // them before clearing the index or destroying cache synchronization.
    {
        std::lock_guard<std::mutex> lock(m_prefetchMutex);
        for (auto& future : m_prefetchFutures) {
            if (future.valid()) {
                try { future.get(); } catch (...) {}
            }
        }
        m_prefetchFutures.clear();
    }
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
    m_residentBytes += m_pageSize;
    return true;
}

void PageCache::evictToFit(std::size_t neededBytes) {
    if (neededBytes > m_capacityBytes) return;
    while (m_residentBytes > m_capacityBytes - neededBytes && !m_lru.empty()) {
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

    // Reserve capacity before loadPage() increments residentBytes. Evicting
    // after loading and passing m_pageSize again double-counted the new page.
    evictToFit(m_pageSize);
    if (m_residentBytes > m_capacityBytes - m_pageSize) {
        // All resident pages are leased; fail closed rather than exceeding the
        // configured budget with another pinned allocation.
        delete page;
        return nullptr;
    }
    if (!loadPage(page)) {
        delete page;
        return nullptr;
    }

    m_lru.push_front(page);
    page->lruIt = m_lru.begin();
    m_index[key] = page;
    return page;
}

void PageCache::release(Page* page) {
    if (!page) return;
    // Serialize the transition to zero with eviction. Decrementing before
    // acquiring m_mutex allowed evictUnleasedRange() to delete the page in the
    // gap before touch(page), leaving release() with a dangling pointer.
    std::lock_guard<std::mutex> lock(m_mutex);
    const uint32_t prev = page->leaseCount.load(std::memory_order_acquire);
    if (prev == 0) return; // defensive: ignore a duplicate release
    page->leaseCount.fetch_sub(1, std::memory_order_acq_rel);
    if (prev == 1) touch(page);
}

bool PageCache::readRange(uint32_t shard, uint64_t offset, std::uint64_t size, std::uint8_t* out) {
    if (size == 0) return true;
    if (!out || size > std::numeric_limits<size_t>::max() ||
        offset > UINT64_MAX - (size - 1)) return false;

    // Acquire/copy/release one page at a time. Holding every page in a large
    // request simultaneously can exceed the configured pager budget because
    // leased pages are not evictable.
    uint64_t copied = 0;
    while (copied < size) {
        const uint64_t absolute = offset + copied;
        const uint64_t pageNo = absolute / m_pageSize;
        Page* page = acquire(shard, pageNo);
        if (!page) return false;
        const size_t pageOffset = static_cast<size_t>(absolute % m_pageSize);
        const uint64_t available = static_cast<uint64_t>(m_pageSize - pageOffset);
        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(size - copied, available));
        std::memcpy(out + static_cast<size_t>(copied), page->data.data() + pageOffset, chunk);
        release(page);
        copied += chunk;
    }
    return true;
}

void PageCache::prefetch(uint32_t shard, uint64_t offset, std::uint64_t size) {
    if (size == 0 || !m_reader || offset > UINT64_MAX - (size - 1)) return;
    const uint64_t firstPage64 = offset / m_pageSize;
    const uint64_t lastPage64 = (offset + size - 1) / m_pageSize;
    if (lastPage64 < firstPage64 ||
        lastPage64 - firstPage64 >= std::numeric_limits<size_t>::max()) return;
    const size_t firstPage = static_cast<size_t>(firstPage64);
    const size_t lastPage = static_cast<size_t>(lastPage64);

    auto work = [this, shard, firstPage, lastPage]() {
        // Reuse acquire/release so reads are serialized with the shard stream,
        // cache index, LRU and hard page-budget accounting.
        for (size_t p = firstPage; p <= lastPage; ++p) {
            Page* page = acquire(shard, static_cast<uint64_t>(p));
            if (page) release(page);
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

std::size_t PageCache::evictUnleasedRange(uint32_t shard, uint64_t offset, uint64_t size) {
    if (!size || offset > UINT64_MAX - (size - 1)) return 0;
    const uint64_t firstPage = offset / m_pageSize;
    const uint64_t lastPage = (offset + size - 1) / m_pageSize;
    std::lock_guard<std::mutex> lock(m_mutex);
    std::size_t evicted = 0;
    // Iterate resident pages, not every page in the tensor's (potentially
    // multi-terabyte) range. The page index is already bounded by the cache.
    for (auto it = m_index.begin(); it != m_index.end();) {
        Page* page = it->second;
        if (page->shard == shard && page->pageNo >= firstPage &&
            page->pageNo <= lastPage &&
            page->leaseCount.load(std::memory_order_acquire) == 0) {
            m_lru.erase(page->lruIt);
            m_residentBytes -= page->data.size();
            page->inCache = false;
            delete page;
            it = m_index.erase(it);
            ++evicted;
        } else {
            ++it;
        }
    }
    return evicted;
}

void PageCache::evictUnleasedAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_index.begin(); it != m_index.end();) {
        Page* page = it->second;
        if (page->leaseCount.load(std::memory_order_acquire) == 0) {
            m_lru.erase(page->lruIt);
            m_residentBytes -= page->data.size();
            page->inCache = false;
            delete page;
            it = m_index.erase(it);
        } else {
            ++it;
        }
    }
}

// ---------------- TensorLease ----------------

TensorLease::TensorLease(PageCache& cache, uint32_t shard, uint64_t offset, uint64_t size)
    : m_cache(&cache), m_shard(shard), m_offset(offset), m_size(size) {
    if (size == 0) { m_ok = true; return; }
    if (offset > UINT64_MAX - (size - 1)) return;
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

TensorLease::~TensorLease() {
    for (Page* pg : m_pages) m_cache->release(pg);
}

bool TensorLease::read(uint64_t relOffset, std::uint64_t size, std::uint8_t* out) const {
    if (!m_ok || size == 0) return true;
    if (relOffset > m_size || size > m_size - relOffset ||
        m_offset > UINT64_MAX - relOffset) return false;
    const uint64_t absOffset = m_offset + relOffset;
    return m_cache->readRange(m_shard, absOffset, size, out);
}

const std::uint8_t* TensorLease::direct(uint64_t relOffset, std::uint64_t size) const {
    if (!m_ok || size == 0 || relOffset > m_size || size > m_size - relOffset ||
        m_offset > UINT64_MAX - relOffset) return nullptr;
    if (m_pages.size() != 1) return nullptr;
    Page* pg = m_pages[0];
    const uint64_t pageBase = m_offset + relOffset;
    if (pageBase > UINT64_MAX - size) return nullptr;
    const uint64_t pageStart = pg->pageNo * m_cache->pageSize();
    const uint64_t pageEnd = pageStart + pg->data.size();
    if (pageBase < pageStart || pageBase + size > pageEnd) return nullptr;
    return pg->data.data() + (pageBase - pageStart);
}

} // namespace deep2
