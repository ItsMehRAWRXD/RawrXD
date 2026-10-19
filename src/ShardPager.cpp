#include "ShardPager.hpp"

#include <algorithm>
#include <cstring>
#include <thread>

namespace deep2 {

PageCache::PageCache(std::size_t capacityBytes, std::size_t pageSize)
    : m_pageSize(pageSize == 0 ? 256 * 1024 : pageSize)
    , m_capacityBytes(capacityBytes) {}

PageCache::~PageCache() {
    // Join the prefetch workers before the cache comes down. A prefetch
    // worker inserts into m_index and m_lru, so letting one run into the
    // destructor would touch pages that are being freed.
    {
        std::lock_guard<std::mutex> plock(m_prefetchMutex);
        for (auto& f : m_prefetchFutures) {
            if (f.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                f.get();
            } else {
                f.wait();
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
    // The resident-byte accounting is done by the caller, under m_mutex, so
    // that the storage read itself can happen outside the cache lock.
    return true;
}

    void PageCache::evictToFit(std::size_t neededBytes) {
      // The page currently being inserted must survive the eviction, or the
      // caller would be handed a pointer to a page that was just deleted.
      while (m_residentBytes + neededBytes > m_capacityBytes && !m_lru.empty()) {
          // Find the least-recently-used page that is not leased. Leased pages
          // are rotated to the front and skipped; a page is only removed from
          // the list when it is the one being evicted, so the iterator stays
          // valid.
          Page* victim = nullptr;
          std::size_t scanned = 0;
          const std::size_t total = m_lru.size();
          while (scanned < total) {
              Page* candidate = m_lru.back();
              m_lru.pop_back();
              if (candidate != m_protected && candidate->leaseCount.load(std::memory_order_acquire) == 0) {
                  victim = candidate;
                  break;
              }
              // Leased, or the page being inserted: rotate it to the front and
              // keep looking.
              m_lru.push_front(candidate);
              candidate->lruIt = m_lru.begin();
              ++scanned;
          }
          if (!victim) break;   // everything resident is leased; nothing to evict
  
          m_index.erase(makeKey(victim->shard, victim->pageNo));
          m_residentBytes -= victim->data.size();
          victim->inCache = false;
          victim->data.clear();
          delete victim;
      }
  }


Page* PageCache::insertResident(Page* fresh, bool takeLease) {
    Key key = makeKey(fresh->shard, fresh->pageNo);
    auto it = m_index.find(key);
    if (it != m_index.end()) {
        // Another thread inserted the same page while this one was being
        // read. The resident copy is the one to use; ours is redundant.
        Page* existing = it->second;
        if (takeLease) {
            existing->leaseCount.fetch_add(1, std::memory_order_release);
        }
        touch(existing);
        delete fresh;
        return existing;
    }

    m_residentBytes += fresh->data.size();
    m_lru.push_front(fresh);
    fresh->lruIt = m_lru.begin();
    m_index[key] = fresh;
    // The page just inserted must not be the one the eviction scan
    // removes, or the pointer returned here would be dangling.
    m_protected = fresh;
    evictToFit(0);
    m_protected = nullptr;
    return fresh;
}

Page* PageCache::acquire(uint32_t shard, uint64_t pageNo) {
    Key key = makeKey(shard, pageNo);

    // Fast path: the page is already resident.
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_index.find(key);
        if (it != m_index.end()) {
            Page* page = it->second;
            page->leaseCount.fetch_add(1, std::memory_order_release);
            touch(page);
            return page;
        }
    }

    // Slow path: read the page from storage outside the cache lock.
    //
    // Holding m_mutex across the read would serialise every demand load in
    // the process behind one disk read, and would block the prefetch thread
    // from inserting the pages it has already fetched. The read is the slow
    // part, so it happens with the lock released.
    //
    // pageNo is an opaque page index; fileOffset = pageNo * pageSize is the
    // default mapping, and the reader callback is responsible for translating
    // it to a shard base if it needs to. TensorROM's reader treats pageNo as
    // an absolute file page number, so the absolute file offset is
    // pageNo * pageSize.
    Page* fresh = new Page();
    fresh->shard = shard;
    fresh->pageNo = pageNo;
    fresh->fileOffset = pageNo * m_pageSize;
    fresh->leaseCount.store(1, std::memory_order_release);

    if (!loadPage(fresh)) {
        delete fresh;
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    return insertResident(fresh, true);
}

void PageCache::release(Page* page) {
    if (!page) return;
    // The decrement has to happen under the cache lock.
    //
    // If it happened outside it, evictToFit could observe a lease count of
    // zero, evict the page and delete it, and this function would then touch
    // the freed page's LRU iterator.
    std::lock_guard<std::mutex> lock(m_mutex);
    const uint32_t prev = page->leaseCount.fetch_sub(1, std::memory_order_acq_rel);
    if (prev <= 1) {
        // Last lease dropped: page remains resident (cached) but is now evictable.
        touch(page);
    }
}

bool PageCache::readRange(uint32_t shard, uint64_t offset, std::uint64_t size, std::uint8_t* out) {
    if (size == 0) return true;
    std::size_t firstPage = static_cast<std::size_t>(offset / m_pageSize);
    std::size_t lastPage = static_cast<std::size_t>((offset + size - 1) / m_pageSize);
    std::vector<Page*> held;
    held.reserve(lastPage - firstPage + 1);
    for (std::size_t p = firstPage; p <= lastPage; ++p) {
        Page* pg = acquire(shard, static_cast<uint64_t>(p));
        if (!pg) {
            for (Page* rel : held) release(rel);
            return false;
        }
        held.push_back(pg);
    }
    std::uint64_t copied = 0;
    while (copied < size) {
        std::size_t p = static_cast<std::size_t>((offset + copied) / m_pageSize);
        Page* pg = held[p - firstPage];
        std::size_t pageRel = static_cast<std::size_t>((offset + copied) % m_pageSize);
        std::size_t avail = m_pageSize - pageRel;
        std::size_t chunk = (std::size_t)(size - copied) < avail ? (std::size_t)(size - copied) : avail;
        std::memcpy(out + copied, pg->data.data() + pageRel, chunk);
        copied += chunk;
    }
    for (Page* rel : held) release(rel);
    return true;
}

void PageCache::prefetch(uint32_t shard, uint64_t offset, std::uint64_t size) {
    if (size == 0 || !m_reader) return;
    std::size_t firstPage = static_cast<std::size_t>(offset / m_pageSize);
    std::size_t lastPage = static_cast<std::size_t>((offset + size - 1) / m_pageSize);

    auto work = [this, shard, firstPage, lastPage]() {
        // Throttle concurrency by joining the oldest futures opportunistically.
        for (std::size_t p = firstPage; p <= lastPage; ++p) {
            // Skip pages that are already resident. Reading them again would
            // cost a disk read and then be thrown away by the insert.
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_index.find(makeKey(shard, static_cast<std::uint64_t>(p))) != m_index.end()) {
                    continue;
                }
            }

            // The read happens with no cache lock held, so a prefetch and a
            // demand load can be in flight on the same shard at the same
            // time. The reader callback is responsible for serialising its
            // own access to the shard's file.
            Page* fresh = new Page();
            fresh->shard = shard;
            fresh->pageNo = static_cast<std::uint64_t>(p);
            fresh->fileOffset = fresh->pageNo * m_pageSize;
            fresh->leaseCount.store(0, std::memory_order_release);
            if (!loadPage(fresh)) {
                delete fresh;
                continue;
            }

            std::lock_guard<std::mutex> lock(m_mutex);
            insertResident(fresh, false);
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
    // Skip the leased pages instead of stopping at the first one, so a single
    // live lease does not stop the rest of the cache from being reclaimed.
    std::size_t scanned = 0;
    const std::size_t total = m_lru.size();
    while (!m_lru.empty() && scanned < total) {
        Page* victim = m_lru.back();
        m_lru.pop_back();
        if (victim->leaseCount.load(std::memory_order_acquire) > 0) {
            m_lru.push_front(victim);
            victim->lruIt = m_lru.begin();
            ++scanned;
            continue;
        }
        m_index.erase(makeKey(victim->shard, victim->pageNo));
        m_residentBytes -= victim->data.size();
        delete victim;
    }
}

// ---------------- TensorLease ----------------

TensorLease::TensorLease(PageCache& cache, uint32_t shard, uint64_t offset, uint64_t size)
    : m_cache(&cache), m_shard(shard), m_offset(offset), m_size(size) {
    if (size == 0) { m_ok = true; return; }
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
    if (relOffset + size > m_size) return false;
    uint64_t absOffset = m_offset + relOffset;
    return m_cache->readRange(m_shard, absOffset, size, out);
}

const std::uint8_t* TensorLease::direct(uint64_t relOffset, std::uint64_t size) const {
    if (!m_ok || size == 0 || relOffset + size > m_size) return nullptr;
    if (m_pages.size() != 1) return nullptr;
    Page* pg = m_pages[0];
    uint64_t pageBase = m_offset + relOffset;
    uint64_t pageStart = pg->pageNo * m_cache->pageSize();
    uint64_t pageEnd = pageStart + pg->data.size();
    if (pageBase < pageStart || pageBase + size > pageEnd) return nullptr;
    return pg->data.data() + (pageBase - pageStart);
}

} // namespace deep2
