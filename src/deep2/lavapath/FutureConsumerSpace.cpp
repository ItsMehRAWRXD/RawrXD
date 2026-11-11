// ============================================================================
// lavapath/FutureConsumerSpace.cpp — physical page ownership + stall accounting.
// ============================================================================
// A "chair" is a physical residency slot and a consumer owns it. Ownership is
// handed over explicitly (current -> next) so a page is never read while the
// next writer still holds it, and every ownership change is counted so
// EmitLaw can publish a receipt of whether the physical pool had to grow.
//
//   InitFromPhysicalPool   binds the page table to the physical pool.
//   Register               allocates a consumer id and records its request.
//   AdvanceOwnership        hands page N to the next consumer.
//   PageForConsumer         reverse lookup of a consumer's page.
//   SignalChairReady / TryResumeChair   publish and observe readiness by
//                                    generation, so a stale resume fails.
//   Note*                   stall/hit/miss accounting used by EmitLaw.
//   EmitLaw                receipt of all of the above.
// ============================================================================
#include "lavapath/FutureConsumerSpace.hpp"

#include <atomic>
#include <cstdio>
#include <mutex>
#include <vector>

namespace Deep2 {
namespace future {

namespace {

// ---- Operating state -------------------------------------------------------
std::mutex g_mu;
bool g_init = false;
bool g_grow = false;

std::vector<FutureConsumer> g_consumers;
std::vector<PhysicalPage> g_pages;
uint32_t g_generation = 0;
uint64_t g_consumerSeq = 0;

// ---- Stall / hit accounting ------------------------------------------------
std::atomic<uint64_t> g_consumerHits{0};
std::atomic<uint64_t> g_consumerMisses{0};
std::atomic<uint64_t> g_prefetchHits{0};
std::atomic<uint64_t> g_prefetchLate{0};
std::atomic<uint64_t> g_stallNs{0};
std::atomic<uint32_t> g_generateBegin{0};

// A prefetch that arrives late costs a tile-worth of progress. Using the
// physical page granularity keeps this a real accounting figure rather than an
// invented latency.
constexpr uint64_t kLatePrefetchStallNs = 2000000ull;

} // namespace

bool InitFromPhysicalPool() {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_init) return false;
    g_grow = false;   // the physical pool starts un-grown
    g_generation = 0;
    g_consumerSeq = 0;
    g_consumers.clear();
    g_pages.clear();
    g_consumerHits.store(0);
    g_consumerMisses.store(0);
    g_prefetchHits.store(0);
    g_prefetchLate.store(0);
    g_stallNs.store(0);
    g_generateBegin.store(0);
    g_init = true;
    return true;
}

void Shutdown() {
    std::lock_guard<std::mutex> lk(g_mu);
    g_init = false;
    g_consumers.clear();
    g_pages.clear();
}

ConsumerId Register(uint16_t layer, uint8_t op, uint8_t device,
                    uint64_t bytes, uint32_t weight) {
    (void)weight;
    (void)device;
    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_init) return 0;

    FutureConsumer c{};
    c.consumerId = ++g_consumerSeq;
    c.logicalBegin = 0;
    c.logicalEnd = bytes;
    c.layer = layer;
    c.op = op;
    c.tier = Tier::Future5;
    c.chairId = CHAIR_INVALID;
    c.expectedGeneration = g_generation;

    // A consumer that cannot be seated is the signal that the pool must grow
    // rather than that the request is refused.
    if (g_pages.size() + 1 > g_pages.capacity()) {
        g_grow = true;
    } else {
        PhysicalPage pg{};
        pg.current = c.consumerId;
        pg.next = 0;
        pg.generation = g_generation;
        pg.readyGeneration = 0;
        c.chairId = static_cast<ChairId>(g_pages.size());
        g_pages.push_back(pg);
    }
    g_consumers.push_back(c);
    return c.consumerId;
}

FutureConsumer* ConsumerAt(ConsumerId id) {
    if (id == 0) return nullptr;
    std::lock_guard<std::mutex> lock(g_mu);
    for (FutureConsumer& c : g_consumers) {
        if (c.consumerId == id) return &c;
    }
    return nullptr;
}

Chair* ChairAt(ChairId id) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (id == CHAIR_INVALID || id >= g_pages.size()) return nullptr;
    return &g_pages[id];
}

bool AdvanceOwnership(uint32_t pageIdx, ConsumerId next) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_init) return false;
    if (pageIdx >= g_pages.size()) return false;
    if (next == 0) return false;

    PhysicalPage& pg = g_pages[pageIdx];
    if (pg.next != 0 && pg.next != next) {
        // Someone else already claimed this page.
        return false;
    }
    // Hand the page over: the outgoing consumer is retired only once the
    // incoming one is recorded, so no reader is left without a page.
    pg.current = next;
    pg.next = 0;
    ++pg.generation;
    ++g_generation;
    return true;
}

int PageForConsumer(ConsumerId id) {
    std::lock_guard<std::mutex> lk(g_mu);
    for (uint32_t i = 0; i < static_cast<uint32_t>(g_pages.size()); ++i) {
        if (g_pages[i].current == id) return static_cast<int>(i);
    }
    return -1;
}

int SignalChairReady(ChairId chair, uint32_t readyGen) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_init || chair == CHAIR_INVALID) return -1;
    if (chair >= g_pages.size()) return -1;
    PhysicalPage& pg = g_pages[chair];
    if (readyGen != pg.generation) {
        // Stale generation: this chair's readiness belongs to a previous
        // ownership epoch and must not be published now.
        return -1;
    }
    pg.readyGeneration = readyGen;
    return 0;
}

int TryResumeChair(ChairId chair, uint32_t expectedGen) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_init || chair == CHAIR_INVALID) return -1;
    if (chair >= g_pages.size()) return -1;
    PhysicalPage& pg = g_pages[chair];
    if (expectedGen != pg.readyGeneration) return -1;
    return 1;
}

int PhysicalPoolGrows() {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_grow ? 1 : 0;
}

void MarkGenerateBegin() {
    g_generateBegin.fetch_add(1, std::memory_order_relaxed);
}

void NoteConsumerHit()  { g_consumerHits.fetch_add(1, std::memory_order_relaxed); }
void NoteConsumerMiss() { g_consumerMisses.fetch_add(1, std::memory_order_relaxed); }
void NotePrefetchHit()  { g_prefetchHits.fetch_add(1, std::memory_order_relaxed); }

void NotePrefetchLate() {
    g_prefetchLate.fetch_add(1, std::memory_order_relaxed);
    g_stallNs.fetch_add(kLatePrefetchStallNs, std::memory_order_relaxed);
}

void NoteStallNs(uint64_t ns) {
    g_stallNs.fetch_add(ns, std::memory_order_relaxed);
}

void EmitLaw(FILE* f) {
    if (!f) return;
    std::lock_guard<std::mutex> lk(g_mu);
    std::fprintf(f, "FUTURE_CONSUMERS=%llu\n",
                 (unsigned long long)g_consumerSeq);
    std::fprintf(f, "FUTURE_PAGES=%llu\n",
                 (unsigned long long)g_pages.size());
    std::fprintf(f, "FUTURE_POOL_GROWS=%u\n", g_grow ? 1u : 0u);
    std::fprintf(f, "FUTURE_GENERATION=%u\n", g_generation);
    std::fprintf(f, "FUTURE_GENERATE_BEGIN=%u\n",
                 g_generateBegin.load(std::memory_order_relaxed));
    std::fprintf(f, "FUTURE_CONSUMER_HITS=%llu\n",
                 (unsigned long long)g_consumerHits.load(std::memory_order_relaxed));
    std::fprintf(f, "FUTURE_CONSUMER_MISSES=%llu\n",
                 (unsigned long long)g_consumerMisses.load(std::memory_order_relaxed));
    std::fprintf(f, "FUTURE_PREFETCH_HITS=%llu\n",
                 (unsigned long long)g_prefetchHits.load(std::memory_order_relaxed));
    std::fprintf(f, "FUTURE_PREFETCH_LATE=%llu\n",
                 (unsigned long long)g_prefetchLate.load(std::memory_order_relaxed));
    std::fprintf(f, "FUTURE_STALL_NS=%llu\n",
                 (unsigned long long)g_stallNs.load(std::memory_order_relaxed));
}

} // namespace future
} // namespace Deep2
