#include "utc_provider.h"
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include <atomic>
#include <cstdio>

static void must(bool value, const char* what) {
    if (!value) { std::fprintf(stderr, "FAIL: %s\n", what); std::abort(); }
}

int main() {
    must(utc::EventCount() == 0, "initial count");
    char source[] = "stack-owned event";
    char detail[] = "stack-owned detail";
    must(utc::LogEvent(source, detail) == 1, "first event sequence");
    source[0] = 'X'; detail[0] = 'X';
    utc::EventRecord check[utc::kRingCapacity]{};
    must(utc::RecentEvents(check, utc::kRingCapacity) == 1, "readback first event");
    must(std::strcmp(check[0].event.data(), "stack-owned event") == 0, "event ownership");
    must(std::strcmp(check[0].detail.data(), "stack-owned detail") == 0, "detail ownership");
    must(check[0].tick > 0, "timestamp");
    must(utc::ReadCounter(nullptr) == 0, "null counter");
    utc::g_Counter_Inference.store(17);
    must(utc::ReadCounter(&utc::g_Counter_Inference) == 17, "atomic counter read");

    std::vector<std::thread> threads;
    constexpr std::size_t kThreads = 8;
    constexpr std::size_t kPerThread = 1000;
    for (std::size_t t = 0; t < kThreads; ++t) {
        threads.emplace_back([t]() {
            for (std::size_t i = 0; i < kPerThread; ++i) {
                char name[64];
                std::snprintf(name, sizeof(name), "T%zu-%zu", t, i);
                must(utc::LogEvent(name, "ok") != 0, "concurrent append");
            }
        });
    }
    for (auto& thread : threads) thread.join();
    const auto count = utc::EventCount();
    must(count == 1 + kThreads * kPerThread, "concurrent count");
    must(utc::RecentEvents(check, utc::kRingCapacity) == utc::kRingCapacity,
         "bounded ring readback");
    const auto first = count - utc::kRingCapacity + 1;
    for (std::size_t i = 0; i < utc::kRingCapacity; ++i) {
        must(check[i].sequence == first + i, "ordered wraparound");
        must(check[i].tick != 0, "timestamp after wraparound");
        must(check[i].event[0] == 'T', "stable owned event text");
    }
    must(utc::RecentEvents(nullptr, 10) == 0, "null output");
    std::puts("UTC_PROVIDER_CERT PASS: threads=8 events=8001 ring=256 no-stubs");
    return 0;
}
