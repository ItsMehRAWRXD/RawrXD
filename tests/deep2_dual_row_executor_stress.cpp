// Exercises the exact dependency-free executor used by Deep2's dual-GPU path.
#include "../~dev/rawrxd/src/deep2/Deep2DualRowExecutor.hpp"
#include <atomic>
#include <cassert>
#include <thread>
#include <vector>

struct JobContext {
    std::atomic<unsigned>* counter;
    unsigned token;
    bool fail;
};

static bool runJob(void* p) noexcept {
    auto* ctx = static_cast<JobContext*>(p);
    if (!ctx || ctx->token == 0) return false;
    ctx->counter->fetch_add(1, std::memory_order_relaxed);
    // Encourage overlap between independent submitting threads.
    std::this_thread::yield();
    return !ctx->fail;
}

int main() {
    constexpr unsigned callers = 8, repetitions = 100;
    std::atomic<unsigned> lane0{0}, lane1{0}, completed{0}, failures{0};
    std::vector<std::thread> submitters;
    for (unsigned caller = 0; caller < callers; ++caller) {
        submitters.emplace_back([&, caller] {
            for (unsigned n = 0; n < repetitions; ++n) {
                JobContext a{&lane0, caller * repetitions + n + 1, false};
                JobContext b{&lane1, caller * repetitions + n + 1, false};
                if (Deep2::rowExecutor().run({runJob, &a}, {runJob, &b}))
                    completed.fetch_add(1, std::memory_order_relaxed);
                else failures.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& thread : submitters) thread.join();
    assert(failures.load() == 0);
    assert(completed.load() == callers * repetitions);
    assert(lane0.load() == callers * repetitions);
    assert(lane1.load() == callers * repetitions);

    // Explicitly verify the executor returns failure if either GPU lane fails.
    JobContext ok{&lane0, 1, false}, fail{&lane1, 1, true};
    assert(!Deep2::rowExecutor().run({runJob, &ok}, {runJob, &fail}));
    return 0;
}
