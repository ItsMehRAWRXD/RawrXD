#include "../~dev/rawrxd/src/generation/module2_cancel.h"
#include <atomic>
#include <cassert>
#include <chrono>
#include <thread>
#include <type_traits>
#include <vector>

int main() {
    static_assert(!std::is_copy_constructible<CancelSource>::value, "Source must not be copied");
    static_assert(!std::is_move_constructible<CancelSource>::value, "Source must not be moved");
    // Immediate predicate and default token are safe.
    CancelToken empty;
    assert(!empty.stopPossible());
    assert(empty.waitFor([] { return true; }));

    // A cancel wakes *all* waiters, even when they were about to sleep.
    for (int iteration = 0; iteration < 400; ++iteration) {
        CancelSource source;
        CancelToken token = source.getToken();
        assert(token.stopPossible() && !token.stopRequested());
        std::atomic<int> finished{0};
        std::vector<std::thread> workers;
        for (int j = 0; j < 3; ++j) {
            workers.emplace_back([&]() {
                const bool completed = token.waitFor([] { return false; });
                assert(!completed);
                ++finished;
            });
        }
        assert(source.requestStop());
        assert(!source.requestStop());
        for (auto& t : workers) t.join();
        assert(finished.load() == 3);
    }
    // A predicate changing without a source notification must not hang.
    {
        CancelSource source;
        std::atomic<bool> finished{false};
        std::atomic<bool> allowed{false};
        std::atomic<int> checks{0};
        std::thread waiter([&]() {
            const bool ok = source.getToken().waitFor([&] {
                ++checks;
                return allowed.load();
            });
            assert(ok);
            finished = true;
        });
        // Ensure at least one false predicate read happened before changing it.
        while (checks.load() == 0) std::this_thread::yield();
        allowed = true;
        waiter.join();
        assert(finished);
        assert(!source.stopRequested());
    }
    // New request B is independent of cancellation of request A.
    {
        CancelSource requestA;
        CancelToken tokenA = requestA.getToken();
        assert(requestA.requestStop() && tokenA.stopRequested());
        CancelSource requestB;
        assert(!requestB.getToken().stopRequested());
        assert(requestB.getToken().waitFor([] { return true; }));
    }
}
