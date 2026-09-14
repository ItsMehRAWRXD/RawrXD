#pragma once
// Stub: ThreadPool (Deep2 namespace)
#include <vector>
#include <functional>
#include <future>
namespace Deep2 {
class ThreadPool {
public:
    explicit ThreadPool(size_t) {}
    template<class F, class... Args>
    auto enqueue(F&& f, Args&&... args) {
        return std::async(std::launch::deferred, std::forward<F>(f), std::forward<Args>(args)...);
    }
};
} // namespace Deep2
