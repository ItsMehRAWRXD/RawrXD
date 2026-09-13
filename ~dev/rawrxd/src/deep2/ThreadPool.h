#pragma once
// Stub: ThreadPool
#include <thread>
#include <vector>
class ThreadPool {
public:
    explicit ThreadPool(size_t n = 1) {}
    template<typename F> void enqueue(F&&) {}
    size_t size() const { return 1; }
};
