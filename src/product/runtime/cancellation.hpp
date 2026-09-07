#pragma once
#include <atomic>
namespace rawr::product {

struct CancelToken {
    std::atomic<int> flag{0};
    void request() { flag.store(1, std::memory_order_release); }
    void clear() { flag.store(0, std::memory_order_release); }
    bool requested() const { return flag.load(std::memory_order_acquire) != 0; }
};

} // namespace rawr::product
