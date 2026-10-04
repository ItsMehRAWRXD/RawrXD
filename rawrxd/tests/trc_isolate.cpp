#include "TensorResidencyCache.hpp"
#include <cstdio>
int main() {
    try {
        Deep2::TensorResidencyCache cache(2);
        int a=1, b=2, c=3;
        cache.insert(Deep2::makeView(1, 1, &a, 4, 1));
        cache.insert(Deep2::makeView(1, 2, &b, 4, 1));
        cache.insert(Deep2::makeView(1, 3, &c, 4, 1));
        std::printf("size=%zu\n", cache.size());
    } catch (const std::exception& e) {
        std::printf("EXCEPTION: %s\n", e.what());
        return 1;
    }
    return 0;
}
