// LavaEdge.hpp — sole irreversible spend boundary
#pragma once
#include "LavapathTypes.hpp"
#include <cstdio>

namespace rawr::lavapath {

// BEFORE_LAVAPATH: allocations/transfers/submits = 0 fiction.
// LAVAPATH: minimum live need → one real op → measured receipt → last-use release.
inline Receipt LavaEdge(const Action& a) {
    Receipt r{};
    r.action = a.id;
    r.phase = a.phase;
    r.generation = 0;
    if (!a.execute) {
        r.success = false;
        return r;
    }
    std::fprintf(stderr, "LAVAPATH_ENTER id=%llu phase=%u\n",
                 (unsigned long long)a.id, (unsigned)a.phase);
    r.success = a.execute();
    std::fprintf(stderr, "LAVAPATH_RECEIPT id=%llu ok=%d\n",
                 (unsigned long long)a.id, (int)r.success);
    return r;
}

} // namespace rawr::lavapath
