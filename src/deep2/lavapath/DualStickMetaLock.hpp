#pragma once
/* DualStickMetaLock — serialize bundle/residency meta across stick threads. */
#include <mutex>

namespace Deep2 {

inline std::recursive_mutex& DualStickMetaMu() {
    static std::recursive_mutex m;
    return m;
}

} // namespace Deep2
