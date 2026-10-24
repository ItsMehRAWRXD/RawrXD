#pragma once
#include <cstddef>
namespace rawrxd::deep2 {
inline bool expertFitsBudget(std::size_t used, std::size_t incoming,
                             std::size_t capacity) noexcept {
    return incoming != 0 && incoming <= capacity && used <= capacity - incoming;
}
}
