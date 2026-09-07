#pragma once
#include "failure_class.hpp"
#include <cstdint>
namespace rawr::product {

struct RetryPolicy {
    int maxTries = 3;
    int tries = 0;
    FailKind last = FailKind::None;

    bool again(FailKind k) {
        last = k;
        tries++;
        if (k == FailKind::Denied || k == FailKind::Hallucinate) return false;
        return tries < maxTries && k != FailKind::None;
    }
};

} // namespace rawr::product
