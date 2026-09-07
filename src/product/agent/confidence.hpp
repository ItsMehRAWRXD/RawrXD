#pragma once
#include <cstdint>
namespace rawr::product {

struct Confidence {
    int evidence = 0;
    int testsPass = 0;
    int compilePass = 0;
    int score() const {
        int s = evidence * 40 + testsPass * 30 + compilePass * 30;
        if (s > 100) s = 100;
        return s;
    }
    bool shippable() const { return score() >= 70 && evidence > 0; }
};

} // namespace rawr::product
