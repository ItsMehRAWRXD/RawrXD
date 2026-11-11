// SpeculativeOptimizer.h — Speculative Decoding (Batch 5 I04)
#pragma once

#include <string>

class SpeculativeOptimizer {
public:
    SpeculativeOptimizer();
    ~SpeculativeOptimizer();

    bool Enable();
    void Disable();
    bool IsEnabled() const;

private:
    bool enabled_ = false;
};
