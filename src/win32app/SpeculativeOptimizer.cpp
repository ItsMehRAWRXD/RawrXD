// SpeculativeOptimizer.cpp — Speculative Decoding (Batch 5 I04)
#include "SpeculativeOptimizer.h"

SpeculativeOptimizer::SpeculativeOptimizer() {}
SpeculativeOptimizer::~SpeculativeOptimizer() {}

bool SpeculativeOptimizer::Enable() {
    enabled_ = true;
    return true;
}

void SpeculativeOptimizer::Disable() {
    enabled_ = false;
}

bool SpeculativeOptimizer::IsEnabled() const {
    return enabled_;
}
