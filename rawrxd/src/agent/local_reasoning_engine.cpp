#include "local_reasoning_engine.hpp"

std::string LocalReasoningEngine::analyze(const AnalysisContext& ctx) {
    return "analysis_complete";
}

std::string LocalReasoningEngine::getStats() const {
    return "stats: ok";
}
