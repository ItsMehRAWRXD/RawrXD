#include "static_analysis_engine.hpp"

namespace StaticAnalysisEngine {

StaticAnalysisEngine& StaticAnalysisEngine::instance() {
    static StaticAnalysisEngine inst;
    return inst;
}

std::vector<uint32_t> StaticAnalysisEngine::getAllFunctions() {
    return {};
}

const void* StaticAnalysisEngine::getCFG(uint32_t funcId) {
    (void)funcId;
    return nullptr;
}

} // namespace StaticAnalysisEngine
