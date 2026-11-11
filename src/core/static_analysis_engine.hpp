#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace StaticAnalysisEngine {

class StaticAnalysisEngine {
public:
    static StaticAnalysisEngine& instance();

    std::vector<uint32_t> getAllFunctions();
    const void* getCFG(uint32_t funcId);
};

} // namespace StaticAnalysisEngine
