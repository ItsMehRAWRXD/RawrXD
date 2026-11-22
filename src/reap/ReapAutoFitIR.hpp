#pragma once

#include <cstdint>
#include <string>

namespace RawrXD::Reap {

struct AutoFitTensorIR {
    std::string logicalPath;
    std::string physicalKey;
    std::string storageDtype;
    std::string scaleGranularity = "UNKNOWN";
    uint64_t sizeBytes = 0;
    uint64_t visitMultiplier = 1;
    bool prunable = false;
    bool recurrent = false;
};

struct AutoFitAggregateIR {
    static constexpr const char* kSchema = "rawrxd.reap.autofit.ir.v1";
    std::string architecture;
    uint64_t tensorCount = 0;
    uint64_t physicalParameterCount = 0;
    uint64_t logicalParameterCount = 0;
    uint64_t prunableExpertBytes = 0;
    uint64_t nonPrunableBytes = 0;
    uint64_t recurrentPhysicalLayers = 0;
    uint64_t recurrentVisitMultiplier = 1;
};

} // namespace RawrXD::Reap
