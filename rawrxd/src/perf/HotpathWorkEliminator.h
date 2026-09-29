// HotpathWorkEliminator.h — RAWRXD_HOTPATH_WORK_ELIMINATOR_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace hotpath {
void recordAllocation();
void recordMemcpy(uint64_t bytes);
void recordUpload(uint64_t bytes);
void recordFlush();
void recordFullScan();
void writeHotpathReceipt(const std::string& path);
}} // namespace rawrxd::hotpath