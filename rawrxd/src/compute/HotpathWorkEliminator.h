// HotpathWorkEliminator.h — RAWRXD_HOTPATH_WORK_ELIMINATOR_001
// Counts wasteful hot-path operations (allocs, memcpys, memsets,
// uploads, full-cache flushes/scans) that should be eliminated from
// the steady-state inference loop. Any non-zero count is a FAIL.
#pragma once
#include <cstddef>
#include <string>

namespace rawrxd { namespace hotpath {

void recordAlloc(size_t bytes);
void recordMemcpy(size_t bytes);
void recordMemset(size_t bytes);
void recordUpload(size_t bytes);
void recordFlush();
void recordFullScan(size_t count);

void writeHotpathReceipt(const std::string& path);

}} // namespace rawrxd::hotpath