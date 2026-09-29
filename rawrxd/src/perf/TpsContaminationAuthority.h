// TpsContaminationAuthority.h — RAWRXD_TPS_CONTAMINATION_AUTHORITY_001
// Names the "dangerous for TPS/perf" part directly.
// Separates debug-contaminated TPS from clean baseline TPS.
#pragma once
#include <string>
#include <cstdint>

namespace rawrxd { namespace perf {

void markDebugSpam();
void markFullLogitsScan();
void markPerTokenFlush();
void markPerTokenStderr();
bool isBaselineValid();
void writeContaminationReceipt(const std::string& path);

}} // namespace rawrxd::perf