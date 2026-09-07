#pragma once
#include "../rawr_evidence_writer.hpp"
namespace rawr {
inline void ToolWriteEvidenceSeal(const char* gate, const char* verdict) {
    SealEvidence("G:\\~dev\\rawrxd\\evidence\\RAWRXD_AGENTIC_CLI_001", gate,
                 verdict);
}
} // namespace rawr
