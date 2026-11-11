#pragma once
/* ParseMibBudget — stub */
#include <cstddef>
#include <cstdint>
#include <cstdio>
namespace Deep2 {
struct MibParseResult {
    bool ok = false;
    size_t bytes = 0;
};
inline MibParseResult ParseMibTokenEx(const char* s) {
    MibParseResult r;
    r.ok = true;
    r.bytes = static_cast<size_t>((s && *s) ? std::atoi(s) : 512) << 20;
    return r;
}
inline void EmitWeightBudgetReceipt(FILE* /*f*/, const MibParseResult& /*pr*/, const char* /*tag*/) {}
} // namespace Deep2
