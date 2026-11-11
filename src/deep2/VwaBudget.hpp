#pragma once

namespace Deep2 {

struct VwaBudget {
    unsigned __int64 ramBytes = 0;
    unsigned __int64 vramBytes = 0;
    unsigned __int64 outstandingIoBytes = 0;
    unsigned long maxOutstandingReads = 0;
};

struct VwaBudgetPeak {
    unsigned __int64 ramBytes = 0;
    unsigned __int64 vramBytes = 0;
    unsigned __int64 outstandingIoBytes = 0;
    unsigned long outstandingReads = 0;
};

struct VwaBudgetVerdict {
    unsigned long ramOk = 0;
    unsigned long vramOk = 0;
    unsigned long ioBytesOk = 0;
    unsigned long ioReadsOk = 0;
    unsigned long pass = 0;
};

inline VwaBudgetVerdict VwaValidateBudget(const VwaBudget& b,
                                          const VwaBudgetPeak& p) noexcept {
    VwaBudgetVerdict v{};
    v.ramOk = (b.ramBytes != 0 && p.ramBytes <= b.ramBytes) ? 1u : 0u;
    v.vramOk = (b.vramBytes != 0 && p.vramBytes <= b.vramBytes) ? 1u : 0u;
    v.ioBytesOk = (b.outstandingIoBytes != 0 &&
                   p.outstandingIoBytes <= b.outstandingIoBytes) ? 1u : 0u;
    v.ioReadsOk = (b.maxOutstandingReads != 0 &&
                   p.outstandingReads <= b.maxOutstandingReads) ? 1u : 0u;
    v.pass = (v.ramOk && v.vramOk && v.ioBytesOk && v.ioReadsOk) ? 1u : 0u;
    return v;
}

} // namespace Deep2
