// K2MLA_QPathDevice_Emit.cpp — counters + PATH_A exchange/mirror emit
#include "K2MLA_QPathDevice.hpp"
#include "K2MLA_PathB.hpp"
#include "../runtime/QbHostReadbackWindow.hpp"
#include "../runtime/QbExchangeLedger.hpp"
#include "../runtime/QbHostCrossLatencySplit.hpp"
#include "HostExchangeDiscover.hpp"
#include "ExchangeMirror.hpp"
#include <atomic>

namespace Deep2 {
namespace {
std::atomic<uint64_t> g_mlaQOps{0}, g_mlaQFail{0};
}
void MLA_QPathDevice_NoteOk() { g_mlaQOps.fetch_add(1); }
void MLA_QPathDevice_NoteFail() { g_mlaQFail.fetch_add(1); }
void MLA_QPathDevice_Reset() {
    g_mlaQOps = g_mlaQFail = 0;
    PathB_Reset();
    rawrxd::runtime::QbX_Reset();
    rawrxd::runtime::QbXC_Reset();
    HostXchg_Reset();
    ExchangeMirror::Reset();
}
uint64_t MLA_QPathDevice_Ops() { return g_mlaQOps.load(); }
uint64_t MLA_QPathDevice_Fail() { return g_mlaQFail.load(); }
void MLA_QPathDevice_Emit(FILE* f) {
    if (!f) return;
    fprintf(f, "MLA_Q_DEVICE_OPS=%llu MLA_Q_DEVICE_FAIL=%llu\n",
            (unsigned long long)g_mlaQOps.load(),
            (unsigned long long)g_mlaQFail.load());
    PathB_Emit(f);
    rawrxd::runtime::QbHostReadback_Emit(f);
    rawrxd::runtime::QbX_Emit(f);
    rawrxd::runtime::QbXC_Emit(f);
    HostXchg_Emit(f);
    ExchangeMirror::Emit(f);
}
} // namespace Deep2
