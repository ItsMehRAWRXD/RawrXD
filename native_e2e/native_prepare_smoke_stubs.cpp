// native_prepare_smoke_stubs.cpp — ABI stubs for prepare smoke (no MASM)
#include "rawr_native_e2e_abi.h"
#include <string.h>

extern "C" uint64_t __cdecl RawrNative_ModelBridgeCapabilities(void) {
    return 1;
}

extern "C" uint32_t __cdecl RawrNative_ModelBridgeResolveProfile(
    const char*, RawrNativeProfileInfo*) {
    return 1;
}

extern "C" uint32_t __cdecl RawrNative_NormalizePolicy(
    const RawrNativeProfileInfo* profile,
    const RawrNativePolicyRequest* request,
    RawrNativePolicy* out_policy)
{
    if (!profile || !request || !out_policy) return 1;
    memset(out_policy, 0, sizeof(*out_policy));
    out_policy->context = request->context ? request->context
                                           : profile->context_default;
    out_policy->max_tokens = request->max_tokens ? request->max_tokens
                                                 : profile->max_tokens;
    out_policy->temperature_milli = request->temperature_milli;
    out_policy->top_p_milli = request->top_p_milli;
    out_policy->top_k = request->top_k;
    out_policy->stream = request->stream;
    if (request->safe_enabled)
        out_policy->flags |= RN_POLICY_SAFE_PREPARED;
    if (request->hop_enabled)
        out_policy->flags |= RN_POLICY_HOP_PREPARED;
    return 0;
}

static uint64_t g_rid = 1;

extern "C" uint64_t __cdecl RawrNative_ReceiptBegin(
    uint32_t, uint32_t, uint32_t) {
    return ++g_rid;
}

extern "C" void __cdecl RawrNative_ReceiptEngineEnter(
    uint64_t, uint32_t, uint32_t) {}
extern "C" void __cdecl RawrNative_ReceiptFirstToken(uint64_t) {}
extern "C" void __cdecl RawrNative_ReceiptComplete(
    uint64_t, uint64_t, int32_t) {}
extern "C" uint32_t __cdecl RawrNative_ReceiptGet(
    uint64_t, RawrNativeReceipt*) { return 1; }
extern "C" uint64_t __cdecl RawrNative_ReceiptLatestId(void) {
    return g_rid;
}
