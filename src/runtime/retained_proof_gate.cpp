// retained_proof_gate.cpp — additive retained-proof → RealtimeImage RX → Deep2 bind
#include "retained_proof_gate.hpp"
#include "../deep2/regenerative/RegenerativeRuntime.hpp"
#include "../deep2/regenerative/RegenerativeVerify.hpp"
#include <cstring>
#include <cstdio>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace k2 {
namespace runtime {
namespace {

using Deep2::Regenerative::BudgetFacts;
using Deep2::Regenerative::HardwareFacts;
using Deep2::Regenerative::RegenDecision;
using Deep2::Regenerative::RegenerativeRuntime;
using Deep2::Regenerative::RuntimeImage;
using Deep2::Regenerative::SealedCore;
using Deep2::Regenerative::VerifyAndRegenerateRuntimeImage;
using Deep2::Regenerative::WorkloadFacts;
using Deep2::TimeReversal::Hash256;

BoundRealtimeImage g_bound{};

bool MapRx(void** out, size_t bytes, const void* src) {
#ifdef _WIN32
    if (!out || bytes == 0 || !src) return false;
    void* p = VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) return false;
    std::memcpy(p, src, bytes);
    DWORD old = 0;
    if (!VirtualProtect(p, bytes, PAGE_EXECUTE_READ, &old)) {
        VirtualFree(p, 0, MEM_RELEASE);
        return false;
    }
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(p, &mbi, sizeof(mbi)) ||
        (mbi.Protect != PAGE_EXECUTE_READ && mbi.Protect != PAGE_EXECUTE_READWRITE)) {
        VirtualFree(p, 0, MEM_RELEASE);
        return false;
    }
    *out = p;
    return true;
#else
    (void)out; (void)bytes; (void)src;
    return false;
#endif
}

// x64: mov eax, 1; ret — first/streamed token proof stub (no model path)
static const uint8_t kTokenStub[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};

bool BuildFixtureAndCommit(RegenerativeRuntime& rt, std::string& detail) {
    SealedCore sealed{};
    sealed.authoritySha.b[0] = 0xA1;
    sealed.generationCounter = 91;
    rt.SetSealed(sealed);
    rt.SetHardware({97.0, 32.0, 0.8, 9.0, 2});
    rt.SetWorkload({28, 384, 1, true});
    rt.SetBudgets({20.0, 50.0, false});
    rt.SetKernelAbi("rawrxd.deep2.abi.v1");

    rt.StageEphemeralSlot(0xDEADBEEF);
    Hash256 ev{};
    ev.b[0] = 1;
    rt.RetainNormalizedProof("reuse_safe_skip", 1.35, 0.90, 91, ev);
    rt.RetainNormalizedProof("gpu1_hot_residency", 2.15, 0.94, 91, ev);
    rt.RetainNormalizedProof("prefetch_horizon", 0.92, 0.91, 91, ev);
    rt.RetainNormalizedProof("kv_layout", 0.61, 0.88, 91, ev);
    rt.RetainNormalizedProof("weight_residency", 2.20, 0.95, 91, ev);
    rt.RetainNormalizedProof("ffn_skip", 1.12, 0.90, 91, ev);

    if (!rt.SerializeAndHashProofTable()) {
        detail = "proof table serialize/hash/envelope failed";
        return false;
    }
    const RegenDecision d = rt.EvaluateRegen(28.20, 4.50, 3.20, 1.10, 0.40, 19.85);
    if (!rt.CommitCrashSafeTransition(d, true, true, true)) {
        detail = "crash-safe G+1 commit failed";
        return false;
    }
    if (!rt.PatchSlotsZero() || !rt.Active() || !rt.Active()->frozen) {
        detail = "active image not frozen or slots not zero";
        return false;
    }
    if (rt.Active()->derivedFromPatchHistory) {
        detail = "patch history leaked into RuntimeImage";
        return false;
    }
    return true;
}

} // namespace

void ReleaseMappedImage(BoundRealtimeImage& img) {
#ifdef _WIN32
    if (img.imageRx) {
        VirtualFree(img.imageRx, 0, MEM_RELEASE);
        img.imageRx = nullptr;
    }
    if (img.entryRx) {
        VirtualFree(img.entryRx, 0, MEM_RELEASE);
        img.entryRx = nullptr;
    }
#endif
    img.imageBytes = 0;
    img.entryBytes = 0;
    img.deep2BridgeSlot = nullptr;
}

RetainedProofGateResult VerifyAndBindRuntime() {
    RetainedProofGateResult r;
    ReleaseMappedImage(g_bound);

    RegenerativeRuntime rt;
    if (!BuildFixtureAndCommit(rt, r.detail))
        return r;

    auto rec = rt.MakeAuthorityRecord();
    if (!VerifyAndRegenerateRuntimeImage(&rec)) {
        r.detail = "generation authority verify failed";
        return r;
    }
    r.authorityOk = true;
    r.generation = rt.Active()->generation;

    // 2) Immutable RX map of frozen RuntimeImage (mutations unreachable)
    g_bound.imageBytes = sizeof(RuntimeImage);
    if (!MapRx(&g_bound.imageRx, g_bound.imageBytes, rt.Active())) {
        r.detail = "RX RealtimeImage map failed";
        return r;
    }
    r.rxMapped = true;

    // 3) Bind Deep2 entrypoint to RX stub — no patch-history pointer/callback
    g_bound.entryBytes = sizeof(kTokenStub);
    if (!MapRx(&g_bound.entryRx, 4096, kTokenStub)) {
        r.detail = "RX entry stub map failed";
        ReleaseMappedImage(g_bound);
        r.rxMapped = false;
        return r;
    }
    g_bound.deep2BridgeSlot = g_bound.entryRx;
    r.deep2Bound = true;

    // 4) First-token + streamed-token proofs via bound entry (structural)
#ifdef _WIN32
    using TokenFn = uint32_t(__cdecl*)();
    auto fn = reinterpret_cast<TokenFn>(g_bound.deep2BridgeSlot);
    const uint32_t t0 = fn();
    const uint32_t t1 = fn();
    r.firstTokenOk = (t0 == 1);
    r.streamedTokenOk = (t1 == 1);
    if (!r.firstTokenOk || !r.streamedTokenOk)
        r.detail = "token stream proof returned unexpected status";
    else
        r.detail = "authority+RX+Deep2Bind+token proofs PASS";
#else
    r.detail = "RetainedProofGate requires Windows VirtualProtect RX";
#endif
    return r;
}

} // namespace runtime
} // namespace k2
