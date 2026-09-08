#pragma once
/* 1(PROCESSION): S → private → S'. Mount solid ⇒ no remount spend. */
#include "ModelMount.hpp"
#include <cstdint>

namespace rawr::mount {

struct TerminalNeed {
    uint64_t tokensHave = 0;
    uint64_t tokensNeed = 0;
    uint64_t wallNsHave = 0; // allowed (budget); 0 = not in this procession
    uint64_t wallNsNeed = 0; // actual wall demand
    bool wallOk = true;      // observe shortcut when ns not filled

    bool met() const noexcept {
        if (tokensHave < tokensNeed) return false;
        if (wallNsHave != 0 && wallNsNeed > wallNsHave) return false;
        return wallOk;
    }
    uint64_t wallDelta() const noexcept {
        if (wallNsHave == 0) return wallOk ? 0ull : 1ull;
        return wallNsNeed > wallNsHave ? (wallNsNeed - wallNsHave) : 0ull;
    }
};

struct ProcessionScratch {
    ModelMount mount{};
    HaveModel have{};
    TerminalNeed terminal{};
    uint64_t steps = 0;
    uint64_t tokenProgress = 0;
    uint64_t terminalDeltaProgress = 0;
    uint64_t negativeGen = 0;
    SpendClass lastSpend = SpendClass::GenerationProgress;
    Advance last = Advance::NoNextExists;
};

using AdvanceFn = Advance (*)(ProcessionScratch& s, void* ctx);

inline SpendClass ClassifySpend(uint64_t tokenDelta, uint64_t wallDeltaBefore,
                                uint64_t wallDeltaAfter) noexcept {
    if (tokenDelta > 0) return SpendClass::GenerationProgress;
    if (wallDeltaAfter < wallDeltaBefore) return SpendClass::UsefulChoreography;
    return SpendClass::NegativeGeneration;
}

inline Advance ProcessionStep(ProcessionScratch& s, AdvanceFn fn,
                              void* ctx) noexcept {
    if (!s.mount.solid() || !s.have.have()) {
        s.last = Advance::NoNextExists;
        return s.last;
    }
    // Performance fault ≠ authority fault: remount ineligible while solid.
    if (s.mount.mountActionEligible() == false && !fn) {
        s.last = Advance::NoNextExists;
        return s.last;
    }
    if (s.terminal.met()) {
        s.last = Advance::TerminalProduced;
        return s.last;
    }
    if (!fn) {
        s.last = Advance::NoNextExists;
        return s.last;
    }
    const uint64_t tok0 = s.terminal.tokensHave;
    const uint64_t d0 = s.terminal.wallDelta();
    s.last = fn(s, ctx);
    ++s.steps;
    const uint64_t tokD = (s.terminal.tokensHave > tok0)
                              ? (s.terminal.tokensHave - tok0)
                              : 0ull;
    const uint64_t d1 = s.terminal.wallDelta();
    s.lastSpend = ClassifySpend(tokD, d0, d1);
    if (tokD) s.tokenProgress += tokD;
    if (d1 < d0) s.terminalDeltaProgress += (d0 - d1);
    if (s.lastSpend == SpendClass::NegativeGeneration) ++s.negativeGen;
    return s.last;
}

inline bool ProcessionComplete(const ProcessionScratch& s) noexcept {
    return s.terminal.met() || s.last == Advance::TerminalProduced;
}

} // namespace rawr::mount
