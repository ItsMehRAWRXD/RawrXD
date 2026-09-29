// RawrGateVerifier.h — RAWRXD_RAWRGATE_VERIFIER_001
// Validates receipts and decides whether a gate is honest. This is the only
// mode besides RawrFix/RawrDebug/RawrCert that may retract a PASS, and it
// may not soften a pass condition in order to obtain one.
//
//   HONESTY IS ABOVE THE GATE.
//   A GATE MAY NOT PASS DISHONESTLY.
//   A DISHONEST GATE IS A FAILED GATE.
#pragma once
#include <string>
#include <vector>

namespace rawrxd { namespace gate {

// The complete set of verdicts this mode may emit.
enum class Verdict {
    Pass,
    Fail,
    RetractedFalsePass,
    StubPassContamination,
    ReceiptMissing,
    SourceRuntimeMismatch
};

const char* verdictName(Verdict v);

struct GateCheck {
    std::string              gateName;
    std::string              receiptPath;
    std::vector<std::string> backingSources;   // files that implement this gate
    std::vector<std::string> requiredFields;   // fields a PASS must contain

    // Measured results
    bool     receiptExists       = false;
    bool     sourceBackingChecked = false;
    bool     runtimeBackingChecked = false;
    int      hardcodedPassFound  = 0;
    int      simulatedCountersFound = 0;
    int      printOnlyFunctionsFound = 0;
    int      missingFields       = 0;
    int      measuredFields      = 0;
    bool     sourceRuntimeMismatch = false;
    std::string declaredVerdict;
    Verdict  verdict = Verdict::Fail;
    std::string rationale;         // why this verdict, in plain words
};

// Cross-check a gate's receipt against the source that is supposed to back it.
// A receipt asserting PASS while its backing source contains a hardcoded
// verdict or a fabricated counter yields StubPassContamination, never Pass.
GateCheck verify(const GateCheck& req);

// Write RAWRXD_RAWRGATE_VERIFIER_001 to `path` from the measured check.
void writeGateReceipt(const std::string& path, const GateCheck& c);

}} // namespace rawrxd::gate
