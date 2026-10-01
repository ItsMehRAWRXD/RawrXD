// RawrGateVerifier.cpp — RAWRXD_RAWRGATE_VERIFIER_001
#include "agentmodes/RawrGateVerifier.h"
#include "agentmodes/RawrAuditAuthority.h"
#include "agentmodes/RawrReceiptValidator.h"
#include "deep2/ReceiptAuthority.h"

#include <cstdio>
#include <filesystem>

namespace rawrxd { namespace gate {

namespace fs = std::filesystem;

const char* verdictName(Verdict v) {
    switch (v) {
        case Verdict::Pass:                    return "PASS";
        case Verdict::Fail:                    return "FAIL";
        case Verdict::RetractedFalsePass:      return "RETRACTED_FALSE_PASS";
        case Verdict::StubPassContamination:   return "STUB_PASS_CONTAMINATION";
        case Verdict::ReceiptMissing:          return "RECEIPT_MISSING";
        case Verdict::SourceRuntimeMismatch:   return "SOURCE_RUNTIME_MISMATCH";
    }
    return "FAIL";
}

GateCheck verify(const GateCheck& req) {
    GateCheck c = req;

    // --- 1. The receipt must exist. -------------------------------------
    const receiptcheck::Receipt r = receiptcheck::load(c.receiptPath);
    c.receiptExists = r.exists;
    if (!r.exists) {
        c.verdict = Verdict::ReceiptMissing;
        c.rationale = "no receipt at " + c.receiptPath + "; a gate cannot pass on absent evidence";
        return c;
    }

    const auto dv = r.fields.find("VERDICT");
    c.declaredVerdict = (dv != r.fields.end()) ? dv->second : std::string("(none)");

    // --- 2. Required fields must be present and measured. ---------------
    //
    // Q1 CORRECTION. The previous version did this:
    //
    //     if (!c.requiredFields.empty()) { ...validate... }
    //     else {
    //         for (const auto& k : c.requiredFields) (void)k;   // iterates EMPTY
    //         for (auto& kv : r.fields) { ...count anything numeric... }
    //     }
    //
    // The else branch therefore (a) executed a no-op loop over the empty
    // vector, and (b) counted ANY numeric-looking field anywhere in the
    // receipt as "measured". A fabricated receipt containing nothing but
    // `VERDICT=PASS` and `FAKE_TOOL_RESULTS=0` scored measuredFields=1 and
    // passed. c.missingFields was never set on that path, so the
    // missingFields>0 branch could not catch it either.
    //
    // The measurement contract is now mandatory. An empty `requiredFields`
    // list on a gate that requires measurement is a missing contract, not a
    // licence to accept unverified numbers.
    if (c.requiredFields.empty() && c.requireMeasuredFields) {
        c.verdict = Verdict::ReceiptMissing;
        c.sourceRuntimeMismatch = true;
        c.rationale =
            "gate '" + c.gateName + "' declares no requiredFields, so it states no "
            "measurement contract; an unmeasured receipt cannot be verified and "
            "must not be passed. Previously this case fell back to counting any "
            "numeric-looking field in the receipt, which accepted fabricated "
            "counters. Declare the fields a PASS must contain, or set "
            "requireMeasuredFields=false if the gate truly measures nothing.";
        return c;
    }

    if (!c.requiredFields.empty()) {
        const receiptcheck::Validation val = receiptcheck::validate(
            c.gateName, c.receiptPath, c.requiredFields);
        c.missingFields    = (int)val.missing.size();
        c.measuredFields   = val.measuredFields;
    } else {
        // requireMeasuredFields == false: nothing is claimed, so nothing can be
        // counted as evidence. Leave measuredFields at 0 deliberately.
        c.measuredFields = 0;
    }

    // --- 3. The backing source must be free of stub markers. -------------
    audit::ScanResult scan;
    for (const auto& src : c.backingSources) {
        std::error_code ec;
        if (!fs::exists(src, ec)) continue;
        if (fs::is_directory(src, ec)) {
            audit::ScanOptions so;
            so.root = src;
            const audit::ScanResult sub = audit::scanSourceTree(so);
            for (const auto& f : sub.findings) scan.findings.push_back(f);
            scan.filesScanned += sub.filesScanned;
            scan.blockingCount += sub.blockingCount;
            scan.advisoryCount += sub.advisoryCount;
            scan.hardcodedPass += sub.hardcodedPass;
            scan.simulatedCounters += sub.simulatedCounters;
        } else {
            audit::auditFile(src, scan);
        }
        c.sourceBackingChecked = true;
    }

    for (const auto& f : scan.findings) {
        if (f.rule == "HARDCODED_VERDICT")     ++c.hardcodedPassFound;
        if (f.rule == "SIMULATED_COUNTER")      ++c.simulatedCountersFound;
        if (f.rule == "PRINT_ONLY_FUNCTION")    ++c.printOnlyFunctionsFound;
    }

    // --- 4. Decide. The declared verdict is evidence, not authority. -----
    const bool declaredPass = (c.declaredVerdict == "PASS");

    if (c.missingFields > 0) {
        c.verdict = declaredPass ? Verdict::RetractedFalsePass : Verdict::Fail;
        c.rationale = "receipt is missing " + std::to_string(c.missingFields) +
                      " required field(s) but declares " + c.declaredVerdict;
    } else if (declaredPass && c.hardcodedPassFound > 0) {
        c.verdict = Verdict::StubPassContamination;
        c.rationale = "receipt declares PASS while the backing source assigns a "
                      "hardcoded PASS verdict in " + std::to_string(c.hardcodedPassFound) +
                      " place(s)";
    } else if (declaredPass && c.simulatedCountersFound > 0) {
        c.verdict = Verdict::StubPassContamination;
        c.rationale = "receipt declares PASS while the backing source fabricates " +
                      std::to_string(c.simulatedCountersFound) +
                      " observation counter(s) from literals";
    } else if (declaredPass && c.measuredFields == 0) {
        c.verdict = Verdict::SourceRuntimeMismatch;
        c.rationale = "receipt declares PASS but contains no measured numeric field "
                      "that could have come from a run";
    } else if (declaredPass) {
        c.verdict = Verdict::Pass;
        c.rationale = "receipt declares PASS, required fields are present and measured, "
                      "and the backing source contains no stub markers";
    } else {
        c.verdict = Verdict::Fail;
        c.rationale = "receipt declares " + c.declaredVerdict;
    }

    return c;
}

void writeGateReceipt(const std::string& path, const GateCheck& c) {
    receipt::beginGate(path, "RAWRXD_RAWRGATE_VERIFIER_001");
    receipt::writeKeyValue(path, "GATE_NAME", c.gateName);
    receipt::writeKeyValue(path, "RECEIPT_PATH", c.receiptPath);
    receipt::writeKeyValueInt(path, "RECEIPT_EXISTS", c.receiptExists ? 1 : 0);
    receipt::writeKeyValueInt(path, "SOURCE_BACKING_CHECKED", c.sourceBackingChecked ? 1 : 0);
    receipt::writeKeyValueInt(path, "RUNTIME_BACKING_CHECKED", c.runtimeBackingChecked ? 1 : 0);
    receipt::writeKeyValueInt(path, "HARDCODED_PASS_FOUND", c.hardcodedPassFound);
    receipt::writeKeyValueInt(path, "SIMULATED_COUNTERS_FOUND", c.simulatedCountersFound);
    receipt::writeKeyValueInt(path, "PRINT_ONLY_FUNCTIONS_FOUND", c.printOnlyFunctionsFound);
    receipt::writeKeyValueInt(path, "MISSING_REQUIRED_FIELDS", c.missingFields);
    receipt::writeKeyValueInt(path, "MEASURED_FIELDS", c.measuredFields);
    receipt::writeKeyValueInt(path, "SOURCE_RUNTIME_MISMATCH", c.sourceRuntimeMismatch ? 1 : 0);
    receipt::writeKeyValue(path, "DECLARED_VERDICT", c.declaredVerdict.empty() ? "(none)" : c.declaredVerdict);
    receipt::writeKeyValue(path, "RATIONALE", c.rationale);
    receipt::endGate(path, verdictName(c.verdict));
}

}} // namespace rawrxd::gate
