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
    if (!c.requiredFields.empty()) {
        const receiptcheck::Validation val = receiptcheck::validate(
            c.gateName, c.receiptPath, c.requiredFields);
        c.missingFields    = (int)val.missing.size();
        c.measuredFields   = val.measuredFields;
    } else {
        int measured = 0;
        for (const auto& k : c.requiredFields) (void)k;
        for (const auto& kv : r.fields) {
            if (kv.second == "0" || kv.second == "1") ++measured;
            else {
                bool numeric = !kv.second.empty();
                for (char ch : kv.second) {
                    if (!std::isdigit(static_cast<unsigned char>(ch)) && ch != '.' && ch != '-') { numeric = false; break; }
                }
                if (numeric) ++measured;
            }
        }
        c.measuredFields = measured;
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
