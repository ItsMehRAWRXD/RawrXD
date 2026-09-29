// RawrFailureLedger.cpp — RAWRXD_RAWRDEBUG_FAILURE_LEDGER_001 / RAWRXD_RAWRFIX_AUTHORITY_001
#include "agentmodes/RawrFailureLedger.h"
#include "deep2/ReceiptAuthority.h"

namespace rawrxd { namespace ledger {

std::string classify(const FailureEntry& e) {
    if (e.failureName.empty() || e.reproCommand.empty()) {
        return "FAIL_UNREPRODUCED";
    }
    if (e.rootCauseFile.empty() || e.rootCauseLine <= 0) {
        return "FAIL_NO_ROOT_CAUSE";
    }
    if (e.patchFiles.empty()) {
        return "FAIL_NO_PATCH";
    }
    if (e.buildExit < 0) {
        return "FAIL_NOT_BUILT";
    }
    if (e.buildExit != 0) {
        return "FAIL_BUILD";
    }
    if (e.rerunExit < 0) {
        return "FAIL_NOT_RERUN";
    }
    if (e.rerunExit != 0) {
        return "FAIL_RERUN";
    }
    return "PASS";
}

void writeEntryReceipt(const std::string& path, const FailureEntry& e) {
    const std::string verdict = classify(e);

    receipt::beginGate(path, "RAWRXD_RAWRDEBUG_FAILURE_LEDGER_001");
    receipt::writeKeyValue(path, "FAILURE_ID", e.failureId);
    receipt::writeKeyValue(path, "FAILURE_NAME", e.failureName);
    receipt::writeKeyValue(path, "REPRO_COMMAND", e.reproCommand);
    receipt::writeKeyValue(path, "EXPECTED", e.expected);
    receipt::writeKeyValue(path, "ACTUAL", e.actual);
    receipt::writeKeyValue(path, "ROOT_CAUSE_FILE", e.rootCauseFile);
    receipt::writeKeyValueInt(path, "ROOT_CAUSE_LINE", e.rootCauseLine);
    receipt::writeKeyValue(path, "ROOT_CAUSE", e.rootCause);
    receipt::writeKeyValueInt(path, "FIX_FILES", (int64_t)e.patchFiles.size());
    for (size_t i = 0; i < e.patchFiles.size(); ++i) {
        receipt::writeKeyValue(path, "FIX_FILE_" + std::to_string(i + 1), e.patchFiles[i]);
    }
    receipt::writeKeyValueInt(path, "BUILD_EXIT", e.buildExit);
    receipt::writeKeyValue(path, "RERUN_COMMAND", e.rerunCommand);
    receipt::writeKeyValueInt(path, "RERUN_EXIT", e.rerunExit);
    receipt::endGate(path, verdict.c_str());

    // The fix gate is a companion view of the same measured evidence.
    receipt::writeKeyValue(path, "RAWRXD_RAWRFIX_AUTHORITY_001", "ENTERED");
    receipt::writeKeyValueInt(path, "FIX_BUILD_EXIT", e.buildExit);
    receipt::writeKeyValueInt(path, "FIX_TEST_EXIT", e.rerunExit);
    receipt::writeKeyValue(path, "FIX_RECEIPT_PATH", path);
}

}} // namespace rawrxd::ledger
