// RawrFailureLedger.h — RAWRXD_RAWRDEBUG_FAILURE_LEDGER_001 / RAWRXD_RAWRFIX_AUTHORITY_001
// One failure, one root cause, one patch, one rebuild, one rerun, one receipt.
// The ledger refuses to record a fix that did not rerun.
#pragma once
#include <string>
#include <vector>

namespace rawrxd { namespace ledger {

struct FailureEntry {
    std::string failureId;        // e.g. RAWRXD_RAWR_DUMP_AUTHORITY_001
    std::string failureName;
    std::string reproCommand;
    std::string expected;
    std::string actual;
    std::string rootCauseFile;
    int         rootCauseLine = 0;
    std::string rootCause;
    std::vector<std::string> patchFiles;
    int         buildExit  = -1;   // -1 == not run
    std::string rerunCommand;
    int         rerunExit  = -1;   // -1 == not run
    std::string receiptPath;
    std::string verdict;
    std::string rationale;
};

// Classify an entry from its measured fields. A fix without a rerun, or with
// a failing rerun, is a FAIL regardless of how good the patch looks.
std::string classify(const FailureEntry& e);

// Append RAWRXD_RAWRDEBUG_FAILURE_LEDGER_001 / RAWRXD_RAWRFIX_AUTHORITY_001 to
// a path. The verdict comes from classify(); it is never passed in.
void writeEntryReceipt(const std::string& path, const FailureEntry& e);

}} // namespace rawrxd::ledger
