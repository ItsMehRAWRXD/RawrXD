// AgentModeRegistry.cpp — RAWRXD_AGENT_MODE_AUTHORITY_001
#include "agentmodes/AgentModeRegistry.h"
#include "deep2/ReceiptAuthority.h"
#include <cstring>

namespace rawrxd { namespace modes {

// The contract table. `canMarkPass` is the load-bearing column: it is what
// stops an Ask or Plan session from asserting a runtime verdict it never
// measured.
static const std::vector<ModeContract>& table() {
    static const std::vector<ModeContract> kTable = {
        { ModeId::Code,      "RawrCode",      "Code",       true,  true,  true,
          "Edit source, build, run, verify, write receipts", "RAWRXD_RAWRCODE_GATE_001" },
        { ModeId::Ask,       "RawrAsk",       "Ask",        false, false, false,
          "Answer and classify without changing files",      "RAWRXD_RAWRASK_CLASSIFICATION_001" },
        { ModeId::Debug,     "RawrDebug",     "Debug",      true,  true,  true,
          "Reproduce, trace root cause, patch, rerun",       "RAWRXD_RAWRDEBUG_FAILURE_LEDGER_001" },
        { ModeId::Plan,      "RawrPlan",      "Plan",       false, false, false,
          "Design batches without mutating source",          "RAWRXD_RAWRPLAN_BATCH_PLAN_001" },
        { ModeId::Conductor, "RawrConductor", "Orchestrator", false, false, false,
          "Control batch order and evidence flow",           "RAWRXD_RAWRCONDUCTOR_AUTHORITY_001" },
        { ModeId::Gate,      "RawrGate",      "",           false, false, true,
          "Validate receipts; retract dishonest PASS",       "RAWRXD_RAWRGATE_VERIFIER_001" },
        { ModeId::Receipt,   "RawrReceipt",   "",           false, false, false,
          "Generate and validate receipt files only",        "RAWRXD_RAWRRECEIPT_AUTHORITY_001" },
        { ModeId::Audit,     "RawrAudit",     "",           false, false, false,
          "Find stubs, hardcoded PASS, exclusions, dead code","RAWRXD_RAWRAUDIT_AUTHORITY_001" },
        { ModeId::Fix,       "RawrFix",       "",           true,  true,  true,
          "Patch one verified failure at a time",            "RAWRXD_RAWRFIX_AUTHORITY_001" },
        { ModeId::Cert,      "RawrCert",      "",           false, true,  true,
          "Final certification only, from existing receipts", "RAWRXD_RAWRCERT_AUTHORITY_001" },
    };
    return kTable;
}

const std::vector<ModeContract>& allContracts() { return table(); }

const ModeContract* findContract(const std::string& name) {
    for (const auto& c : table()) {
        if (name == c.name) return &c;
    }
    return nullptr;
}

bool modeMayMarkPass(const std::string& name) {
    const ModeContract* c = findContract(name);
    return c ? c->canMarkPass : false;
}

const char* universalRule() {
    return "HONESTY_IS_ABOVE_THE_GATE|A_GATE_MAY_NOT_PASS_DISHONESTLY|"
           "A_DISHONEST_GATE_IS_A_FAILED_GATE|NO_MODE_MAY_MARK_PASS_UNLESS_"
           "THE_GATE_RECEIPT_PROVES_PASS|NO_MODE_MAY_HIDE_MISSING_IMPLEMENTATION|"
           "NO_MODE_MAY_REPLACE_RUNTIME_TRUTH_WITH_EXPLANATION";
}

void writeModeRegistryReceipt(const std::string& path) {
    receipt::beginGate(path, "RAWRXD_AGENT_MODE_AUTHORITY_001");
    receipt::writeKeyValue(path, "UNIVERSAL_RULE", universalRule());
    receipt::writeKeyValueInt(path, "MODE_COUNT", (int64_t)table().size());

    for (const auto& c : table()) {
        const std::string p = std::string(c.name) + ".";
        receipt::writeKeyValue(path, p + "REPLACES",     c.replaces[0] ? c.replaces : "(new)");
        receipt::writeKeyValue(path, p + "CAN_EDIT_SOURCE", c.canEditSource ? "1" : "0");
        receipt::writeKeyValue(path, p + "CAN_RUN_BUILD",   c.canRunBuild  ? "1" : "0");
        receipt::writeKeyValue(path, p + "CAN_MARK_PASS",   c.canMarkPass  ? "1" : "0");
        receipt::writeKeyValue(path, p + "GATE",            c.gateName);
    }

    // A registry is a declaration, so the verdict describes the declaration
    // being complete, not any runtime behaviour it describes.
    receipt::writeKeyValueInt(path, "REGISTRY_COMPLETE", 1);
    receipt::endGate(path, "PASS");
}

}} // namespace rawrxd::modes
