// AgentModeRegistry.h — RAWRXD_AGENT_MODE_AUTHORITY_001
// RawrXD-native agent modes. Honesty-gated equivalents of Code, Ask, Debug,
// Plan, Orchestrator, plus the new gate-keeping modes.
//
// The universal rule is machine-readable here so that it can be emitted into
// receipts and checked, not merely stated in prose.
//
//   HONESTY IS ABOVE THE GATE.
//   A GATE MAY NOT PASS DISHONESTLY.
//   A DISHONEST GATE IS A FAILED GATE.
#pragma once
#include <string>
#include <vector>

namespace rawrxd { namespace modes {

enum class ModeId {
    Code,
    Ask,
    Debug,
    Plan,
    Conductor,
    Gate,
    Receipt,
    Audit,
    Fix,
    Cert
};

struct ModeContract {
    ModeId           id;
    const char*      name;         // e.g. "RawrCode"
    const char*      replaces;     // e.g. "Code"  ("" for new modes)
    bool             canEditSource;
    bool             canRunBuild;
    bool             canMarkPass;  // may a PASS be asserted in this mode?
    const char*      purpose;
    const char*      gateName;     // receipt gate identifier
};

// All ten contracts, in table order.
const std::vector<ModeContract>& allContracts();

// Lookup by mode name ("RawrCode"). Returns nullptr when unknown.
const ModeContract* findContract(const std::string& name);

// True when the mode is permitted to assert PASS at all. Modes that cannot
// mark PASS must never emit a PASS verdict for a gate they did not measure.
bool modeMayMarkPass(const std::string& name);

// The universal rule, verbatim, as data.
const char* universalRule();

// Append the mode table + universal rule to a receipt path.
void writeModeRegistryReceipt(const std::string& path);

}} // namespace rawrxd::modes
