// RawrModesCli.cpp — CLI surface for the honesty-gated agent modes.
//
//   rawr modes                             emit the mode registry
//   rawr audit  <root> [--out <receipt>]   scan a source tree for stubs
//   rawr gate   <gate> <receipt> <src...>  verify a gate; may retract a PASS
//   rawr cert   <exe> <gate>=<receipt>...  certify a chain from receipts
//
// Every subcommand writes a receipt and derives its exit code from what it
// measured. None of them can be talked into a PASS.
#include "agentmodes/AgentModeRegistry.h"
#include "agentmodes/RawrAuditAuthority.h"
#include "agentmodes/RawrCertAuthority.h"
#include "agentmodes/RawrGateVerifier.h"
#include "deep2/ReceiptAuthority.h"
#include "repointel/RepoIntelCli.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace rawrxd { namespace modes {

static std::string defaultReceipt(const char* stem) {
    return std::string("_rawr_mode_") + stem + ".txt";
}

static int cmdModes() {
    const std::string out = "_rawr_agent_modes_receipt.txt";
    writeModeRegistryReceipt(out);
    std::printf("UNIVERSAL_RULE: %s\n", universalRule());
    std::printf("%zu modes registered -> %s\n", allContracts().size(), out.c_str());
    return 0;
}

static int cmdAudit(int argc, char** argv) {
    if (argc < 1) { std::printf("usage: rawr audit <root> [--out <receipt>]\n"); return 64; }
    std::string root = argv[0];
    std::string out  = defaultReceipt("audit");
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], "--out") == 0) out = argv[i + 1];
    }
    const int rc = audit::runAudit(root, out);
    std::printf("receipt: %s (exit %d)\n", out.c_str(), rc);
    return rc;
}

static int cmdGate(int argc, char** argv) {
    // rawr gate <gateName> <receiptPath> <backingSource>...
    if (argc < 3) {
        std::printf("usage: rawr gate <gateName> <receiptPath> <backingSource>...\n");
        return 64;
    }
    gate::GateCheck req;
    req.gateName    = argv[0];
    req.receiptPath = argv[1];
    for (int i = 2; i < argc; ++i) req.backingSources.emplace_back(argv[i]);

    const gate::GateCheck c = gate::verify(req);
    const std::string out = defaultReceipt("gate");
    gate::writeGateReceipt(out, c);

    std::printf("GATE=%s\n", c.gateName.c_str());
    std::printf("DECLARED_VERDICT=%s\n", c.declaredVerdict.empty() ? "(none)" : c.declaredVerdict.c_str());
    std::printf("HARDCODED_PASS_FOUND=%d\n", c.hardcodedPassFound);
    std::printf("SIMULATED_COUNTERS_FOUND=%d\n", c.simulatedCountersFound);
    std::printf("VERDICT=%s\n", gate::verdictName(c.verdict));
    std::printf("RATIONALE=%s\n", c.rationale.c_str());
    std::printf("receipt: %s\n", out.c_str());
    return (c.verdict == gate::Verdict::Pass) ? 0 : 3;
}

static int cmdCert(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: rawr cert <exe> <gateName>=<receiptPath>...\n");
        return 64;
    }
    const std::string exe = argv[0];
    std::vector<cert::GateInput> gates;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        const size_t eq = a.find('=');
        if (eq == std::string::npos) continue;
        gates.push_back({ a.substr(0, eq), a.substr(eq + 1) });
    }
    const cert::CertResult r = cert::certify(exe, gates);
    const std::string out = defaultReceipt("cert");
    cert::writeCertReceipt(out, r);
    std::printf("STRICT_EXE=%s\nSTRICT_EXE_SHA256=%s\n", r.exePath.c_str(),
                r.exeSha256.empty() ? "(unreadable)" : r.exeSha256.c_str());
    std::printf("GATES_REQUIRED=%d GATES_PASS=%d GATES_FAIL=%d\n",
                r.gatesRequired, r.gatesPass, r.gatesFail);
    std::printf("VERDICT=%s\nRATIONALE=%s\n", r.verdict.c_str(), r.rationale.c_str());
    std::printf("receipt: %s\n", out.c_str());
    return (r.verdict == "PASS") ? 0 : 4;
}

int runRawrModes(int argc, char** argv) {
    if (argc < 1) {
        std::printf("RawrXD honesty-gated agent modes\n"
                    "  HONESTY IS ABOVE THE GATE.\n"
                    "  A GATE MAY NOT PASS DISHONESTLY.\n"
                    "  A DISHONEST GATE IS A FAILED GATE.\n\n"
                    "usage:\n"
                    "  rawr modes\n"
                    "  rawr audit  <root> [--out <receipt>]\n"
                    "  rawr gate   <gateName> <receiptPath> <backingSource>...\n"
                    "  rawr cert   <exe> <gateName>=<receiptPath>...\n"
                    "  rawr repo   <subcommand>   whole-repository index\n");
        return 64;
    }
    const std::string sub = argv[0];
    const int rest = argc - 1;
    char** restv = argv + 1;
    if (sub == "modes")  return cmdModes();
    if (sub == "audit") return cmdAudit(rest, restv);
    if (sub == "gate")  return cmdGate(rest, restv);
    if (sub == "cert")  return cmdCert(rest, restv);
    // RAWRXD_REPOSITORY_INTELLIGENCE_001. `rawr repo` answers repository-scale
    // questions against the whole repository, and refuses to answer "absent"
    // from a narrowed scope. `rawr audit` above scans one tree; this one knows
    // the size of the whole tree.
    if (sub == "repo") {
        std::vector<std::string> args;
        args.reserve(static_cast<size_t>(rest));
        for (int i = 0; i < rest; ++i) args.emplace_back(restv[i]);
        const repointel::RepoCliResult r =
            repointel::runRepoIntelCli(args, std::string());
        return r.exitCode;
    }
    std::printf("unknown modes subcommand: %s\n", sub.c_str());
    return 64;
}

}} // namespace rawrxd::modes
