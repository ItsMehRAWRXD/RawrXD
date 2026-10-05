// ============================================================================
// tools/deep2_dual_route_gate.cpp  --  RAWRXD_DUAL_ROUTE_AUTHORITY_001
// ============================================================================
// Regression gate for the dual-device route-authority leak.
//
// THE DEFECT: LinearW() correctly gated dual-row execution on
// multiGpuLayerPlan_.active, but its nominal "single-GPU fallback" called
// tryVulkanHostGEMV(), which re-entered the dual-row split on the strength of
// two devices existing. That defeated the measured capability gate and made the
// caller's route receipt false.
//
// THE INVARIANT:
//
//   DUAL_DEVICE_ROUTE_ALLOWED = multiGpuLayerPlan_.active
//                            && vulkanDevices_.size() >= 2
//                            && wt.rows >= 2
//
// WHY THIS IS LINE-BASED, NOT AN AST PARSE
// Three earlier revisions located the guard by scanning for `if(` and matching
// balanced parentheses. All three reported the wrong predicate or the wrong
// verdict -- and the negative control below PROVED the gate passed with the
// conjunct deleted. A conformance gate that cannot detect the defect it exists
// for is worse than no gate, because it reads as a pass.
//
// So the check is deliberately dumb: find the line that admits the dual-row
// split, and require the capability conjunct ON THAT LINE. There is no nesting,
// no paren counting, and no "which if did I mean".
//
// SCOPE, stated plainly: this is a SOURCE-INVARIANT gate. It does not execute
// Vulkan and proves nothing about runtime route behaviour. What it does
// guarantee is that the exact defect cannot be reintroduced by editing the
// predicate on that line, which is how it was introduced.
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

namespace {

bool readFile(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

std::vector<std::string> lines(const std::string& s) {
    std::vector<std::string> v;
    std::istringstream is(s);
    std::string l;
    while (std::getline(is, l)) v.push_back(l);
    return v;
}

bool has(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

int g_fail = 0;
void check(bool ok, const char* id, const std::string& detail) {
    if (!ok) ++g_fail;
    std::printf("%-4s %-32s %s\n", ok ? "ok" : "FAIL", id, detail.c_str());
}

// A line "admits the dual-row split" if it gates on a device count of 2 and
// also mentions rows. That identifies the admission predicate and not the
// `if(Deep2RunDualGpuRowSplit(...))` success check below it, and not the early
// validity return (which uses vulkanDevices_.empty(), not .size()).
bool isDualAdmissionLine(const std::string& l) {
    return has(l, "vulkanDevices_.size()") && has(l, ">=2") && has(l, "wt.rows");
}

} // namespace

int main(int argc, char** argv) {
    const std::string moePath = (argc > 1) ? argv[1]
                                           : "src/deep2/Deep2Engine_GpuMoEMLA.cpp";
    const std::string engPath = (argc > 2) ? argv[2]
                                           : "src/deep2/Deep2Engine.cpp";

    std::printf("=== RAWRXD_DUAL_ROUTE_AUTHORITY_001 ===\n");
    std::printf("SCOPE=source invariant (reads the guard line; does NOT execute the route)\n");
    std::printf("file=%s\n", moePath.c_str());

    std::string moe, eng;
    if (!readFile(moePath, moe) || !readFile(engPath, eng)) {
        std::printf("FAIL <unreadable source> cannot certify an invariant from a file "
                    "that did not open\n");
        std::printf("VERDICT=FAIL\n");
        return 1;
    }

    const std::vector<std::string> ml = lines(moe);
    std::vector<std::string> guard;      // every candidate admission line
    int lineNo = 0;
    for (size_t i = 0; i < ml.size(); ++i) {
        if (!isDualAdmissionLine(ml[i])) continue;
        guard.push_back(ml[i]);
        lineNo = static_cast<int>(i) + 1;
    }

    if (guard.empty()) {
        std::printf("FAIL <admission guard not found> this gate must not pass by "
                    "failing to find the code it certifies\n");
        std::printf("VERDICT=FAIL\n");
        return 1;
    }

    // Every admission line in this file must carry the capability conjunct, or
    // none may. One unguarded entry point is the same defect one layer down.
    int unguarded = 0;
    for (const auto& g : guard) {
        if (!has(g, "multiGpuLayerPlan_.active")) ++unguarded;
        std::printf("  L%-5d %.150s\n", lineNo, g.c_str());
    }
    std::printf("\n");
    check(unguarded == 0, "all_dual_guards_plan_gated",
          std::to_string(guard.size()) + " admission guard(s), " +
              std::to_string(unguarded) + " without the capability conjunct");

    const std::vector<std::string> el = lines(eng);
    bool linearWGated = false;
    for (const auto& l : el) {
        if (has(l, "vulkanDevices_.size()") && has(l, "multiGpuLayerPlan_.active") &&
            has(l, "wt.rows")) {
            linearWGated = true;
        }
    }
    check(linearWGated, "linearw_still_plan_gated",
          linearWGated ? "LinearW retains its own capability gate"
                       : "LinearW no longer gates on the plan at all");

    std::printf("\nCHECKS_TOTAL=2\n");
    std::printf("CHECKS_FAIL=%d\n", g_fail);
    if (g_fail == 0) {
        std::printf("DUAL_ROUTE_REQUIRES_PLAN_ACTIVE=1\n");
        std::printf("NOTE=source invariant only; route BEHAVIOUR still needs a "
                    "runtime A/B gate\n");
        std::printf("VERDICT=PASS\n");
        return 0;
    }
    std::printf("VERDICT=FAIL\n");
    return 1;
}
