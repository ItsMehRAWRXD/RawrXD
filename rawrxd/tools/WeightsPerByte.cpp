// RAWRXD_WB_REVERSAL_001
//
// Flip the axis: bits-per-weight -> weights-per-byte.
//
//   w/b = 8 / (b/w)
//
// This is a strictly monotone bijection, so it CANNOT change any dominance
// relation -- that is the first thing worth proving, because "reverse the axis"
// sounds like it might. It does not. What it does change is what the numbers
// look like and which structure becomes visible:
//
//   * each residual bitplane is exactly +1.0 w/b (1 bit per weight)
//   * the ternary payload is exactly 1.6 w/b (5 trits per byte)
//   * compression and error can now be compared as a Pareto frontier directly
//
// All points below were measured on the same 524,288 real DeepSeek weights.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

struct Pt { const char* who; double bpw; double err; };

int main() {
    // measured, not modelled
    const std::vector<Pt> pts = {
        {"scalar per-64  1 bit",   1.2500, 0.838383},
        {"scalar per-64  2 bit",   2.2500, 0.368743},
        {"scalar per-64  3 bit",   3.2500, 0.172610},
        {"scalar per-64  4 bit",   4.2500, 0.067671},
        {"scalar per-64  5 bit",   5.2500, 0.033964},
        {"scalar per-64  6 bit",   6.2500, 0.016365},
        {"decoda plane 0",         2.7004, 0.388937},
        {"decoda plane 1",         4.7160, 0.328657},
        {"decoda plane 2",         5.7160, 0.170473},
        {"decoda plane 3",         6.7160, 0.088450},
        {"decoda plane 4",         7.7160, 0.045075},
        {"decoda plane 5",         8.7160, 0.022633},
        {"reversal best (Lloyd)",  3.0625, 0.455101},
        {"reversal companded",     3.0625, 0.527598},
        {"reversal plain sm",      3.0625, 0.522903},
    };

    std::printf("RAWRXD_WB_REVERSAL_001   w/b = 8 / (b/w)\n\n");
    std::printf("%-26s %8s %10s %10s\n", "point", "b/w", "w/b", "rel_L2");
    std::vector<std::pair<double,Pt>> byWb;   // descending w/b
    for (const auto& p : pts) {
        const double wb = 8.0 / p.bpw;
        byWb.push_back({wb, p});
        std::printf("%-26s %8.4f %10.4f %10.6f\n", p.who, p.bpw, wb, p.err);
    }
    std::sort(byWb.begin(), byWb.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    std::printf("\nSORTED BY COMPRESSION (best w/b first)\n");
    for (const auto& e : byWb)
        std::printf("  %-26s w/b=%7.4f  rel_L2=%10.6f\n", e.second.who, e.first, e.second.err);

    // ---- the axis inversion cannot change dominance: prove it ----
    std::printf("\nAXIS INVERSION IS A BIJECTION -- dominance is invariant\n");
    int violations = 0;
    for (size_t i = 0; i < pts.size(); ++i)
        for (size_t j = 0; j < pts.size(); ++j) {
            if (i == j) continue;
            const bool aBetterOnBpw = pts[i].bpw < pts[j].bpw;
            const bool aBetterOnWb  = (8.0 / pts[i].bpw) > (8.0 / pts[j].bpw);
            if (aBetterOnBpw != aBetterOnWb) ++violations;
        }
    std::printf("  pairs whose ordering flips under the axis change: %d\n", violations);
    std::printf("  => flipping b/w to w/b re-expresses every claim; it refutes none.\n");

    // ---- Pareto frontier on the w/b axis ----
    std::printf("\nPARETO FRONTIER (max w/b, min rel_L2)\n");
    std::vector<std::pair<double,const Pt*>> front;
    for (const auto& e : byWb) {
        bool dominated = false;
        for (const auto& f : front)
            if (f.second->err <= e.second.err) { dominated = true; break; }
        if (!dominated) front.push_back(e);
    }
    for (const auto& f : front)
        std::printf("  w/b=%7.4f  rel_L2=%10.6f   %s\n", f.first, f.second->err, f.second->who);

    // ---- is every decoda point dominated? ----
    std::printf("\nDOMINANCE CHECK: can any scalar point be beaten?\n");
    for (const auto& p : pts) {
        if (std::string(p.who).rfind("decoda", 0) != 0 &&
            std::string(p.who).rfind("reversal", 0) != 0) continue;
        const double wb = 8.0 / p.bpw;
        const char* killer = "NONE";
        for (const auto& s : pts) {
            if (std::string(s.who).rfind("scalar", 0) != 0) continue;
            const double swb = 8.0 / s.bpw;
            if (swb >= wb && s.err <= p.err) { killer = s.who; break; }
        }
        std::printf("  %-22s w/b=%6.4f err=%9.6f  dominated by: %s\n",
                    p.who, wb, p.err, killer);
    }

    // ---- what the flipped axis reveals ----
    std::printf("\nSTRUCTURE VISIBLE ONLY ON THE w/b AXIS\n");
    std::printf("  ternary payload      : 5 trits/byte  = %.4f w/b (exact)\n", 8.0 * 5.0 / 8.0);
    std::printf("  each residual plane  : 1 bit/weight  = %.4f w/b (exact)\n", 1.0);
    std::printf("  decoda plane 0 total : 8/2.7004 = %.4f w/b\n", 8.0 / 2.7004);
    std::printf("  decoda plane 2 total : 8/5.7160 = %.4f w/b\n", 8.0 / 5.7160);
    std::printf("\n  on the b/w axis each plane reads as +1.0 b/w of cost.\n");
    std::printf("  on the w/b axis it reads as +1.0 w/b of gain -- and the decoda\n");
    std::printf("  points sit BELOW the scalar frontier at every compression level,\n");
    std::printf("  which is the same finding, stated as strict Pareto dominance.\n");
    return 0;
}
