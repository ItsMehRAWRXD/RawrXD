// Standalone smoke test: cl /nologo /std:c++20 /EHsc /I src/deep2 tests/reap_unified_options_smoke.cpp
#include "ReapUnifiedOptions.hpp"
#include <cassert>
#include <string>
#include <vector>
int main() {
    using namespace Deep2::Reap;
    std::string error;
    Options o;
    o.activeExperts = 4;
    o.expertBudget = 32;
    o.qualityFloor = 0.95;
    assert(Validate(o, 384, 8, error));
    o.activeExperts = 33;
    assert(!Validate(o, 384, 8, error));
    o.activeExperts = 4;
    const std::vector<Route> routes = {{2, .4f},{8,.3f},{3,.2f},{1,.1f}};
    std::vector<Route> selected;
    assert(SelectRuntimeRoutes(routes, 2, selected, error));
    assert(selected.size() == 2 && selected[0].expert == 2 && selected[1].expert == 8);
    assert(selected[0].weight == routes[0].weight);
    assert(!MeetsQualityFloor(.90, 1.0, .95, error));
    assert(MeetsQualityFloor(.96, 1.0, .95, error));
    return 0;
}
