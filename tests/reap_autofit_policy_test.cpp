#include "reap/ReapAutoFitPolicy.hpp"

#include <cassert>
#include <iostream>

int main() {
    auto policy = RawrXD::Reap::AutoFitPolicy::All();
    std::string error;
    assert(policy.valid(error));
    assert(error.empty());
    const auto json = policy.json();
    assert(json.find("\"policy\":\"ALL\"") != std::string::npos);
    assert(json.find("\"quality_constraint\":\"REQUIRED\"") != std::string::npos);

    policy.maximumThroughput = false;
    assert(!policy.valid(error));
    assert(error == "POLICY_ALL_REQUIRES_ALL_OBJECTIVES");
    std::cout << "reap_autofit_policy: PASS\n";
    return 0;
}
