#include "Deep2Steering.hpp"
#include <cassert>
#include <iostream>
using namespace rawrxd::deep2;
int main() {
    SteeringController c;
    SteeringConfig cfg;
    cfg.enabled = true;
    cfg.allowed_tokens = {1, 2};
    cfg.logit_bias[1] = 3.0f;
    c.Configure(cfg);
    std::vector<float> raw = {100.f, 1.f, 2.f}, working = raw;
    assert(c.Apply(working));
    assert(SteeringController::Argmax(working) == 1);
    assert(raw[0] == 100.f);
    cfg.certification_mode = true;
    c.Configure(cfg);
    working = raw;
    assert(c.Apply(working));
    assert(working == raw);
    cfg.certification_mode = false;
    cfg.allowed_tokens = {9};
    c.Configure(cfg);
    working = raw;
    assert(!c.Apply(working));
    std::cout << "STEERING_TEST=PASS\n";
}
