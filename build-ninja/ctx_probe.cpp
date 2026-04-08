#include <iostream>
#include "context_config.h"
int main(){
    RawrXD::ContextDecision d = RawrXD::ResolveContextDecision(131072);
    std::cout << "requested=" << d.requested
              << " effective=" << d.effective
              << " kv_bytes=" << d.estimated_kv_bytes
              << " kv_budget=" << d.kv_budget_bytes
              << " pressure=" << (d.pressure_detected ? 1 : 0)
              << " adapted=" << (d.adapted ? 1 : 0)
              << std::endl;
    return 0;
}
