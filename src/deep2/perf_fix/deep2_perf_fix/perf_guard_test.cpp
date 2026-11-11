#include "deep2_perf_guard.hpp"
#include <cassert>
#include <iostream>
int main(){
    using namespace rawrxd::deep2;
    Telemetry t;t.gpu_dispatch(4);t.prefill(100,50);t.decode(10,20);t.kv(50,100);
    auto s=t.snapshot();assert(s.prefill_tps==2000.0);assert(s.decode_tps==500.0);
    assert(evaluate(s,Policy{true,true,100})=="PASS");
    PrefixTracker p;std::vector<int32_t> a{1,2,3};p.commit("model-a",a);
    assert(p.reusable("model-a",{1,2,4})==2);
    assert(p.reusable("model-b",a)==0);
    ResidencyGate gate;{auto lease=gate.acquire();bool failed=false;
    try{auto other=gate.acquire();(void)other;}catch(const std::runtime_error&){failed=true;}
    assert(failed);}auto lease=gate.acquire();(void)lease;
    std::cout<<"PERF_GUARD_TEST PASS\n";
}
