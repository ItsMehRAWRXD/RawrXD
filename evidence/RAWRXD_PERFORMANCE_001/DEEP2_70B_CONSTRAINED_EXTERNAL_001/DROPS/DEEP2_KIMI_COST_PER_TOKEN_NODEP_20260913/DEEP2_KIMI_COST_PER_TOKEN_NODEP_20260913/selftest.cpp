#include "KimiCostAuthority.hpp"
#include "KimiCostDeep2Adapter.hpp"
#include "KimiCostSeal.hpp"
#include "KimiCostPowerSampler.hpp"
#include <cstdio>
using namespace Deep2::kcost;
struct C {uint64_t h2d_bytes,d2h_bytes,reload_miss_bytes,gpu_join_wait_ns,gpu0_work_ns;
 uint64_t gpu1_work_ns,experts_selected,experts_executed,gpu_submits,gpu_waits;
 uint64_t moe_layers_gpu,d2h_partial_vectors,worker_failures,product_backend_attested;};
static Run R(uint64_t wall,uint64_t energy){
 Run r{};r.id={1,2,3,4,14,4096,64};r.generatedTokens=64;r.wallNs=wall;r.energyMilliJ=energy;
 r.exitCode=0;r.argmaxParity=1;r.numericParity=1;r.qualityPass=1;
 C c{32000000000ull,3000000,0,2000000000,20,18,30720,30720,7680,7680,3840,7680,0,1};
 CaptureMoE(c,r);return r;
}
int main(){
 Economics e{0.20,3500.0,12000.0,0.02}; Run a=R(12800000000ull,900000),b=R(25600000000ull,1800000);
 Comparison c=Compare(a,b,e); if(!c.comparable||!c.deep2.authority||!c.baseline.authority)return 10;
 if(c.costAdvantagePct<40.0||!c.deep2WinsCost)return 11;
 if(!Seal(c,{25.0,32}))return 12;
 Run bad=b;bad.id.quant=15;if(Compare(a,bad,e).comparable)return 13;
 PowerSample p[2]={{0,100000},{1000000000ull,100000}};if(IntegrateMilliJ(p,2)!=100000)return 14;
 EmitComparison(stdout,c);
 std::puts("DEEP2_KIMI_COST_SELFTEST=PASS");
 std::puts("TOP15_COST_MECHANICS=15/15 PRODUCT_BOUND=0 COST_SEAL_LIVE=0 PROMOTE=0");
 return 0;
}
