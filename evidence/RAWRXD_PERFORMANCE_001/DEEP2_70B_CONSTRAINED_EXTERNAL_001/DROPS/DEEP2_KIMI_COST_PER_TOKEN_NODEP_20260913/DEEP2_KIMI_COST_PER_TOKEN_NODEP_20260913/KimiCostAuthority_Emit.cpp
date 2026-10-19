#include "KimiCostAuthority.hpp"
namespace Deep2 { namespace kcost {
void Emit(FILE*f,const char*tag,const Result&r){
 if(!f)return; if(!tag)tag="RUN";
 std::fprintf(f,"%s_TOKENS=%llu\n%s_TPS=%.9f\n%s_WH_PER_TOKEN=%.9f\n",
  tag,(unsigned long long)r.tokens,tag,r.tps,tag,r.whPerToken);
 std::fprintf(f,"%s_USD_PER_1M=%.6f\n%s_ENERGY_USD_PER_1M=%.6f\n",
  tag,r.usdPer1m,tag,r.energyUsdPer1m);
 std::fprintf(f,"%s_AMORT_USD_PER_1M=%.6f\n%s_STORAGE_HOST_USD_PER_1M=%.6f\n",
  tag,r.amortUsdPer1m,tag,r.storageHostUsdPer1m);
 std::fprintf(f,"%s_H2D_BYTES_PER_TOKEN=%.3f\n%s_D2H_BYTES_PER_TOKEN=%.3f\n",
  tag,r.h2dBytesPerToken,tag,r.d2hBytesPerToken);
 std::fprintf(f,"%s_JOIN_IDLE_PCT=%.3f\n%s_GATES=0x%X\n%s_COST_AUTHORITY=%u\n",
  tag,r.idleJoinPct,tag,r.gates,tag,(unsigned)r.authority);
}
void EmitComparison(FILE*f,const Comparison&c){
 if(!f)return; Emit(f,"DEEP2",c.deep2); Emit(f,"BASELINE",c.baseline);
 std::fprintf(f,"SAME_BENCHMARK_IDENTITY=%u\nCOST_ADVANTAGE_PCT=%.3f\n",
  (unsigned)c.comparable,c.costAdvantagePct);
 std::fprintf(f,"TPS_ADVANTAGE_PCT=%.3f\nDEEP2_WINS_COST=%u\n",
  c.tpsAdvantagePct,(unsigned)c.deep2WinsCost);
}
}} 
