#include "KimiCostAuthority.hpp"
namespace Deep2 { namespace kcost {
Comparison Compare(const Run&a,const Run&b,const Economics&e){
 Comparison c{}; c.deep2=Evaluate(a,e); c.baseline=Evaluate(b,e);
 c.comparable=SameIdentity(a.id,b.id)&&a.qualityPass&&b.qualityPass?1:0;
 if(c.comparable){c.deep2.gates|=G_IDENTITY;c.baseline.gates|=G_IDENTITY;}
 if(c.baseline.usdPer1m>0)
  c.costAdvantagePct=100.0*(c.baseline.usdPer1m-c.deep2.usdPer1m)/c.baseline.usdPer1m;
 if(c.baseline.tps>0)
  c.tpsAdvantagePct=100.0*(c.deep2.tps-c.baseline.tps)/c.baseline.tps;
 c.deep2WinsCost=(c.comparable&&c.deep2.authority&&c.baseline.authority&&
                  c.deep2.usdPer1m<c.baseline.usdPer1m)?1:0;
 return c;
}
}} 
