#include "KimiCostAuthority.hpp"
namespace Deep2 { namespace kcost {
static double Safe(double a,double b){return b>0.0?a/b:0.0;}
bool SameIdentity(const Identity&a,const Identity&b){
 return a.modelHash==b.modelHash&&a.promptHash==b.promptHash&&
 a.hardwareHash==b.hardwareHash&&a.samplingHash==b.samplingHash&&
 a.quant==b.quant&&a.context==b.context&&a.maxTokens==b.maxTokens;
}
Result Evaluate(const Run&r,const Economics&e){
 Result o{}; o.tokens=r.generatedTokens;
 if(r.exitCode==0)o.gates|=G_EXIT; if(r.generatedTokens)o.gates|=G_TOKENS;
 if(r.argmaxParity&&r.numericParity)o.gates|=G_PARITY;
 if(r.backendAttested)o.gates|=G_BACKEND;
 if(r.selected&&r.selected==r.executed)o.gates|=G_SEL_EXE;
 if(!r.workerFailures)o.gates|=G_WORKERS;
 if(r.moeLayers&&r.submits==2*r.moeLayers&&r.waits==2*r.moeLayers&&
    r.d2hPartials==2*r.moeLayers)o.gates|=G_GEOMETRY;
 if(r.energyMilliJ)o.gates|=G_ENERGY; if(r.qualityPass)o.gates|=G_QUALITY;
 double sec=r.wallNs/1e9, kwh=r.energyMilliJ/3.6e9;
 o.tps=Safe((double)r.generatedTokens,sec);
 o.whPerToken=Safe(kwh*1000.0,(double)r.generatedTokens);
 o.energyUsdPer1m=Safe(kwh*e.electricityUsdPerKwh,(double)r.generatedTokens)*1e6;
 double hourly=e.usefulLifeHours>0?e.hardwareCapexUsd/e.usefulLifeHours:0.0;
 o.amortUsdPer1m=Safe(sec/3600.0*hourly,(double)r.generatedTokens)*1e6;
 o.storageHostUsdPer1m=Safe(sec/3600.0*e.storageHostUsdPerHour,
                            (double)r.generatedTokens)*1e6;
 o.usdPer1m=o.energyUsdPer1m+o.amortUsdPer1m+o.storageHostUsdPer1m;
 o.h2dBytesPerToken=Safe((double)r.h2dBytes,(double)r.generatedTokens);
 o.d2hBytesPerToken=Safe((double)r.d2hBytes,(double)r.generatedTokens);
 o.idleJoinPct=r.wallNs?100.0*(double)r.joinWaitNs/(double)r.wallNs:0.0;
 uint32_t need=G_EXIT|G_TOKENS|G_PARITY|G_BACKEND|G_SEL_EXE|G_WORKERS|
               G_GEOMETRY|G_ENERGY|G_QUALITY;
 o.authority=((o.gates&need)==need)?1:0; return o;
}
}} 
