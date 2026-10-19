#pragma once
/* Kimi cost/token authority — no third-party dependencies. */
#include <cstdint>
#include <cstdio>

namespace Deep2 { namespace kcost {
enum Gate : uint32_t {
 G_EXIT=1u<<0,G_TOKENS=1u<<1,G_PARITY=1u<<2,G_BACKEND=1u<<3,
 G_SEL_EXE=1u<<4,G_WORKERS=1u<<5,G_GEOMETRY=1u<<6,G_ENERGY=1u<<7,
 G_IDENTITY=1u<<8,G_QUALITY=1u<<9
};
struct Identity {
 uint64_t modelHash, promptHash, hardwareHash, samplingHash;
 uint32_t quant, context, maxTokens;
};
struct Economics {
 double electricityUsdPerKwh, hardwareCapexUsd, usefulLifeHours;
 double storageHostUsdPerHour;
};
struct Run {
 Identity id; uint64_t generatedTokens, wallNs, energyMilliJ;
 uint64_t h2dBytes,d2hBytes,reloadBytes,joinWaitNs,gpu0WorkNs,gpu1WorkNs;
 uint64_t selected,executed,submits,waits,moeLayers,d2hPartials,workerFailures;
 int exitCode; uint8_t argmaxParity,numericParity,backendAttested,qualityPass;
};
struct Result {
 uint32_t gates; double tps,whPerToken,usdPer1m,energyUsdPer1m;
 double amortUsdPer1m,storageHostUsdPer1m,h2dBytesPerToken,d2hBytesPerToken;
 double idleJoinPct; uint64_t tokens; uint8_t authority;
};
struct Comparison {
 Result deep2, baseline; double costAdvantagePct,tpsAdvantagePct;
 uint8_t comparable, deep2WinsCost;
};
Result Evaluate(const Run&,const Economics&);
bool SameIdentity(const Identity&,const Identity&);
Comparison Compare(const Run&,const Run&,const Economics&);
void Emit(FILE*,const char*,const Result&);
void EmitComparison(FILE*,const Comparison&);
}} 
