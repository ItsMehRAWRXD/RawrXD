#pragma once
/* Deep2 DeepSeek V3/R1 no-dep planning seam. No model-quality changes. */
#include <cstdint>
#include <cstddef>

namespace Deep2 { namespace dsv3 {

enum { MAX_TOPK=16, MAX_PREFETCH=32, MAX_TIERS=3 };
enum Tier : uint8_t { TIER_VRAM=0, TIER_RAM=1, TIER_MMAP=2 };
enum QuantClass : uint8_t { Q_UNKNOWN=0, Q_LOW=1, Q_SAFE=2, Q_HIGH=3 };

struct Config {
    uint32_t layers, routedExperts, topK, sharedExperts, hidden, moeHidden;
    uint32_t contextMax, prefillChunk;
};
struct RoutedExpert { int32_t id; float weight; uint64_t bytes; uint8_t resident, stick; };
struct Route {
    RoutedExpert x[MAX_TOPK]; uint32_t n;
};
struct ExpertStat {
    uint32_t layer, expert; uint64_t hits, misses, lastTick, meanNs[2];
    uint32_t heatPpm, confidencePpm;
};
struct KvPlan {
    uint32_t context, hotTokens, warmTokens; uint8_t hotTier, warmTier, coldTier;
};
struct MtpPlan { uint32_t draftTokens, verifyBatch; uint8_t enabled; };
struct PrefillPlan { uint32_t totalTokens, chunkTokens, chunks; };
struct TokenMetrics {
    uint64_t tokenCommitNs, h2dBytes, joinWaitNs, reloadBytes;
    uint32_t selected, executed, prefetches, sharedPinned;
};
typedef uint64_t (*CostFn)(void*,unsigned,int,uint64_t,int);
typedef unsigned (*AssignFn)(void*,int,uint64_t,int);
typedef int (*ResidentFn)(void*,uint32_t,int,unsigned*);
typedef int (*PrefetchFn)(void*,uint32_t,int,unsigned);

struct Hooks {
    void* ctx; CostFn cost; AssignFn assign; ResidentFn resident; PrefetchFn prefetch;
};
struct State {
    static const uint32_t STAT_CAP=1024;
    Config cfg; Hooks hooks; ExpertStat stats[STAT_CAP]; uint32_t used;
    uint64_t tick; TokenMetrics metrics; uint64_t predictedFinish[2];
};

bool ValidateConfig(const Config& c);
void Init(State& s,const Config& c,const Hooks& h);
bool PreserveRoute(const int32_t* ids,const float* weights,const uint64_t* bytes,
                   uint32_t n,Route& out);
void BeginToken(State& s);
void BeginLayer(State& s);
void AssignRoute(State& s,uint32_t layer,Route& r);
void ObserveExpert(State& s,uint32_t layer,int expert,unsigned gpu,uint64_t ns,int hit);
uint32_t PlanPrefetch(State& s,uint32_t layer,const Route& r,int32_t* out,uint32_t cap);
KvPlan PlanKv(uint32_t context,uint32_t hotBudgetTokens,uint32_t warmBudgetTokens);
PrefillPlan PlanPrefill(const State& s,uint32_t tokens);
MtpPlan PlanMtp(uint32_t remaining,uint32_t maxDraft,uint32_t verifyBatch,bool supported);
QuantClass QuantPolicy(uint32_t sensitivityPpm,uint32_t outlierPpm);
uint64_t ScoreResidency(const ExpertStat& st,uint64_t bytes,uint64_t reloadNs);
void FinishToken(State& s,uint64_t commitNs,uint64_t joinWaitNs,uint64_t reloadBytes);
}} // namespace
