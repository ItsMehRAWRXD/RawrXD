#include "Deep2DeepSeekRuntime.hpp"
#include <cstring>

namespace Deep2 { namespace dsv3 {
bool ValidateConfig(const Config&c){
    return c.layers>0 && c.routedExperts>0 && c.topK>0 && c.topK<=MAX_TOPK &&
           c.sharedExperts<=8 && c.hidden>0 && c.moeHidden>0 &&
           c.prefillChunk>0 && c.contextMax>=c.prefillChunk;
}
void Init(State&s,const Config&c,const Hooks&h){
    std::memset(&s,0,sizeof(s)); s.cfg=c; s.hooks=h;
}
void BeginToken(State&s){
    s.tick++; s.metrics=TokenMetrics{}; s.predictedFinish[0]=s.predictedFinish[1]=0;
}
void BeginLayer(State&s){ s.predictedFinish[0]=s.predictedFinish[1]=0; }
void FinishToken(State&s,uint64_t commit,uint64_t join,uint64_t reload){
    s.metrics.tokenCommitNs=commit; s.metrics.joinWaitNs=join; s.metrics.reloadBytes=reload;
}
}} 
