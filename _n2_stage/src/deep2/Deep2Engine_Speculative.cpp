#include "Deep2Engine.h"
#include "Deep2DualGpuRowSplit.hpp"
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>

extern std::atomic<uint32_t> g_strictGpuViolations;

namespace Deep2 {
namespace {
inline float specSilu(float x) {
    return x/(1.0f+std::exp(-x));
}
inline bool finiteAll(const float* p,size_t n) {
    if(!p) return false;
    for(size_t i=0;i<n;++i) if(!std::isfinite(p[i])) return false;
    return true;
}
inline void softmaxLocal(float* x,size_t n) {
    float m=x[0];
    for(size_t i=1;i<n;++i) m=std::max(m,x[i]);
    double s=0.0;
    for(size_t i=0;i<n;++i){x[i]=std::exp(x[i]-m);s+=x[i];}
    const float inv=s>0.0?float(1.0/s):0.0f;
    for(size_t i=0;i<n;++i)x[i]*=inv;
}
inline int greedyArgmax(const float* p,size_t n) {
    if(!p||!n) return -1;
    size_t best=0;
    for(size_t i=1;i<n;++i) if(p[i]>p[best]) best=i;
    return (int)best;
}

uint32_t selfDraftDepth(const ModelWeights& m,uint32_t overrideDepth) {
    uint32_t d=overrideDepth;
    if(!d) {
        d=8;
        if(const char* e=std::getenv("DEEP2_SELF_DRAFT_LAYERS")) {
            const long v=std::strtol(e,nullptr,10);
            if(v>0) d=(uint32_t)v;
        }
    }
    if(m.numLayers<=1) return 0;
    return std::max<uint32_t>(
        1,std::min<uint32_t>(d,(uint32_t)m.numLayers-1));
}
}

bool Deep2Engine::proposeSelfSpeculativeGreedy(
    const float* currentHidden,size_t maxDraft,
    std::vector<int32_t>& proposals,uint32_t draftLayersOverride)
{
    proposals.clear();
    if(!currentHidden||!kvCache||!deterministicGreedy_||
       maxDraft==0||maxDraft>4||modelWeights.isMoE||modelWeights.useMLA)
        return false;

    const uint32_t depth=selfDraftDepth(modelWeights,draftLayersOverride);
    if(!depth) return false;

    // First proposal is exact: it comes from the current FULL target hidden.
    specWs_.logits.resize(modelWeights.vocabSize);
    float* lg=specWs_.logits.data();
    computeLogits(currentHidden,lg);
    int tok=greedyArgmax(lg,modelWeights.vocabSize);
    if(tok<0) return false;
    proposals.push_back(tok);
    if(maxDraft==1) return true;

    const size_t base=kvCache->currentLength();
    KVSpecTransaction tx(*kvCache);
    specWs_.hidden.resize(modelWeights.hiddenDim);
    float* h=specWs_.hidden.data();

    while(proposals.size()<maxDraft) {
        const int prev=proposals.back();
        if(!embedToken(prev,h)) {
            tx.rollback(); return false;
        }

        // Draft only the first D target layers. Those layers see the exact
        // committed KV prefix and previously-drafted shallow KV positions.
        const size_t seq=kvCache->currentLength()+1;
        try {
            for(uint32_t l=0;l<depth;++l) {
                forwardLayer(l,h,layerOut,seq);
                std::memcpy(
                    h,layerOut,modelWeights.hiddenDim*sizeof(float));
            }
        } catch(...) {
            tx.rollback(); return false;
        }
        if(!kvCache->advance()) {
            tx.rollback(); return false;
        }

        computeLogits(h,lg);
        tok=greedyArgmax(lg,modelWeights.vocabSize);
        if(tok<0) {
            tx.rollback(); return false;
        }
        proposals.push_back(tok);
    }

    // Draft KV is never authoritative.
    tx.rollback();
    return !proposals.empty() && kvCache->currentLength()==base;
}

bool Deep2Engine::buildAdaptiveSpeculativeProposals(
    const float* currentHidden,size_t remaining,
    std::vector<int32_t>& proposals)
{
    const auto __t0=std::chrono::steady_clock::now();
    proposals.clear();
    if(!medusaDecoder_||!currentHidden||remaining<2)
        return false;

    const uint32_t win=std::min<uint32_t>(
        medusaDecoder_->suggestedWindowByMeasuredCost(),
        (uint32_t)std::min<size_t>(4,remaining-1));
    if(!win) return false;

    std::vector<int32_t> self;
    if(!proposeSelfSpeculativeGreedy(
            currentHidden,win,self,
            medusaDecoder_->suggestedSelfDraftLayers()))
        return false;

    std::vector<int32_t> ng=medusaDecoder_->propose();
    if(ng.size()>win) ng.resize(win);

    // n-gram may be excellent for code/repeated structure, but it must at
    // least agree with the exact first target token before being preferred.
    if(!ng.empty()&&!self.empty()&&ng[0]==self[0]&&ng.size()>=2) {
        size_t consensus=1;
        while(consensus<ng.size()&&consensus<self.size()&&
              ng[consensus]==self[consensus])
            ++consensus;

        // Strong consensus: keep the longer n-gram continuation. Weak
        // consensus: use self-draft, whose first token is target-exact.
        if(consensus>=2 || medusaDecoder_->stats.exact.acceptanceEwma>=0.80) {
            proposals=std::move(ng);
            ++medusaDecoder_->stats.exact.ngramDraftWindows;
            if(medusaDecoder_) {
                medusaDecoder_->stats.exact.proposalNs += (uint64_t)
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now()-__t0).count();
            }
            return true;
        }
    }

    proposals=std::move(self);
    ++medusaDecoder_->stats.exact.selfDraftWindows;
    if(medusaDecoder_) {
        medusaDecoder_->stats.exact.proposalNs += (uint64_t)
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now()-__t0).count();
    }
    return !proposals.empty();
}

bool Deep2Engine::computeGreedyTop1Batch(
    const float* hiddenBatch,size_t count,int32_t* outTokens)
{
    if(!hiddenBatch||!outTokens||count==0||count>4||
       !vulkanInitialized_||vulkanDevices_.size()<2||
       modelWeights.lmHead.type!=(int)GGMLType::GGML_TYPE_Q4_K)
        return false;
    const size_t H=modelWeights.hiddenDim;
    auto& norm=specWs_.norm;
    norm.resize(count*H);
    for(size_t b=0;b<count;++b)
        RMSNormW(modelWeights.finalNorm,hiddenBatch+b*H,
                 norm.data()+b*H,H,modelWeights.normEps);
    std::vector<uint32_t> tok(count);
    std::vector<float> val(count);
    const uint64_t epoch=kvCache?kvCache->currentLength():0;
    if(!Deep2RunDualGpuRowSplitBatchTop1(
            *vulkanDevices_[0],*vulkanDevices_[1],modelWeights.lmHead,
            norm.data(),(uint32_t)count,tok.data(),val.data(),epoch))
        return false;
    for(size_t b=0;b<count;++b) outTokens[b]=(int32_t)tok[b];
    if(medusaDecoder_) ++medusaDecoder_->stats.exact.gpuTop1Batches;
    return true;
}

bool Deep2Engine::trySpecRmsNormBatch(
    const WeightTensor& w,const float* in,float* out,
    size_t width,size_t count)
{
    if(!in||!out||!w.data||w.type!=(int)GGMLType::GGML_TYPE_F32||
       width>UINT32_MAX||count==0||count>4)
        return false;
    auto* vc=getVulkanComputeSlot(0);
    if(!vc) return false;
    const bool ok=vc->RunSpecRmsNormHostBatch(
        in,(const float*)w.data,out,(uint32_t)width,(uint32_t)count,
        modelWeights.normEps,kvCache?kvCache->currentLength():0);
    if(ok&&medusaDecoder_) ++medusaDecoder_->stats.exact.gpuBatchNormOps;
    return ok;
}

bool Deep2Engine::trySpecSwiGLUBatch(
    const float* gate,const float* up,float* out,size_t width,size_t count)
{
    auto* vc=getVulkanComputeSlot(0);
    if(!vc||!gate||!up||!out||width>UINT32_MAX||count==0||count>4)
        return false;
    const bool ok=vc->RunSpecSwiGLUHostBatch(
        gate,up,out,(uint32_t)width,(uint32_t)count,
        kvCache?kvCache->currentLength():0);
    if(ok&&medusaDecoder_) ++medusaDecoder_->stats.exact.gpuBatchSwiGLUOps;
    return ok;
}

void Deep2Engine::specKvMirrorReset() {
    specKvMirrorCommittedLen_.assign(modelWeights.numLayers,0);
    if(auto* vc=getVulkanComputeSlot(0)) vc->ResetSpecKvMirror();
}

void Deep2Engine::specKvMirrorCommit(size_t newLen) {
    if(specKvMirrorCommittedLen_.size()!=modelWeights.numLayers)
        specKvMirrorCommittedLen_.assign(modelWeights.numLayers,0);
    for(auto& n:specKvMirrorCommittedLen_)
        n=std::max(n,newLen);
}

bool Deep2Engine::trySpecAttentionBatch(
    size_t layer,const float* q,const float* k,const float* v,float* out,
    size_t basePos,size_t count)
{
    if(!kvCache||!q||!k||!v||!out||count==0||count>4||
       layer>=modelWeights.numLayers)
        return false;
    auto* vc=getVulkanComputeSlot(0);
    if(!vc) return false;
    const size_t NK=modelWeights.numKVHeads;
    const size_t HD=modelWeights.headDim;
    const size_t KD=NK*HD;
    const size_t seq=basePos+count;
    if(!NK||!HD||seq>UINT32_MAX) return false;
    if(specKvMirrorCommittedLen_.size()!=modelWeights.numLayers)
        specKvMirrorCommittedLen_.assign(modelWeights.numLayers,0);
    if(!vc->EnsureSpecKvMirror(
            (uint32_t)modelWeights.numLayers,(uint32_t)NK,(uint32_t)HD,
            (uint32_t)config.maxSeqLen))
        return false;

    size_t synced=specKvMirrorCommittedLen_[layer];
    if(synced>basePos) synced=basePos;
    if(synced<basePos) {
        const size_t miss=basePos-synced;
        auto& kp=specWs_.kPacked;auto& vp=specWs_.vPacked;
        kp.resize(miss*NK*HD);vp.resize(miss*NK*HD);
        for(size_t t=0;t<miss;++t) {
            for(size_t h=0;h<NK;++h) {
                const float* ks=kvCache->keyPtr(layer,h,synced+t);
                const float* vs=kvCache->valuePtr(layer,h,synced+t);
                if(!ks||!vs) return false;
                std::memcpy(kp.data()+(t*NK+h)*HD,ks,HD*sizeof(float));
                std::memcpy(vp.data()+(t*NK+h)*HD,vs,HD*sizeof(float));
            }
        }
        if(!vc->UploadSpecKvRange(
                (uint32_t)layer,(uint32_t)synced,(uint32_t)miss,
                kp.data(),vp.data()))
            return false;
        if(medusaDecoder_) {
            ++medusaDecoder_->stats.exact.kvMirrorPrefixUploads;
            medusaDecoder_->stats.exact.kvMirrorDeltaTokens+=miss;
        }
    }

    if(!vc->UploadSpecKvRange(
            (uint32_t)layer,(uint32_t)basePos,(uint32_t)count,k,v))
        return false;
    const bool ok=vc->RunSpecAttentionResident(
        (uint32_t)layer,q,out,
        (uint32_t)modelWeights.numHeads,(uint32_t)NK,(uint32_t)HD,
        (uint32_t)seq,(uint32_t)basePos,(uint32_t)count,
        kvCache->currentLength());
    if(ok&&medusaDecoder_) ++medusaDecoder_->stats.exact.gpuBatchAttentionOps;
    if(ok&&medusaDecoder_) ++medusaDecoder_->stats.exact.kvMirrorResidentAttn;
    return ok;
}

bool Deep2Engine::trySpecColumnSplitBatch(
    const WeightTensor& wt,const float* in,float* out,size_t count)
{
    if(vulkanDevices_.size()<2||!in||!out||count==0||count>4) return false;
    // Deep2RunDualGpuColumnSplitBatch4 only materializes Q4_K column
    // slices (q4kColumnSlices returns nullptr for every other type).
    // Fail fast for Q6_K (type 14) oproj/down weights so the caller's
    // LinearWBatch4 fallback routes them through the zero-copy
    // dual-row-split lane instead of a wasted column-split attempt.
    if(wt.type!=(int)GGMLType::GGML_TYPE_Q4_K) return false;
    const bool ok=Deep2RunDualGpuColumnSplitBatch4(
        *vulkanDevices_[0],*vulkanDevices_[1],wt,in,out,
        (uint32_t)count,kvCache?kvCache->currentLength():0);
    if(ok&&medusaDecoder_) ++medusaDecoder_->stats.exact.dualColumnSplitOps;
    return ok;
}

bool Deep2Engine::trySpecQ4KGroup(
    const WeightTensor* const* w,float* const* out,size_t weightCount,
    const float* input,size_t count)
{
    if(vulkanDevices_.size()<2||!w||!out||!input||
       weightCount<2||weightCount>3||count==0||count>4)
        return false;
    return Deep2RunDualGpuRowSplitBatchGroupQ4K(
        *vulkanDevices_[0],*vulkanDevices_[1],
        w,out,weightCount,input,(uint32_t)count,
        kvCache?kvCache->currentLength():0);
}

bool Deep2Engine::forwardSpeculativeBlock(
    const int32_t* tokenIds,size_t count,size_t basePos,float* finalHiddenBatch)
{
    if(!tokenIds||!finalHiddenBatch||count==0||count>4||
       !modelWeights.loaded||modelWeights.isMoE||modelWeights.useMLA||
       !kvCache||!config.useKVCache)
        return false;
    const size_t H=modelWeights.hiddenDim;
    const size_t NH=modelWeights.numHeads;
    const size_t NK=modelWeights.numKVHeads;
    const size_t HD=modelWeights.headDim;
    const size_t KD=NK*HD;
    const size_t I=modelWeights.intermediateDim;
    const size_t qDim=NH*HD;
    if(!H||!NH||!NK||!HD||!I||NH%NK!=0||
       basePos+count>kvCache->capacity()||
       kvCache->currentLength()<basePos+count)
        return false;

    auto& ws=specWs_;
    if(count > SIZE_MAX / H) return false;
    if(count > SIZE_MAX / KD) return false;
    if(count > SIZE_MAX / I) return false;
    ws.hidden.resize(count*H);
    ws.norm.resize(count*H);
    ws.q.resize(count*H);
    ws.k.resize(count*KD);
    ws.v.resize(count*KD);
    ws.attn.resize(count*H);
    ws.proj.resize(count*H);
    ws.gate.resize(count*I);
    ws.up.resize(count*I);
    ws.down.resize(count*H);
    float* hidden=ws.hidden.data();
    float* norm=ws.norm.data();
    float* q=ws.q.data();
    float* k=ws.k.data();
    float* v=ws.v.data();
    float* attn=ws.attn.data();
    float* proj=ws.proj.data();
    float* gate=ws.gate.data();
    float* up=ws.up.data();
    float* down=ws.down.data();
    std::fprintf(stderr,"FSB_EMBED_BEGIN B=%zu\n",count); std::fflush(stderr);
    if(!embedTokensBatch(tokenIds,count,hidden))
        return false;
    std::fprintf(stderr,"FSB_EMBED_OK\n"); std::fflush(stderr);

    const size_t group=NH/NK;
    for(size_t layer=0;layer<modelWeights.numLayers;++layer) {
        std::fprintf(stderr,"FSB_L%zu_ENTER\n",layer); std::fflush(stderr);
        const LayerWeights& lw=modelWeights.layers[layer];
        if(!lw.attnNorm.data||!lw.ffnNorm.data||
           !lw.wq.data||!lw.wk.data||!lw.wv.data||
           (!lw.wo.data&&!lw.attnO.data)||
           !lw.wGate.data||!lw.wUp.data||!lw.wDown.data)
            return false;

        std::fprintf(stderr,"FSB_L%zu_ATTN_NORM_BEGIN\n",layer); std::fflush(stderr);
        // STEP1: GPU RMSNorm re-enabled
        if(!trySpecRmsNormBatch(lw.attnNorm,hidden,norm,H,count)) {
            for(size_t b=0;b<count;++b)
                RMSNormW(lw.attnNorm,hidden+b*H,
                         norm+b*H,H,modelWeights.normEps);
        }
        std::fprintf(stderr,"FSB_L%zu_ATTN_NORM_END\n",layer); std::fflush(stderr);

        const float* bq=lw.bq.data
            ? reinterpret_cast<const float*>(lw.bq.data):nullptr;
        const float* bk=lw.bk.data
            ? reinterpret_cast<const float*>(lw.bk.data):nullptr;
        const float* bv=lw.bv.data
            ? reinterpret_cast<const float*>(lw.bv.data):nullptr;
        std::fprintf(stderr,"FSB_L%zu_QKV_BEGIN\n",layer); std::fflush(stderr);
        const WeightTensor* qkvW[3]={&lw.wq,&lw.wk,&lw.wv};
        float* qkvO[3]={q,k,v};
        try{
            LinearWBatch4(lw.wq,norm,count,bq,q,qDim);
            LinearWBatch4(lw.wk,norm,count,bk,k,KD);
            LinearWBatch4(lw.wv,norm,count,bv,v,KD);
        }catch(const std::exception& e){
            std::fprintf(stderr,"FATAL_LINEAR_QKV layer=%zu exc=%s\n",layer,e.what()); std::fflush(stderr);
            vulkanStrictViolation_=true;
            g_strictGpuViolations.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        std::fprintf(stderr,"FSB_L%zu_QKV_END\n",layer); std::fflush(stderr);

        for(size_t b=0;b<count;++b) {
            float* qb=q+b*H;
            float* kb=k+b*KD;
            std::fprintf(stderr,"FSB_L%zu_ROPE_KV_BEGIN b=%zu\n",layer,b); std::fflush(stderr);
            if(lw.attnQNorm.data) {
                for(size_t h=0;h<NH;++h)
                    RMSNormW(lw.attnQNorm,qb+h*HD,qb+h*HD,
                             HD,modelWeights.normEps);
            }
            if(lw.attnKNorm.data) {
                for(size_t h=0;h<NK;++h)
                    RMSNormW(lw.attnKNorm,kb+h*HD,kb+h*HD,
                             HD,modelWeights.normEps);
            }
            if(config.useRoPE)
                applyRoPE(qb,kb,HD,NH,NK,basePos+b,
                          ropeThetaForLayer(layer),
                          modelWeights.ropeScaling>0.0f
                              ? modelWeights.ropeScaling:1.0f);

            for(size_t h=0;h<NK;++h) {
                float* kd=kvCache->keyPtr(layer,h,basePos+b);
                float* vd=kvCache->valuePtr(layer,h,basePos+b);
                if(!kd||!vd) return false;
                std::memcpy(kd,kb+h*HD,HD*sizeof(float));
                std::memcpy(vd,v+b*KD+h*HD,HD*sizeof(float));
            }
        }
        std::fprintf(stderr,"FSB_L%zu_ROPE_KV_END\n",layer); std::fflush(stderr);

        std::fprintf(stderr,"FSB_L%zu_ATTN_BEGIN\n",layer); std::fflush(stderr);
        const float scale=1.0f/std::sqrt((float)HD);
        if(!trySpecAttentionBatch(layer,q,k,v,attn,basePos,count))
        for(size_t b=0;b<count;++b) {
            const size_t attend=basePos+b+1;
            float* out=attn+b*H;
            std::fill(out,out+H,0.0f);
            ws.scores.resize(attend);
            float* scores=ws.scores.data();
            for(size_t h=0;h<NH;++h) {
                const size_t kh=h/group;
                const float* qq=q+b*H+h*HD;
                for(size_t t=0;t<attend;++t) {
                    const float* kk=kvCache->keyPtr(layer,kh,t);
                    if(!kk) return false;
                    double dot=0.0;
                    for(size_t d=0;d<HD;++d) dot+=(double)qq[d]*kk[d];
                    scores[t]=(float)dot*scale;
                }
                softmaxLocal(scores,attend);
                float* ho=out+h*HD;
                for(size_t t=0;t<attend;++t) {
                    const float* vv=kvCache->valuePtr(layer,kh,t);
                    if(!vv) return false;
                    const float a=scores[t];
                    for(size_t d=0;d<HD;++d) ho[d]+=a*vv[d];
                }
            }
        }
        std::fprintf(stderr,"FSB_L%zu_ATTN_END\n",layer); std::fflush(stderr);

        const WeightTensor& wo=lw.wo.data?lw.wo:lw.attnO;
        std::fprintf(stderr,"FSB_L%zu_OPROJ_BEGIN\n",layer); std::fflush(stderr);
        // ISOLATION STEP 4: ColumnSplit re-enabled
        if(!trySpecColumnSplitBatch(wo,attn,proj,count))
            try{
                LinearWBatch4(wo,attn,count,nullptr,proj,H);
            }catch(const std::exception& e){
                std::fprintf(stderr,"FATAL_LINEAR_OPROJ layer=%zu exc=%s\n",layer,e.what()); std::fflush(stderr);
                vulkanStrictViolation_=true;
                g_strictGpuViolations.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
        std::fprintf(stderr,"FSB_L%zu_OPROJ_END\n",layer); std::fflush(stderr);
        for(size_t i=0;i<count*H;++i) hidden[i]+=proj[i];

        std::fprintf(stderr,"FSB_L%zu_FFN_NORM_BEGIN\n",layer); std::fflush(stderr);
        // STEP1: GPU RMSNorm re-enabled
        if(!trySpecRmsNormBatch(lw.ffnNorm,hidden,norm,H,count)) {
            for(size_t b=0;b<count;++b)
                RMSNormW(lw.ffnNorm,hidden+b*H,
                         norm+b*H,H,modelWeights.normEps);
        }
        std::fprintf(stderr,"FSB_L%zu_FFN_NORM_END\n",layer); std::fflush(stderr);
        const WeightTensor* guW[2]={&lw.wGate,&lw.wUp};
        float* guO[2]={gate,up};
        std::fprintf(stderr,"FSB_L%zu_FFN_BEGIN\n",layer); std::fflush(stderr);
        try{
            LinearWBatch4(lw.wGate,norm,count,nullptr,gate,I);
            LinearWBatch4(lw.wUp  ,norm,count,nullptr,up  ,I);
        }catch(const std::exception& e){
            std::fprintf(stderr,"FATAL_LINEAR_FFN layer=%zu exc=%s\n",layer,e.what()); std::fflush(stderr);
            vulkanStrictViolation_=true;
            g_strictGpuViolations.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        std::fprintf(stderr,"FSB_L%zu_SWIGLU_BEGIN\n",layer); std::fflush(stderr);
        if(!trySpecSwiGLUBatch(gate,up,gate,I,count))
            for(size_t i=0;i<count*I;++i)
                gate[i]=specSilu(gate[i])*up[i];
        std::fprintf(stderr,"FSB_L%zu_SWIGLU_END\n",layer); std::fflush(stderr);
        std::fprintf(stderr,"FSB_L%zu_DOWN_BEGIN\n",layer); std::fflush(stderr);
        // ISOLATION STEP 4: ColumnSplit re-enabled
        if(!trySpecColumnSplitBatch(lw.wDown,gate,down,count))
            try{
                LinearWBatch4(lw.wDown,gate,count,nullptr,down,H);
            }catch(const std::exception& e){
                std::fprintf(stderr,"FATAL_LINEAR_DOWN layer=%zu exc=%s\n",layer,e.what()); std::fflush(stderr);
                vulkanStrictViolation_=true;
                g_strictGpuViolations.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
        std::fprintf(stderr,"FSB_L%zu_DOWN_END\n",layer); std::fflush(stderr);

        for(size_t i=0;i<count*H;++i) hidden[i]+=down[i];
        std::fprintf(stderr,"FSB_L%zu_FFN_END\n",layer); std::fflush(stderr);
        if(!finiteAll(hidden,count*H)) return false;
        std::fprintf(stderr,"FSB_L%zu_EXIT\n",layer); std::fflush(stderr);
    }

    std::fprintf(stderr,"FSB_COPY_HIDDEN\n"); std::fflush(stderr);
    std::memcpy(finalHiddenBatch,hidden,count*H*sizeof(float));

    std::fprintf(stderr,"FSB_EXIT_OK\n"); std::fflush(stderr);

    return true;
}

static uint32_t deep2SpecWindowCap() noexcept {
    const char* e=std::getenv("DEEP2_SPEC_WINDOW_CAP");
    if(!e||!*e) return 4u;
    const long v=std::strtol(e,nullptr,10);
    return (uint32_t)std::max<long>(1,std::min<long>(4,v));
}

bool Deep2Engine::prepareSpecWindow(
    const float* currentHidden,size_t remaining,
    PreparedSpecWindow& out)
{
    out.clear();
    if(!currentHidden||remaining<2||!medusaDecoder_) return false;
    std::vector<int32_t> p;
    if(!buildAdaptiveSpeculativeProposals(currentHidden,remaining,p)||
       p.empty())
        return false;
    const uint32_t cap=deep2SpecWindowCap();
    if(p.size()>cap) p.resize(cap);
    out.proposals=std::move(p);
    out.window=(uint32_t)out.proposals.size();
    out.generation=++specGeneration_;
    out.ready=true;
    ++medusaDecoder_->stats.exact.pipelinePrepareWindows;
    medusaDecoder_->stats.exact.preparedSpecTokens += out.window;
    return true;
}
bool Deep2Engine::verifySpeculativeGreedyWindow(
    float* currentHidden,
    const std::vector<int32_t>& proposals,
    size_t maxEmit,
    std::vector<int32_t>& verified)
{
    std::fprintf(stderr,"VSGW_ENTER proposals=%zu maxEmit=%zu\n",proposals.size(),maxEmit); std::fflush(stderr);
    const size_t verifiedBefore=verified.size();
    const auto __v0=std::chrono::steady_clock::now();
    verified.clear();
    if(!currentHidden||proposals.empty()||proposals.size()>4||
       maxEmit==0||!deterministicGreedy_||!kvCache)
        return false;

    const size_t B=std::min<size_t>(proposals.size(),maxEmit);
    if(B==0) return false;

    // First proposal can be rejected before running any speculative block.
    specWs_.logits.resize(modelWeights.vocabSize);
    float* currentLogits=specWs_.logits.data();
    std::fprintf(stderr,"VSGW_LOGITS_0_BEGIN\n"); std::fflush(stderr);
    computeLogits(currentHidden,currentLogits);
    const int first=greedyArgmax(currentLogits,modelWeights.vocabSize);
    std::fprintf(stderr,"VSGW_LOGITS_0_END first=%d\n",first); std::fflush(stderr);
    if(first<0) return false;
    if(proposals[0]!=first) {
        verified.push_back(first);
        if(medusaDecoder_)
            ++medusaDecoder_->stats.exact.pipelineVerifyWindows;
        if(medusaDecoder_) {
            auto& c=medusaDecoder_->stats.exact;
            ++c.verifiedTargetWindows;
            const uint64_t acceptedNow=
                verified.size()>=verifiedBefore
                    ? (uint64_t)(verified.size()-verifiedBefore) : 0ull;
            c.acceptedVerifiedTokens += acceptedNow;
            if(!acceptedNow) ++c.rejectedSpecWindows;
            ++medusaDecoder_->stats.rejected;
            ++medusaDecoder_->stats.exact.rejectedTokens;
            ++medusaDecoder_->stats.exact.verifiedOutputTokens;
        }
        return true;
    }

    const size_t base=kvCache->currentLength();
    std::fprintf(stderr,"VSGW_KV_BASE=%zu B=%zu\n",base,B); std::fflush(stderr);
    KVSpecTransaction tx(*kvCache);
    std::fprintf(stderr,"VSGW_ADVANCE_BY_BEGIN B=%zu\n",B); std::fflush(stderr);
    if(!kvCache->advanceBy(B)) { std::fprintf(stderr,"VSGW_ADVANCE_BY_FAIL\n"); std::fflush(stderr); return false; }
    std::fprintf(stderr,"VSGW_ADVANCE_BY_OK kv=%zu\n",kvCache->currentLength()); std::fflush(stderr);

    if(B > SIZE_MAX / modelWeights.hiddenDim) return false;
    specWs_.hidden.resize(B*modelWeights.hiddenDim);
    float* hiddenBatch=specWs_.hidden.data();
    const auto __b0=std::chrono::steady_clock::now();
    std::fprintf(stderr,"VSGW_FORWARD_BLOCK_BEGIN B=%zu base=%zu\n",B,base); std::fflush(stderr);
    if(!forwardSpeculativeBlock(
            proposals.data(),
            B,base,hiddenBatch)) {
        std::fprintf(stderr,"VSGW_FORWARD_BLOCK_FAIL\n"); std::fflush(stderr);
        return false; // RAII rollback
    }
    std::fprintf(stderr,"VSGW_FORWARD_BLOCK_OK\n"); std::fflush(stderr);
    if(medusaDecoder_) {
        medusaDecoder_->stats.exact.targetBatchNs += (uint64_t)
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now()-__b0).count();
    }

    std::vector<int32_t> top1(B);
    std::fprintf(stderr,"VSGW_TOP1_BEGIN\n"); std::fflush(stderr);
    if(!computeGreedyTop1Batch(hiddenBatch,B,top1.data())) {
        std::fprintf(stderr,"VSGW_TOP1_FALLBACK\n"); std::fflush(stderr);
        // Exact fallback retains correctness; strict 85 authority will expose
        // zero GPU-top1 batches rather than silently minting the optimization.
        if(B > SIZE_MAX / modelWeights.vocabSize) return false;
        specWs_.logitsBatch.resize(B*modelWeights.vocabSize);
        computeLogitsBatch(hiddenBatch,B,specWs_.logitsBatch.data());
        for(size_t j=0;j<B;++j)
            top1[j]=greedyArgmax(
                specWs_.logitsBatch.data()+j*modelWeights.vocabSize,
                modelWeights.vocabSize);
    }
    std::fprintf(stderr,"VSGW_TOP1_END tok0=%d tok1=%d\n",(int)top1[0],B>1?(int)top1[1]:-1); std::fflush(stderr);

    size_t accepted=1; // proposal[0] matched current target logits
    int replacement=-1;
    for(size_t j=1;j<B;++j) {
        const int target=top1[j-1];
        if(target<0) return false;
        if(proposals[j]!=target) {
            replacement=target;
            break;
        }
        ++accepted;
    }

    verified.reserve(std::min(maxEmit,B+1));
    for(size_t j=0;j<accepted&&verified.size()<maxEmit;++j)
        verified.push_back(proposals[j]);

    if(accepted<B) {
        if(replacement<0) {
            replacement=top1[accepted-1];
        }
        if(verified.size()<maxEmit)
            verified.push_back(replacement);
    } else if(verified.size()<maxEmit) {
        const int bonus=top1[B-1];
        if(bonus<0) return false;
        verified.push_back(bonus);
    }

    if(!tx.commitAccepted(accepted)) { std::fprintf(stderr,"VSGW_COMMIT_FAIL\n"); std::fflush(stderr); return false; }
    std::fprintf(stderr,"VSGW_COMMIT_OK accepted=%zu\n",accepted); std::fflush(stderr);
    specKvMirrorCommit(base+accepted);
    std::fprintf(stderr,"VSGW_MIRROR_COMMIT_OK\n"); std::fflush(stderr);

    // currentHidden must describe the last KV-committed token. The final
    // replacement/bonus remains unforwarded, matching ordinary decode.
    std::memcpy(currentHidden,
                hiddenBatch+(accepted-1)*modelWeights.hiddenDim,
                modelWeights.hiddenDim*sizeof(float));

    if(medusaDecoder_)
        medusaDecoder_->recordVerification(B,accepted,verified.size());
    if(medusaDecoder_) {
        const uint64_t __verifyNs=(uint64_t)
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now()-__v0).count();
        medusaDecoder_->stats.exact.verifyNs += __verifyNs;
        medusaDecoder_->recordWindowCost(
            (uint32_t)B,(uint64_t)verified.size(),__verifyNs);
        ++medusaDecoder_->stats.exact.pipelineWindows;
    }

    return !verified.empty();
}

} // namespace Deep2

