// ============================================================================
// Deep2Engine_GpuMoEMLA.cpp — Batch 10 dual-GPU row split + GPU MoE/MLA
// ============================================================================
#include "Deep2Engine.h"
#include "Deep2DualGpuRowSplit.hpp"
#include "Deep2GpuOverlapWitness.hpp"
#include "Deep2PeerDeviceGroup.hpp"
// RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001: these GPU authorities consume model
// weights directly and never route through LinearW().
#include "WeightConsumptionCensus.hpp"
#include "vulkan_compute.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <future>
#include <limits>
#include <stdexcept>
#include <vector>

namespace Deep2 {
namespace {

bool finiteVec(const float* p,size_t n) noexcept {
    if(!p) return false;
    for(size_t i=0;i<n;++i) if(!std::isfinite(p[i])) return false;
    return true;
}

bool fullView(const WeightTensor& wt,GpuWeightView& v) noexcept {
    if(wt.rows==0 || wt.rows>std::numeric_limits<uint32_t>::max())
        return false;
    return Deep2BuildGpuWeightView(
        wt,0,static_cast<uint32_t>(wt.rows),v);
}

void applyMlaRope(float* qFull,float* kPe,
                  size_t heads,size_t nope,size_t rope,
                  size_t pos,float theta,float scaling)
{
    if(!qFull||!kPe||!heads||!rope||(rope&1u)||
       !(theta>1.0f)||!(scaling>0.0f))
        throw std::runtime_error("MLA RoPE: invalid geometry");

    const float position=static_cast<float>(pos)/scaling;
    for(size_t pair=0;pair<rope/2;++pair){
        const size_t d=pair*2;
        const float freq=std::pow(
            theta,-static_cast<float>(d)/static_cast<float>(rope));
        const float angle=position*freq;
        const float cs=std::cos(angle);
        const float sn=std::sin(angle);

        for(size_t h=0;h<heads;++h){
            float* qr=qFull+h*(nope+rope)+nope;
            const float a=qr[d],b=qr[d+1];
            qr[d]=a*cs-b*sn;
            qr[d+1]=a*sn+b*cs;
        }

        const float a=kPe[d],b=kPe[d+1];
        kPe[d]=a*cs-b*sn;
        kPe[d+1]=a*sn+b*cs;
    }
}

} // namespace

bool Deep2Engine::tryVulkanHostGEMV(
    const WeightTensor& wt,const float* input,float* output,size_t outDim)
{
    if(!vulkanInitialized_||vulkanDevices_.empty()||
       !input||!output||!wt.data||wt.rows!=outDim||
       wt.rows==0||wt.cols==0||
       wt.rows>std::numeric_limits<uint32_t>::max()||
       wt.cols>std::numeric_limits<uint32_t>::max())
        return false;

    const uint64_t epoch=kvCache?kvCache->currentLength():0;

    // First preference: true simultaneous independent row partitions.
    if(vulkanDevices_.size()>=2 && wt.rows>=2){
        RowSplitReceipt r{};
        if(Deep2RunDualGpuRowSplit(
                *vulkanDevices_[0],*vulkanDevices_[1],
                wt,input,output,epoch,&r)){
            ++gpuFwd_.dualRowSplitOps;
            ++gpuFwd_.dualRowSlot[0];
            ++gpuFwd_.dualRowSlot[1];
            ++gpuFwd_.hostMergeOps;
            ++gpuFwd_.hostMaterializations; // explicit row-slice merge
            ++gpuFwd_.matDualRowSingle;
            gpuFwd_.dualArithmeticOverlapNs=
                std::max(gpuFwd_.dualArithmeticOverlapNs,
                         r.calibratedOverlapNs);
            return finiteVec(output,outDim);
        }
    }

    // One valid device is still a real GPU path; no fake two-stick claim.
    auto* g=getVulkanComputeSlot(0);
    if(!g){
        std::fprintf(stderr,"GEMV_SINGLE getVulkanComputeSlot(0)=null name=%s\n",wt.name.empty()?"null":wt.name.c_str()); std::fflush(stderr);
        return false;
    }
    GpuWeightView view{};
    if(!fullView(wt,view)){
        std::fprintf(stderr,"GEMV_SINGLE fullView failed name=%s\n",wt.name.empty()?"null":wt.name.c_str()); std::fflush(stderr);
        return false;
    }
    const char* wtn = wt.name.empty() ? "null" : wt.name.c_str();

    g->SetWorkEpoch(epoch);
    if(!g->EnsureScratch(30,wt.cols)){
        std::fprintf(stderr,"GEMV_SINGLE EnsureScratch(30,cols) failed name=%s cols=%zu\n",wtn,wt.cols); std::fflush(stderr);
        return false;
    }
    if(!g->EnsureScratch(31,wt.rows)){
        std::fprintf(stderr,"GEMV_SINGLE EnsureScratch(31,rows) failed name=%s rows=%zu\n",wtn,wt.rows); std::fflush(stderr);
        return false;
    }
    auto& x=g->Scratch(30);
    auto& y=g->Scratch(31);
    if(!g->UploadVector(x,input,wt.cols)){
        std::fprintf(stderr,"GEMV_SINGLE UploadVector failed name=%s\n",wtn); std::fflush(stderr);
        return false;
    }
    if(!g->DispatchWeight(view,x,y)){
        std::fprintf(stderr,"GEMV_SINGLE DispatchWeight failed name=%s type=%d rows=%u cols=%u bytes=%zu\n",wtn,view.type,view.rows,view.cols,view.bytes); std::fflush(stderr);
        return false;
    }
    if(!g->DownloadVector(y,output,wt.rows)){
        std::fprintf(stderr,"GEMV_SINGLE DownloadVector failed name=%s\n",wtn); std::fflush(stderr);
        return false;
    }

    ++gpuFwd_.hostMaterializations;
    ++gpuFwd_.matGemvSingleRoundTrip;
    bool fin=finiteVec(output,outDim);
    if(!fin) std::fprintf(stderr,"GEMV_SINGLE finiteVec failed name=%s\n",wtn), std::fflush(stderr);
    return fin;
}

bool Deep2Engine::tryVulkanHostGEMVBatch4(
    const WeightTensor& wt,const float* inputBatch,size_t count,
    float* outputBatch,size_t outDim)
{
    if(!vulkanInitialized_||vulkanDevices_.size()<2||
       !inputBatch||!outputBatch||count==0||count>4||
       wt.rows!=outDim||wt.type!=(int)GGMLType::GGML_TYPE_Q4_K)
        return false;
    const uint64_t epoch=kvCache?kvCache->currentLength():0;
    RowSplitReceipt r{};
    if(!Deep2RunDualGpuRowSplitBatch4(
            *vulkanDevices_[0],*vulkanDevices_[1],
            wt,inputBatch,outputBatch,(uint32_t)count,epoch,&r))
        return false;
    ++gpuFwd_.dualRowSplitOps;
    ++gpuFwd_.dualRowSlot[0];
    ++gpuFwd_.dualRowSlot[1];
    ++gpuFwd_.hostMergeOps;
    gpuFwd_.dualArithmeticOverlapNs=
        std::max(gpuFwd_.dualArithmeticOverlapNs,r.calibratedOverlapNs);
    return true;
}


bool Deep2Engine::tryVulkanHostGEMVGroup(
    const WeightTensor* const* weights,float* const* outputs,size_t count,
    const float* input,size_t inputCount,const char** rejectReason)
{
    // RAWRXD_LAYER0_ATTN_BISECT_001: every false return names its guard, so a
    // false result is attributable instead of indistinguishable from
    // "handled the operation but returned false later".
    if(rejectReason)*rejectReason="NONE";
    // RAWRXD_GPU_ROUTE_RECEIPT_001: every early return below is tallied, so a
    // guard that refuses is as visible as a dispatch that succeeds.
    NoteGroupedReject("ATTEMPT");
    if(!vulkanInitialized_) { if(rejectReason)*rejectReason="VULKAN_NOT_INITIALIZED"; NoteGroupedReject("VULKAN_NOT_INITIALIZED"); return false; }
    if(vulkanDevices_.size()<2){ if(rejectReason)*rejectReason="DEVICE_COUNT_LT_2"; NoteGroupedReject("DEVICE_COUNT_LT_2"); return false; }
    if(!weights||!outputs||!input){ if(rejectReason)*rejectReason="NULL_ARGUMENT"; NoteGroupedReject("NULL_ARGUMENT"); return false; }
    if(count<2||count>3){ if(rejectReason)*rejectReason="COUNT_OUT_OF_RANGE"; NoteGroupedReject("COUNT_OUT_OF_RANGE"); return false; }
    if(inputCount==0||inputCount>UINT32_MAX){ if(rejectReason)*rejectReason="INPUT_COUNT_INVALID"; NoteGroupedReject("INPUT_COUNT_INVALID"); return false; }

    const uint64_t epoch=kvCache?kvCache->currentLength():0;
    // RAWRXD_GPU_ROUTE_RECEIPT_001: count ENTRY before the dispatch so a route
    // that is attempted and refused is distinguishable from one never reached.
    ++routeReceipt_.groupedDualRowCalls;
    RowSplitReceipt r{};
    if(!Deep2RunDualGpuRowSplitGroup(
            *vulkanDevices_[0],*vulkanDevices_[1],
            weights,outputs,count,input,(uint32_t)inputCount,epoch,&r)){
        // The reason is computed here and was previously handed back to a
        // caller that discarded it, so a refusal was unattributable after the
        // fact. It is now also tallied by name.
        NoteGroupedReject(rejectReason?*rejectReason:"DUAL_ROW_SPLIT_GROUP_FAILED");
        if(rejectReason)*rejectReason="DUAL_ROW_SPLIT_GROUP_FAILED";
        return false;
    }

    ++gpuFwd_.dualRowSplitOps;
    ++gpuFwd_.dualRowSlot[0];
    ++gpuFwd_.dualRowSlot[1];
    ++gpuFwd_.hostMergeOps;
    ++gpuFwd_.hostMaterializations;
    ++gpuFwd_.matDualRowGroup; // grouped dual-row host round-trip
    gpuFwd_.dualArithmeticOverlapNs=
        std::max(gpuFwd_.dualArithmeticOverlapNs,r.calibratedOverlapNs);

    // RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001
    // Grouped dual-GPU QKV / gate+up is the second half of the attention and
    // FFN bypass: the caller only calls LinearW() on the FAILURE branch, so on
    // this success path none of these weights ever enter LinearW(). Each
    // grouped tensor is recorded by name.
    {
        using namespace rawrxd::deep2::weightcensus;
        for (size_t i = 0; i < count; ++i) {
            const WeightTensor* t = weights[i];
            if (!t || !t->data) continue;
            Event gev;
            gev.site = Site::GroupedGemm;
            gev.route = Route::Bypass;   // never entered LinearW on this path
            gev.tensor = t->name;
            gev.bytes = t->sizeBytes ? t->sizeBytes : t->numElements();
            gev.tokenEpoch = (uint32_t)epoch;
            WeightConsumptionCensus::instance().record(gev);
        }
    }
    return true;
}

bool Deep2Engine::computeMoEFFNGpu(

    size_t layer,const float* input,float* output)
{
    if(!vulkanInitialized_||vulkanDevices_.empty()||
       !input||!output||layer>=modelWeights.layers.size())
        return false;

    const LayerWeights& lw=modelWeights.layers[layer];
    const size_t H=modelWeights.hiddenDim;
    const size_t E=modelWeights.numExperts;
    const size_t K=modelWeights.numExpertsPerToken;
    const size_t I=modelWeights.moeIntermediateDim;
    if(!H||!E||!K||K>E||!I||
       H>UINT32_MAX||I>UINT32_MAX||
       !lw.moeRouter.data||
       lw.moeGate.size()!=E||
       lw.moeUp.size()!=E||
       lw.moeDown.size()!=E||
       layer>=moeRouters_.size()||!moeRouters_[layer])
        return false;

    std::vector<float> logits(E,0.0f);
    if(!tryVulkanHostGEMV(lw.moeRouter,input,logits.data(),E))
        return false;

    TokenRoute route=
        moeRouters_[layer]->RouteFromLogits(logits.data(),E);
    if(!route.valid||route.expertIds.size()!=K||
       route.expertWeights.size()!=K)
        return false;

    std::fill(output,output+H,0.0f);
    const size_t gpuN=vulkanDevices_.size();
    const uint64_t epoch=kvCache?kvCache->currentLength():0;

    // BATCH007: advisory prefetch of routed experts into per-device ExpertCache
    for(size_t dev=0;dev<expertCaches_.size();++dev){
        auto& cache=expertCaches_[dev];
        if(!cache) continue;
        for(size_t k=0;k<K;++k){
            const int eid=route.expertIds[k];
            if(eid>=0) cache->prefetch(rawrxd::deep2::ExpertKey{static_cast<uint32_t>(layer),static_cast<uint32_t>(eid)},epoch);
        }
    }

    std::vector<std::vector<float>> expertOut(
        K,std::vector<float>(H,0.0f));

    // Run at most one expert per device at a time. Experts in each round are
    // mathematically independent and therefore genuinely concurrent.
    for(size_t base=0;base<K;base+=gpuN){
        const size_t n=std::min(gpuN,K-base);
        std::vector<std::future<bool>> futures;
        futures.reserve(n);

        for(size_t j=0;j<n;++j){
            const size_t routeIndex=base+j;
            const int expertId=route.expertIds[routeIndex];
            if(expertId<0||(size_t)expertId>=E) return false;
            const size_t ex=(size_t)expertId;

            GpuWeightView gate{},up{},down{};
            if(!fullView(lw.moeGate[ex],gate)||
               !fullView(lw.moeUp[ex],up)||
               !fullView(lw.moeDown[ex],down))
                return false;

            VulkanCompute* g=vulkanDevices_[j].get();
            futures.emplace_back(std::async(
                std::launch::async,
                [g,gate,up,down,input,&expertOut,routeIndex,H,I,epoch]{
                    return g->RunExpertFFN(
                        gate,up,down,input,
                        expertOut[routeIndex].data(),
                        (uint32_t)H,(uint32_t)I,epoch);
                }));
        }

        for(auto& f:futures) if(!f.get()) return false;
    }

    for(size_t j=0;j<K;++j){
        const float w=route.expertWeights[j];
        if(!std::isfinite(w)) return false;
        for(size_t i=0;i<H;++i)
            output[i]+=w*expertOut[j][i];
    }

    gpuFwd_.gpuExpertDispatches+=K;
    gpuFwd_.hostMaterializations+=K; // one returned vector per routed expert
    gpuFwd_.matOther+=K; // expert host round-trips: MoE residue class

    // Shared expert is independent of top-k route and runs on GPU0.
    const bool anyShared=
        lw.moeSharedGate.data||lw.moeSharedUp.data||lw.moeSharedDown.data;
    if(anyShared){
        if(!lw.moeSharedGate.data||!lw.moeSharedUp.data||
           !lw.moeSharedDown.data)
            return false;
        const size_t SI=lw.moeSharedGate.rows;
        if(!SI||SI>UINT32_MAX) return false;

        GpuWeightView gate{},up{},down{};
        if(!fullView(lw.moeSharedGate,gate)||
           !fullView(lw.moeSharedUp,up)||
           !fullView(lw.moeSharedDown,down))
            return false;

        std::vector<float> shared(H,0.0f);
        if(!vulkanDevices_[0]->RunExpertFFN(
            gate,up,down,input,shared.data(),
            (uint32_t)H,(uint32_t)SI,epoch))
            return false;
        for(size_t i=0;i<H;++i) output[i]+=shared[i];
        ++gpuFwd_.gpuExpertDispatches;
        ++gpuFwd_.hostMaterializations;
        ++gpuFwd_.matOther; // shared expert host round-trip: MoE residue class
    }

    if(vulkanDevices_.size()>=2){
        auto w=Deep2Gpu_MeasureArithmeticOverlap(
            *vulkanDevices_[0],*vulkanDevices_[1],epoch);
        gpuFwd_.dualArithmeticOverlapNs=
            std::max(gpuFwd_.dualArithmeticOverlapNs,
                     w.calibratedOverlapNs);
    }

    // RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001
    // GPU MoE is a whole-family bypass: the router, the per-expert gate/up/down
    // and the shared expert are all resolved and dispatched on the device here.
    // Note this is a BYPASS and not a delegation -- computeMoEFFNGpu is reached
    // BEFORE any host-orchestrated LinearW() call, so on this route none of
    // these weights ever enter LinearW(). The host-side MoE fallback below it
    // does call LinearW(), which is why MoE as a whole is CONDITIONAL.
    {
        using namespace rawrxd::deep2::weightcensus;
        auto addOne=[&](const WeightTensor* t){
            if(!t||!t->data) return;
            Event mev;
            mev.site = Site::MoeGpu;
            mev.route = Route::Bypass;
            mev.tensor = t->name;
            mev.bytes = t->sizeBytes ? t->sizeBytes : t->numElements();
            mev.tokenEpoch = (uint32_t)epoch;
            WeightConsumptionCensus::instance().record(mev);
        };
        addOne(&lw.moeRouter);
        addOne(&lw.moeSharedGate);
        addOne(&lw.moeSharedUp);
        addOne(&lw.moeSharedDown);
        // Per-expert families: one record per expert so the byte count is the
        // real consumed extent rather than a single tensor's size.
        for (size_t e = 0; e < lw.moeGate.size(); ++e)  addOne(&lw.moeGate[e]);
        for (size_t e = 0; e < lw.moeUp.size();   ++e)  addOne(&lw.moeUp[e]);
        for (size_t e = 0; e < lw.moeDown.size(); ++e)  addOne(&lw.moeDown[e]);
    }

    return finiteVec(output,H);
}

bool Deep2Engine::computeMLAAttentionGpu(
    size_t layer,const float* input,float* output,size_t seqLen)
{
    if(!vulkanInitialized_||vulkanDevices_.empty()||
       !input||!output||layer>=modelWeights.layers.size()||
       !kvCache)
        return false;

    const LayerWeights& lw=modelWeights.layers[layer];
    if(!(lw.useMLA||modelWeights.useMLA)) return false;

    const size_t H=modelWeights.hiddenDim;
    const size_t heads=modelWeights.numHeads;
    const size_t qRank=modelWeights.qLoraRank;
    const size_t kvRank=modelWeights.kvLoraRank;
    const size_t nope=modelWeights.qkNopeHeadDim;
    const size_t rope=modelWeights.qkRopeHeadDim;
    const size_t valueLen=modelWeights.vHeadDim;
    const size_t keyLen=nope+rope;

    if(!H||!heads||!qRank||!kvRank||!nope||!rope||!valueLen||
       (rope&1u)||
       H>UINT32_MAX||heads>UINT32_MAX||keyLen>UINT32_MAX||
       valueLen>UINT32_MAX||
       !lw.attnQ_a.data||!lw.attnQ_a_norm.data||!lw.attnQ_b.data||
       !lw.attnKV_a_mqa.data||!lw.attnKV_a_norm.data||
       !lw.attnK_b.data||!lw.attnV_b.data||!lw.attnO.data)
        return false;

    if(lw.attnQ_a.rows!=qRank||lw.attnQ_a.cols!=H||
       lw.attnQ_b.rows!=heads*keyLen||lw.attnQ_b.cols!=qRank||
       lw.attnKV_a_mqa.rows!=kvRank+rope||lw.attnKV_a_mqa.cols!=H||
       lw.attnK_b.rows!=heads*nope||lw.attnK_b.cols!=kvRank||
       lw.attnV_b.rows!=heads*valueLen||lw.attnV_b.cols!=kvRank||
       lw.attnO.rows!=H||lw.attnO.cols!=heads*valueLen)
        return false;

    const size_t pos=kvCache->currentLength();
    if(seqLen!=pos+1||pos>=config.maxSeqLen) return false;

    std::vector<float> qa(qRank,0.0f);
    std::vector<float> qaNorm(qRank,0.0f);
    std::vector<float> qFull(heads*keyLen,0.0f);
    std::vector<float> kva(kvRank+rope,0.0f);
    std::vector<float> cNorm(kvRank,0.0f);
    std::vector<float> kNope(heads*nope,0.0f);
    std::vector<float> values(heads*valueLen,0.0f);

    if(!tryVulkanHostGEMV(lw.attnQ_a,input,qa.data(),qRank))
        return false;
    RMSNormW(lw.attnQ_a_norm,qa.data(),qaNorm.data(),
             qRank,modelWeights.normEps);
    if(!tryVulkanHostGEMV(lw.attnQ_b,qaNorm.data(),
                          qFull.data(),qFull.size()))
        return false;

    if(!tryVulkanHostGEMV(lw.attnKV_a_mqa,input,kva.data(),kva.size()))
        return false;
    RMSNormW(lw.attnKV_a_norm,kva.data(),cNorm.data(),
             kvRank,modelWeights.normEps);

    if(!tryVulkanHostGEMV(lw.attnK_b,cNorm.data(),
                          kNope.data(),kNope.size())||
       !tryVulkanHostGEMV(lw.attnV_b,cNorm.data(),
                          values.data(),values.size()))
        return false;

    std::vector<float> kPe(rope,0.0f);
    std::memcpy(kPe.data(),kva.data()+kvRank,rope*sizeof(float));

    const float theta=modelWeights.ropeTheta>1.0f
        ?modelWeights.ropeTheta:config.ropeTheta;
    const float scaling=modelWeights.ropeScaling>0.0f
        ?modelWeights.ropeScaling:config.ropeScaling;
    applyMlaRope(
        qFull.data(),kPe.data(),heads,nope,rope,pos,theta,scaling);

    std::vector<float> kFull(heads*keyLen,0.0f);
    for(size_t h=0;h<heads;++h){
        float* dst=kFull.data()+h*keyLen;
        std::memcpy(dst,kNope.data()+h*nope,nope*sizeof(float));
        std::memcpy(dst+nope,kPe.data(),rope*sizeof(float));
    }

    std::vector<float> attn(heads*valueLen,0.0f);
    const float scale=1.0f/std::sqrt((float)keyLen);
    const uint64_t epoch=pos;
    auto* g0=getVulkanComputeSlot(0);
    if(!g0||!g0->RunMLAAttentionHost(
        qFull.data(),kFull.data(),values.data(),attn.data(),
        (uint32_t)heads,(uint32_t)keyLen,(uint32_t)valueLen,
        (uint32_t)layer,(uint32_t)pos,
        (uint32_t)modelWeights.numLayers,
        (uint32_t)config.maxSeqLen,scale,epoch))
        return false;

    if(!tryVulkanHostGEMV(lw.attnO,attn.data(),output,H))
        return false;

    ++gpuFwd_.mlaGpuAttentionOps;
    // MLA projections are currently host-staged between device GEMVs. Keep
    // authority fail-closed until a fully resident absorbed-matrix path lands.
    ++gpuFwd_.hostMergeOps;

    // RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001
    // MLA is not a small exception inside LinearW() -- it is a separate
    // attention authority, reached from computeAttention() BEFORE any ordinary
    // QKV handling. The whole MLA weight family is resolved and dispatched
    // here, so on this route none of them enter LinearW(). Every tensor the
    // function itself declared required is recorded by name.
    {
        using namespace rawrxd::deep2::weightcensus;
        const WeightTensor* mla[8] = {
            &lw.attnQ_a, &lw.attnQ_a_norm, &lw.attnQ_b,
            &lw.attnKV_a_mqa, &lw.attnKV_a_norm,
            &lw.attnK_b, &lw.attnV_b, &lw.attnO
        };
        for (const WeightTensor* t : mla) {
            if (!t || !t->data) continue;
            Event v;
            v.site  = Site::MlaGpu;
            v.route = Route::Bypass;   // MLA never routes through LinearW
            v.tensor = t->name;
            v.bytes  = t->sizeBytes ? t->sizeBytes : t->numElements();
            v.tokenEpoch = (uint32_t)epoch;
            WeightConsumptionCensus::instance().record(v);
        }
    }

    return finiteVec(output,H);
}

bool Deep2Engine::forwardTokenGpuHybrid(float* hidden,size_t seqLen)
{
    gpuFwdStateMutated_=false;
    if(!hidden||!seqLen||!vulkanInitialized_||vulkanDevices_.empty()||
       modelWeights.layers.size()<modelWeights.numLayers)
        return false;

    gpuFwdStateMutated_=true;
    try{
        for(size_t l=0;l<modelWeights.numLayers;++l){
            forwardLayer(l,hidden,layerTemp,seqLen);
            std::memcpy(hidden,layerTemp,config.hiddenDim*sizeof(float));
            ++gpuFwd_.hostForwardLayerCalls; // explicit host orchestration
        }
    }catch(const std::exception& ex){
        std::fprintf(stderr,"BATCH10_GPU_HYBRID_FAIL layer_math=%s\n",ex.what());
        return false;
    }

    gpuFwdCommitted_=false; // heavy GPU compute != fully resident authority
    return finiteVec(hidden,config.hiddenDim);
}

PeerDeviceGroupProbe Deep2Engine::probeVulkanPeerGroup() const {
    if(vulkanDevices_.size()<2||!vulkanDevices_[0]||!vulkanDevices_[1])
        return {};
    return Deep2ProbePeerDeviceGroup(
        vulkanDevices_[0]->physicalInfo(),
        vulkanDevices_[1]->physicalInfo());
}

} // namespace Deep2
