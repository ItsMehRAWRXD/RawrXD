// Deep2DualGpuRowSplit.cpp
#include "Deep2DualGpuRowSplit.hpp"
#include <algorithm>
#include <cstring>
#include <future>
#include <limits>
#include <vector>

namespace Deep2 {
namespace {

bool supportedGpuType(int t) noexcept {
    return t==0 || t==8 || t==10 || t==12 || t==14;
}

uint64_t sliceKey(const WeightTensor& wt,uint32_t begin,uint32_t count) noexcept {
    uint64_t h=14695981039346656037ull;
    for(unsigned char c:wt.name){h^=c;h*=1099511628211ull;}
    h^=(uint64_t)begin<<32;
    h^=count;
    h^=(uint64_t)(uint32_t)wt.type*0x9E3779B185EBCA87ull;
    return h;
}

} // namespace

bool Deep2BuildGpuWeightView(
    const WeightTensor& wt,uint32_t rowBegin,uint32_t rowCount,
    GpuWeightView& out) noexcept
{
    out={};
    if(!wt.data || !rowCount || rowBegin>=wt.rows ||
       rowCount>wt.rows-rowBegin || !wt.cols ||
       !supportedGpuType(wt.type))
        return false;

    size_t rowBytes=0;
    if(wt.type==0){
        if(wt.cols>std::numeric_limits<size_t>::max()/sizeof(float))
            return false;
        rowBytes=wt.cols*sizeof(float);
    } else {
        if(!wt.sizeBytes || wt.rows==0 || wt.sizeBytes%wt.rows!=0)
            return false;
        rowBytes=wt.sizeBytes/wt.rows;
    }
    if(!rowBytes ||
       rowBegin>std::numeric_limits<size_t>::max()/rowBytes ||
       rowCount>std::numeric_limits<size_t>::max()/rowBytes)
        return false;

    const size_t off=(size_t)rowBegin*rowBytes;
    const size_t bytes=(size_t)rowCount*rowBytes;
    if(wt.sizeBytes && (off>wt.sizeBytes || bytes>wt.sizeBytes-off))
        return false;

    out.data=static_cast<const uint8_t*>(wt.data)+off;
    out.bytes=bytes;
    out.type=wt.type;
    out.rows=rowCount;
    out.cols=(uint32_t)wt.cols;
    out.key=sliceKey(wt,rowBegin,rowCount);
    return true;
}

bool Deep2RunDualGpuRowSplit(
    VulkanCompute& g0,VulkanCompute& g1,
    const WeightTensor& wt,const float* input,float* output,
    uint64_t epoch,RowSplitReceipt* receipt)
{
    if(receipt) *receipt={};
    if(!input||!output||wt.rows<2||!wt.cols||!supportedGpuType(wt.type))
        return false;

    RowSplitPlan plan=Deep2ChooseRowSplit(
        (uint32_t)wt.rows,g0.deviceLocalBytes(),g1.deviceLocalBytes());
    if(!plan.valid) return false;

    GpuWeightView w0{},w1{};
    if(!Deep2BuildGpuWeightView(wt,plan.row0Begin,plan.row0Count,w0) ||
       !Deep2BuildGpuWeightView(wt,plan.row1Begin,plan.row1Count,w1))
        return false;

    auto run=[&](VulkanCompute& g,const GpuWeightView& w,
                 float* dst)->bool{
        g.SetWorkEpoch(epoch);
        if(!g.EnsureScratch(20,w.cols) ||
           !g.EnsureScratch(21,w.rows))
            return false;
        auto& in=g.Scratch(20);
        auto& out=g.Scratch(21);
        if(!g.UploadVector(in,input,w.cols)) return false;
        if(!g.DispatchWeight(w,in,out)) return false;
        return g.DownloadVector(out,dst,w.rows);
    };

    std::vector<float> y0(plan.row0Count,0.0f);
    std::vector<float> y1(plan.row1Count,0.0f);

    auto f0=std::async(std::launch::async,[&]{
        return run(g0,w0,y0.data());
    });
    auto f1=std::async(std::launch::async,[&]{
        return run(g1,w1,y1.data());
    });

    const bool ok0=f0.get();
    const bool ok1=f1.get();
    if(!ok0||!ok1) return false;

    std::memcpy(output+plan.row0Begin,y0.data(),
                y0.size()*sizeof(float));
    std::memcpy(output+plan.row1Begin,y1.data(),
                y1.size()*sizeof(float));

    auto overlap=Deep2Gpu_MeasureArithmeticOverlap(g0,g1,epoch);
    if(receipt){
        receipt->valid=true;
        receipt->gpu0=ok0;
        receipt->gpu1=ok1;
        receipt->hostMerge=true;
        receipt->rows0=plan.row0Count;
        receipt->rows1=plan.row1Count;
        receipt->calibratedOverlapNs=overlap.calibratedOverlapNs;
        receipt->hostEnvelopeOverlapNs=overlap.hostEnvelopeOverlapNs;
    }
    return true;
}

} // namespace Deep2
