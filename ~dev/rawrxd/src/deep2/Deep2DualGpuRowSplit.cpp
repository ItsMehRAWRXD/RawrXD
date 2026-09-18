// Deep2DualGpuRowSplit.cpp
#include "Deep2DualGpuRowSplit.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <limits>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace Deep2 {


long double envThroughput(const char* name) noexcept {
    const char* s=std::getenv(name);
    if(!s||!*s) return 1.0L;
    char* end=nullptr;
    const long double v=std::strtold(s,&end);
    return end!=s && v>0.0L ? v : 1.0L;
}

// Overlap-probe sampling period. The pairwise witness scan costs ~50us and
// used to run after EVERY GEMV (~7% of dense-row wall at 32T). Authority or
// cert runs that need full-rate calibrated overlap set
// DEEP2_OVERLAP_PROBE_EVERY=1; 0 falls back to the default 16.
static uint64_t envOverlapProbePeriod() noexcept {
    const char* e=std::getenv("DEEP2_OVERLAP_PROBE_EVERY");
    if(!e||!*e) return 16;
    const unsigned long v=std::strtoul(e,nullptr,10);
    return v?v:16;
}

RowSplitPlan chooseThroughputSplit(
    uint32_t rows, const VulkanCompute& g0, const VulkanCompute& g1) noexcept;
RowSplitPlan cachedThroughputSplit(
    const WeightTensor& wt, const VulkanCompute& g0, const VulkanCompute& g1);

std::atomic<double> gOverlapEfficiency{0.0};
std::atomic<uint64_t> gOverlapEfficiencySamples{0};

void updateOverlapEfficiency(
    uint64_t gpu0Ns,uint64_t gpu1Ns,uint64_t wallNs) noexcept
{
    if(!gpu0Ns||!gpu1Ns||!wallNs) return;
    const uint64_t sum=gpu0Ns+gpu1Ns;
    const uint64_t ov=sum>wallNs?sum-wallNs:0;
    const uint64_t denom=std::min(gpu0Ns,gpu1Ns);
    if(!denom) return;
    const double e=std::max(0.0,std::min(1.0,(double)ov/(double)denom));
    const double old=gOverlapEfficiency.load(std::memory_order_relaxed);
    const uint64_t n=gOverlapEfficiencySamples.load(std::memory_order_relaxed);
    gOverlapEfficiency.store(n?old*0.875+e*0.125:e,
                             std::memory_order_relaxed);
    gOverlapEfficiencySamples.fetch_add(1,std::memory_order_relaxed);
}
std::atomic<double> gAsyncRowRatio{0.50};
std::atomic<uint64_t> gAsyncSamples{0};

bool asyncSplitControl() noexcept {
    const char* e=std::getenv("DEEP2_ASYNC_SPLIT_CONTROL");
    return !(e&&e[0]=='0');
}

void updateAsyncRowRatio(uint64_t ns0,uint64_t ns1) noexcept {
    if(!asyncSplitControl()||!ns0||!ns1) return;
    double r=gAsyncRowRatio.load(std::memory_order_relaxed);
    // Faster GPU gets modestly more rows. Limit movement to avoid oscillation.
    if(ns0+ns1) {
        const double ideal=(double)ns1/(double)(ns0+ns1);
        double target=r*0.875+ideal*0.125;
        target=std::max(r-0.05,std::min(r+0.05,target));
        target=std::max(0.20,std::min(0.80,target));
        gAsyncRowRatio.store(target,std::memory_order_relaxed);
        gAsyncSamples.fetch_add(1,std::memory_order_relaxed);
    }
}
struct DualPlanKey {
    const void* data=nullptr;
    uint32_t rows=0,cols=0;
    int type=0;
    uint16_t ratioPermille=500;
    bool operator==(const DualPlanKey& o) const noexcept {
        return data==o.data&&rows==o.rows&&cols==o.cols&&
               type==o.type&&ratioPermille==o.ratioPermille;
    }
};
struct DualPlanHash {
    size_t operator()(const DualPlanKey& k) const noexcept {
        uint64_t h=(uint64_t)(uintptr_t)k.data;
        h^=(uint64_t)k.rows<<32;h^=k.cols;
        h^=(uint64_t)(uint32_t)k.type*0x9e3779b185ebca87ull;
        h^=(uint64_t)k.ratioPermille<<7;
        return (size_t)h;
    }
};

const CachedDualRowPlan* Deep2GetCachedDualRowPlan(
    const WeightTensor& wt,VulkanCompute& g0,VulkanCompute& g1)
{
    const long double s0=envThroughput("DEEP2_GPU0_THROUGHPUT_WEIGHT");
    const long double s1=envThroughput("DEEP2_GPU1_THROUGHPUT_WEIGHT");
    const uint16_t pm=(uint16_t)std::max<long double>(
        1,std::min<long double>(999,s0/(s0+s1)*1000.0L+0.5L));
    const DualPlanKey key{
        wt.data,(uint32_t)wt.rows,(uint32_t)wt.cols,wt.type,pm};
    static std::mutex mu;
    static std::unordered_map<
        DualPlanKey,CachedDualRowPlan,DualPlanHash> cache;
    std::lock_guard<std::mutex> lock(mu);
    auto it=cache.find(key);
    if(it!=cache.end()) return &it->second;

    CachedDualRowPlan p{};
    p.split=chooseThroughputSplit((uint32_t)wt.rows,g0,g1);
    p.valid=p.split.valid &&
        Deep2BuildGpuWeightView(
            wt,p.split.row0Begin,p.split.row0Count,p.gpu0) &&
        Deep2BuildGpuWeightView(
            wt,p.split.row1Begin,p.split.row1Count,p.gpu1);
    auto ins=cache.emplace(key,std::move(p));
    return &ins.first->second;
}

std::atomic<double> gColSpeed0{0.0};
std::atomic<double> gColSpeed1{0.0};

bool autoColumnSplit() noexcept {
    const char* e=std::getenv("DEEP2_COLUMN_SPLIT_AUTO");
    return !(e&&e[0]=='0');
}

void updateColSpeed(unsigned lane,uint32_t cols,uint64_t ns) noexcept {
    if(!autoColumnSplit()||!cols||!ns) return;
    const double sample=(double)cols*1.0e9/(double)ns;
    auto& a=lane==0?gColSpeed0:gColSpeed1;
    const double old=a.load(std::memory_order_relaxed);
    a.store(old>0.0?old*0.875+sample*0.125:sample,
            std::memory_order_relaxed);
}

struct Q4KColumnSlices {
    uint32_t cols0=0,cols1=0;
    std::vector<uint8_t> w0,w1;
};

// One mutable/latest slice set per weight tensor pointer, keyed by wt.data only.
// Replaced when ratio changes — prevents unbounded growth under varying ratioPermille.
const Q4KColumnSlices* q4kColumnSlices(const WeightTensor& wt) {
    if(wt.type!=(int)GGMLType::GGML_TYPE_Q4_K||!wt.data||
       !wt.rows||!wt.cols||wt.cols%256u!=0u) return nullptr;

    struct Entry { Q4KColumnSlices s; uint16_t ratioPermille=0; };
    static std::mutex mu;
    static std::unordered_map<const void*, Entry> cache;

    long double s0=envThroughput("DEEP2_GPU0_THROUGHPUT_WEIGHT");
    long double s1=envThroughput("DEEP2_GPU1_THROUGHPUT_WEIGHT");
    if(autoColumnSplit()) {
        const double a0=gColSpeed0.load(std::memory_order_relaxed);
        const double a1=gColSpeed1.load(std::memory_order_relaxed);
        if(a0>0.0&&a1>0.0){s0=a0;s1=a1;}
    }
    const long double ratio=s0/(s0+s1);
    const uint16_t pm=(uint16_t)std::max<long double>(
        1.0L,std::min<long double>(999.0L,ratio*1000.0L+0.5L));

    const uint32_t blocks=(uint32_t)wt.cols/256u;
    if(blocks<2) return nullptr;
    uint32_t b0=(uint32_t)(
        (long double)blocks*s0/(s0+s1)+0.5L);
    b0=std::max<uint32_t>(1,std::min<uint32_t>(blocks-1,b0));
    const uint32_t b1=blocks-b0;
    constexpr size_t QB=144;
    const size_t rowBytes=(size_t)blocks*QB;
    const size_t row0=(size_t)b0*QB;
    const size_t row1=(size_t)b1*QB;
    if(wt.sizeBytes<(size_t)wt.rows*rowBytes) return nullptr;

    std::lock_guard<std::mutex> g(mu);
    auto it=cache.find(wt.data);
    if(it!=cache.end() && it->second.ratioPermille==pm)
        return &it->second.s;

    // Rebuild under drift: free the old slice pair BEFORE constructing the
    // replacement. Building-then-swapping would transiently hold both
    // images (~2x model bytes) during the copy loop below.
    if(it!=cache.end()) it->second.s={};
    Q4KColumnSlices s{};
    s.cols0=b0*256u;s.cols1=b1*256u;
    s.w0.resize((size_t)wt.rows*row0);
    s.w1.resize((size_t)wt.rows*row1);
    const auto* src=(const uint8_t*)wt.data;
    for(size_t r=0;r<wt.rows;++r) {
        std::memcpy(s.w0.data()+r*row0,src+r*rowBytes,row0);
        std::memcpy(s.w1.data()+r*row1,src+r*rowBytes+row0,row1);
    }
    // try_emplace keeps position when the key exists (drift case);
    // overwrite in place instead of inserting a second Entry.
    auto [it2, inserted] = cache.try_emplace(wt.data);
    it2->second.s = std::move(s);
    it2->second.ratioPermille = pm;
    return &it2->second.s;
}

struct DualRowJob {
    bool (*fn)(void*) noexcept = nullptr;
    void* ctx = nullptr;
};

class DualRowExecutor {
public:
    DualRowExecutor() {
        worker_[0] = std::thread([this]{ loop(0); });
        worker_[1] = std::thread([this]{ loop(1); });
    }
    ~DualRowExecutor() {
        {
            std::lock_guard<std::mutex> g(mu_);
            stop_ = true;
            ++generation_;
        }
        cv_.notify_all();
        for (auto& t : worker_) if (t.joinable()) t.join();
    }

    bool run(DualRowJob a, DualRowJob b) {
        std::unique_lock<std::mutex> lk(mu_);
        done_[0] = done_[1] = false;
        result_[0] = result_[1] = false;
        job_[0] = a;
        job_[1] = b;
        const uint64_t g = ++generation_;
        cv_.notify_all();
        doneCv_.wait(lk, [&] {
            return stop_ || (done_[0] && done_[1] && completedGeneration_ == g);
        });
        return !stop_ && result_[0] && result_[1];
    }

private:
    void loop(unsigned lane) {
        uint64_t seen = 0;
        for (;;) {
            DualRowJob j{};
            uint64_t g = 0;
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait(lk, [&]{ return stop_ || generation_ != seen; });
                if (stop_) return;
                seen = generation_;
                g = seen;
                j = job_[lane];
            }
            const bool r = j.fn ? j.fn(j.ctx) : false;
            {
                std::lock_guard<std::mutex> lk(mu_);
                result_[lane] = r;
                done_[lane] = true;
                if (done_[0] && done_[1]) {
                    completedGeneration_ = g;
                    doneCv_.notify_one();
                }
            }
        }
    }

    std::mutex mu_;
    std::condition_variable cv_;
    std::condition_variable doneCv_;
    std::thread worker_[2];
    DualRowJob job_[2];
    bool done_[2] = {false,false};
    bool result_[2] = {false,false};
    bool stop_ = false;
    uint64_t generation_ = 0;
    uint64_t completedGeneration_ = 0;
};

DualRowExecutor& rowExecutor() {
    static DualRowExecutor ex;
    return ex;
}

static std::atomic<uint64_t> gDualRowTimingCalls{0};
static std::atomic<uint64_t> gDualRowTimingSingleCalls{0};
static std::atomic<uint64_t> gDualRowTimingGroupCalls{0};
static std::atomic<uint64_t> gDualRowTimingTotalWallNs{0};
static std::atomic<uint64_t> gDualRowTimingExecutorWallNs{0};
static std::atomic<uint64_t> gDualRowTimingLane0HostEnvelopeNs{0};
static std::atomic<uint64_t> gDualRowTimingLane1HostEnvelopeNs{0};
static std::atomic<uint64_t> gDualRowTimingLaneCriticalNs{0};
static std::atomic<uint64_t> gDualRowTimingHostMergeNs{0};
static std::atomic<uint64_t> gDualRowTimingOverlapProbeNs{0};

void Deep2ResetDualRowTiming() noexcept {
    gDualRowTimingCalls.store(0, std::memory_order_relaxed);
    gDualRowTimingSingleCalls.store(0, std::memory_order_relaxed);
    gDualRowTimingGroupCalls.store(0, std::memory_order_relaxed);
    gDualRowTimingTotalWallNs.store(0, std::memory_order_relaxed);
    gDualRowTimingExecutorWallNs.store(0, std::memory_order_relaxed);
    gDualRowTimingLane0HostEnvelopeNs.store(0, std::memory_order_relaxed);
    gDualRowTimingLane1HostEnvelopeNs.store(0, std::memory_order_relaxed);
    gDualRowTimingLaneCriticalNs.store(0, std::memory_order_relaxed);
    gDualRowTimingHostMergeNs.store(0, std::memory_order_relaxed);
    gDualRowTimingOverlapProbeNs.store(0, std::memory_order_relaxed);
}

DualRowTimingCounters Deep2GetDualRowTiming() noexcept {
    DualRowTimingCounters c{};
    c.calls = gDualRowTimingCalls.load(std::memory_order_relaxed);
    c.singleCalls = gDualRowTimingSingleCalls.load(std::memory_order_relaxed);
    c.groupCalls = gDualRowTimingGroupCalls.load(std::memory_order_relaxed);
    c.totalWallNs = gDualRowTimingTotalWallNs.load(std::memory_order_relaxed);
    c.executorWallNs = gDualRowTimingExecutorWallNs.load(std::memory_order_relaxed);
    c.lane0HostEnvelopeNs = gDualRowTimingLane0HostEnvelopeNs.load(std::memory_order_relaxed);
    c.lane1HostEnvelopeNs = gDualRowTimingLane1HostEnvelopeNs.load(std::memory_order_relaxed);
    c.laneCriticalNs = gDualRowTimingLaneCriticalNs.load(std::memory_order_relaxed);
    c.hostMergeNs = gDualRowTimingHostMergeNs.load(std::memory_order_relaxed);
    c.overlapProbeNs = gDualRowTimingOverlapProbeNs.load(std::memory_order_relaxed);
    return c;
}

bool Deep2RunDualGpuColumnSplitBatch4(
    VulkanCompute& g0,VulkanCompute& g1,const WeightTensor& wt,
    const float* inputBatch,float* outputBatch,
    uint32_t batch,uint64_t epoch)
{
    if(!inputBatch||!outputBatch||!batch||batch>4) return false;
    const Q4KColumnSlices* s=q4kColumnSlices(wt);
    if(!s) return false;
    const uint32_t rows=(uint32_t)wt.rows;
    static thread_local std::vector<float> x0;
    static thread_local std::vector<float> x1;
    static thread_local std::vector<float> y0;
    static thread_local std::vector<float> y1;
    x0.resize((size_t)batch*s->cols0);
    x1.resize((size_t)batch*s->cols1);
    for(uint32_t b=0;b<batch;++b) {
        const float* src=inputBatch+(size_t)b*wt.cols;
        std::memcpy(x0.data()+(size_t)b*s->cols0,src,
                    (size_t)s->cols0*sizeof(float));
        std::memcpy(x1.data()+(size_t)b*s->cols1,src+s->cols0,
                    (size_t)s->cols1*sizeof(float));
    }
    y0.resize((size_t)batch*rows);
    y1.resize((size_t)batch*rows);

    GpuWeightView w0{},w1{};
    w0.data=s->w0.data();w0.bytes=s->w0.size();w0.type=12;
    w0.rows=rows;w0.cols=s->cols0;
    w1.data=s->w1.data();w1.bytes=s->w1.size();w1.type=12;
    w1.rows=rows;w1.cols=s->cols1;

    struct ColSplitCtx {
        VulkanCompute* g;
        const GpuWeightView* w;
        const float* x;
        float* y;
        uint32_t batch;
        uint64_t epoch;
        uint64_t ns;
        bool ok;
    };
    auto runFn=[](void* p) noexcept -> bool {
        auto* c=static_cast<ColSplitCtx*>(p);
        const auto a=std::chrono::steady_clock::now();
        c->ok=c->g->RunWeightHostBatchQ4K(
            *c->w,c->x,c->y,c->batch,c->epoch);
        const auto z=std::chrono::steady_clock::now();
        c->ns=(uint64_t)std::chrono::duration_cast<
            std::chrono::nanoseconds>(z-a).count();
        return c->ok;
    };
    ColSplitCtx c0{&g0,&w0,x0.data(),y0.data(),batch,epoch,0,false};
    ColSplitCtx c1{&g1,&w1,x1.data(),y1.data(),batch,epoch,0,false};

    const bool both=rowExecutor().run(
        DualRowJob{runFn,&c0},
        DualRowJob{runFn,&c1});
    if(!both||!c0.ok||!c1.ok) return false;
    updateColSpeed(0,s->cols0,c0.ns);
    updateColSpeed(1,s->cols1,c1.ns);

    const size_t n=(size_t)batch*rows;
    for(size_t i=0;i<n;++i) outputBatch[i]=y0[i]+y1[i];
    return true;
}

bool Deep2RunDualGpuRowSplitBatchGroupQ4K(
    VulkanCompute& g0,VulkanCompute& g1,
    const WeightTensor* const* weights,float* const* outputs,size_t weightCount,
    const float* inputBatch,uint32_t batch,uint64_t epoch)
{
    if(!weights||!outputs||!inputBatch||weightCount<2||weightCount>3||
       !batch||batch>4) return false;
    RowSplitPlan plans[3];
    GpuWeightView wv[3][2]{};
    static thread_local std::vector<float> slab0;
    static thread_local std::vector<float> slab1;
    size_t offsets0[3]{};
    size_t offsets1[3]{};
    for(size_t i=0;i<weightCount;++i) {
        if(!weights[i]||!outputs[i]||
           weights[i]->type!=(int)GGMLType::GGML_TYPE_Q4_K)
            return false;
        plans[i]=cachedThroughputSplit(*weights[i],g0,g1);
        if(!plans[i].valid||
           !Deep2BuildGpuWeightView(
               *weights[i],plans[i].row0Begin,plans[i].row0Count,wv[i][0])||
           !Deep2BuildGpuWeightView(
               *weights[i],plans[i].row1Begin,plans[i].row1Count,wv[i][1]))
            return false;
    }
    // Both cards receive the shared activation ONCE.
    if(!g0.UploadResidentBatchInput(
            inputBatch,weights[0]->cols,batch,epoch)||
       !g1.UploadResidentBatchInput(
            inputBatch,weights[0]->cols,batch,epoch))
        return false;

    size_t total0=0,total1=0;
    for(size_t i=0;i<weightCount;++i) {
        total0+=(size_t)batch*wv[i][0].rows;
        total1+=(size_t)batch*wv[i][1].rows;
    }
    slab0.resize(total0);
    slab1.resize(total1);

    struct GroupQ4KCtx {
        VulkanCompute* g;
        GpuWeightView* views;
        float* slab;
        size_t* offsets;
        size_t weightCount;
        uint32_t cols;
        uint32_t batch;
        uint64_t epoch;
        bool ok;
    };
    auto runFn=[](void* p) noexcept -> bool {
        auto* c=static_cast<GroupQ4KCtx*>(p);
        c->ok=c->g->RunWeightGroupResidentInputQ4KSingleReturn(
            c->views,c->slab,c->offsets,
            c->weightCount,c->cols,c->batch,c->epoch);
        return c->ok;
    };
    GroupQ4KCtx c0{&g0,wv[0],slab0.data(),offsets0,
        weightCount,(uint32_t)weights[0]->cols,batch,epoch,false};
    GroupQ4KCtx c1{&g1,wv[1],slab1.data(),offsets1,
        weightCount,(uint32_t)weights[0]->cols,batch,epoch,false};

    const bool both=rowExecutor().run(
        DualRowJob{runFn,&c0},
        DualRowJob{runFn,&c1});
    if(!both||!c0.ok||!c1.ok) return false;
    for(size_t i=0;i<weightCount;++i) {
        for(uint32_t t=0;t<batch;++t) {
            float* dst=outputs[i]+(size_t)t*weights[i]->rows;
            std::memcpy(
                dst+plans[i].row0Begin,
                slab0.data()+offsets0[i]+
                    (size_t)t*plans[i].row0Count,
                (size_t)plans[i].row0Count*sizeof(float));
            std::memcpy(
                dst+plans[i].row1Begin,
                slab1.data()+offsets1[i]+
                    (size_t)t*plans[i].row1Count,
                (size_t)plans[i].row1Count*sizeof(float));
        }
    }

    return true;
}

std::atomic<double> gAutoSpeed0{0.0};
std::atomic<double> gAutoSpeed1{0.0};

bool autoSplitEnabled() noexcept {
    const char* e=std::getenv("DEEP2_ROW_SPLIT_AUTO");
    return !(e && e[0]=='0');
}

void updateAutoSpeed(unsigned lane,uint32_t rows,uint64_t ns) noexcept {
    if(!autoSplitEnabled()||!rows||!ns) return;
    const double sample=
        static_cast<double>(rows)*1.0e9/static_cast<double>(ns);
    auto& a=lane==0?gAutoSpeed0:gAutoSpeed1;
    double old=a.load(std::memory_order_relaxed);
    const double next=old>0.0 ? old*0.875+sample*0.125 : sample;
    a.store(next,std::memory_order_relaxed);
}

struct SplitCacheKey {
    const void* data=nullptr;
    uint32_t rows=0;
    uint32_t cols=0;
    int type=0;
    uint32_t speed0m=0;
    uint32_t speed1m=0;
    bool operator==(const SplitCacheKey& o) const noexcept {
        return data==o.data&&rows==o.rows&&cols==o.cols&&type==o.type&&
               speed0m==o.speed0m&&speed1m==o.speed1m;
    }
};
struct SplitCacheHash {
    size_t operator()(const SplitCacheKey& k) const noexcept {
        uint64_t h=(uint64_t)(uintptr_t)k.data;
        h^=(uint64_t)k.rows<<32;
        h^=k.cols;
        h^=(uint64_t)(uint32_t)k.type*0x9e3779b185ebca87ull;
        h^=(uint64_t)k.speed0m<<17;
        h^=(uint64_t)k.speed1m<<3;
        return (size_t)h;
    }
};

RowSplitPlan cachedThroughputSplit(
    const WeightTensor& wt,const VulkanCompute& g0,const VulkanCompute& g1)
{
    const long double s0=envThroughput("DEEP2_GPU0_THROUGHPUT_WEIGHT");
    const long double s1=envThroughput("DEEP2_GPU1_THROUGHPUT_WEIGHT");
    const uint32_t m0=(uint32_t)(s0*1000.0L+0.5L);
    const uint32_t m1=(uint32_t)(s1*1000.0L+0.5L);
    const SplitCacheKey key{
        wt.data,(uint32_t)wt.rows,(uint32_t)wt.cols,wt.type,m0,m1};
    static std::mutex mu;
    static std::unordered_map<SplitCacheKey,RowSplitPlan,SplitCacheHash> cache;
    {
        std::lock_guard<std::mutex> g(mu);
        auto it=cache.find(key);
        if(it!=cache.end()) return it->second;
    }
    RowSplitPlan p=chooseThroughputSplit((uint32_t)wt.rows,g0,g1);
    {
        std::lock_guard<std::mutex> g(mu);
        if(cache.size()>4096) cache.clear();
        cache.emplace(key,p);
    }
    return p;
}

RowSplitPlan chooseThroughputSplit(
    uint32_t rows,const VulkanCompute& g0,const VulkanCompute& g1) noexcept
{
    // Frozen-split gate: once the async ratio has converged through warmup,
    // stop chasing per-token drift. Re-deriving geometry per call churns
    // plan caches and can rebuild host-heavy column slices mid-decode.
    static std::atomic<uint64_t> frozenSamples{0};
    static std::atomic<double> frozenRatio{-1.0};
    const uint64_t samples=gAsyncSamples.load(std::memory_order_relaxed);
    const char* freezeEnv=std::getenv("DEEP2_SPLIT_FREEZE");
    const bool freezeEnabled=!(freezeEnv&&freezeEnv[0]=='0');
    if(freezeEnabled&&asyncSplitControl()&&samples>0) {
        uint64_t seen=frozenSamples.load(std::memory_order_relaxed);
        if(seen==0&&samples>=256) {
            // Warmup convergence point: capture and freeze the ratio.
            frozenSamples.store(samples,std::memory_order_relaxed);
            frozenRatio.store(
                gAsyncRowRatio.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
        }
        if(frozenSamples.load(std::memory_order_relaxed)>0) {
            const double r=frozenRatio.load(std::memory_order_relaxed);
            uint32_t n0=(uint32_t)std::llround((double)rows*r);
            n0=std::max<uint32_t>(1,std::min<uint32_t>(rows-1,n0));
            RowSplitPlan p{};
            p.valid=true;
            p.row0Begin=0;p.row0Count=n0;
            p.row1Begin=n0;p.row1Count=rows-n0;
            return p;
        }
    }
    if(asyncSplitControl()&&gAsyncSamples.load(std::memory_order_relaxed)>0) {
        const double r=gAsyncRowRatio.load(std::memory_order_relaxed);
        uint32_t n0=(uint32_t)std::llround((double)rows*r);
        n0=std::max<uint32_t>(1,std::min<uint32_t>(rows-1,n0));
        RowSplitPlan p{};
        p.valid=true;
        p.row0Begin=0;p.row0Count=n0;
        p.row1Begin=n0;p.row1Count=rows-n0;
        return p;
    }
    if(!g0.deviceLocalBytes()||!g1.deviceLocalBytes()) return {};
    long double s0=envThroughput("DEEP2_GPU0_THROUGHPUT_WEIGHT");
    long double s1=envThroughput("DEEP2_GPU1_THROUGHPUT_WEIGHT");
    if(autoSplitEnabled()){
        const double a0=gAutoSpeed0.load(std::memory_order_relaxed);
        const double a1=gAutoSpeed1.load(std::memory_order_relaxed);
        if(a0>0.0&&a1>0.0){
            s0=(long double)a0;
            s1=(long double)a1;
        }
    }
    return Deep2ChooseRowSplitWeighted(rows,s0,s1);
}

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
    const auto totalStart = std::chrono::steady_clock::now();
    if(receipt) *receipt={};
    if(!input||!output||wt.rows<2||!wt.cols||!supportedGpuType(wt.type))
        return false;

    RowSplitPlan plan=cachedThroughputSplit(wt,g0,g1);
    if(!plan.valid) return false;

    GpuWeightView w0{},w1{};
    if(!Deep2BuildGpuWeightView(wt,plan.row0Begin,plan.row0Count,w0) ||
       !Deep2BuildGpuWeightView(wt,plan.row1Begin,plan.row1Count,w1))
        return false;

    // Batch2 #7: lanes write directly into the caller's disjoint final row
    // ranges — staging vectors and the host merge memcpy are gone.
    struct Ctx {
        unsigned lane;
        VulkanCompute* g;
        const GpuWeightView* w;
        const float* input;
        float* dst;
        uint64_t epoch;
        uint64_t hostEnvelopeNs;
        bool ok;
    } c0{0,&g0,&w0,input,output+plan.row0Begin,epoch,0,false};
    Ctx c1{1,&g1,&w1,input,output+plan.row1Begin,epoch,0,false};

    auto runFn=[](void* p) noexcept -> bool {
        auto* c=static_cast<Ctx*>(p);
        const auto a = std::chrono::steady_clock::now();
        const bool ok=c->g->RunWeightHostRoundTrip(*c->w,c->input,c->dst,c->epoch);
        const auto z = std::chrono::steady_clock::now();
        c->hostEnvelopeNs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(z - a).count());
        if(ok){ updateAutoSpeed(c->lane,c->w->rows,0); }
        c->ok=ok;
        return ok;
    };

    const auto execStart = std::chrono::steady_clock::now();
    const bool both = rowExecutor().run(
        DualRowJob{runFn,&c0},
        DualRowJob{runFn,&c1});
    const auto execEnd = std::chrono::steady_clock::now();
    if(!both||!c0.ok||!c1.ok) return false;

    // Host merge eliminated by direct final-range lane writes.
    const uint64_t hostMergeNs = 0;

    // Sampled overlap probe: 1-in-N GEMVs pay the ~50us witness scan.
    // Call 0 always samples; full rate via DEEP2_OVERLAP_PROBE_EVERY=1.
    GpuOverlapWitness overlap{};
    uint64_t overlapProbeNs = 0;
    {
        static std::atomic<uint64_t> probeSeq{0};
        const uint64_t seq=probeSeq.fetch_add(1,std::memory_order_relaxed);
        if(seq%envOverlapProbePeriod()==0){
            const auto overlapStart = std::chrono::steady_clock::now();
            overlap=Deep2Gpu_MeasureArithmeticOverlap(g0,g1,epoch);
            const auto overlapEnd = std::chrono::steady_clock::now();
            overlapProbeNs = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    overlapEnd - overlapStart).count());
        }
    }

    const uint64_t executorWallNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(execEnd - execStart).count());
    const uint64_t lane0HostEnvelopeNs = c0.hostEnvelopeNs;
    const uint64_t lane1HostEnvelopeNs = c1.hostEnvelopeNs;
    const uint64_t laneCriticalNs = std::max(lane0HostEnvelopeNs, lane1HostEnvelopeNs);
    const uint64_t totalWallNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            execEnd - totalStart).count()) + overlapProbeNs;

    gDualRowTimingCalls.fetch_add(1, std::memory_order_relaxed);
    gDualRowTimingSingleCalls.fetch_add(1, std::memory_order_relaxed);
    gDualRowTimingExecutorWallNs.fetch_add(executorWallNs, std::memory_order_relaxed);
    gDualRowTimingLane0HostEnvelopeNs.fetch_add(lane0HostEnvelopeNs, std::memory_order_relaxed);
    gDualRowTimingLane1HostEnvelopeNs.fetch_add(lane1HostEnvelopeNs, std::memory_order_relaxed);
    gDualRowTimingLaneCriticalNs.fetch_add(laneCriticalNs, std::memory_order_relaxed);
    gDualRowTimingHostMergeNs.fetch_add(hostMergeNs, std::memory_order_relaxed);
    gDualRowTimingOverlapProbeNs.fetch_add(overlapProbeNs, std::memory_order_relaxed);
    gDualRowTimingTotalWallNs.fetch_add(totalWallNs, std::memory_order_relaxed);

    // Feed the real dual-lane timing into the async ratio controller.
    // Before this wiring the controller was dead code: gAsyncSamples stayed
    // 0, chooseThroughputSplit never left the static env-weight branch, and
    // both GPUs split rows 50/50 regardless of measured lane speed.
    if(lane0HostEnvelopeNs>0&&lane1HostEnvelopeNs>0)
        updateAsyncRowRatio(lane0HostEnvelopeNs,lane1HostEnvelopeNs);

    if(receipt){
        receipt->valid=true;
        receipt->gpu0=c0.ok;
        receipt->gpu1=c1.ok;
        receipt->hostMerge=false; // lanes wrote final ranges directly (#7)
        receipt->rows0=plan.row0Count;
        receipt->rows1=plan.row1Count;
        receipt->calibratedOverlapNs=overlap.calibratedOverlapNs;
        receipt->hostEnvelopeOverlapNs=overlap.hostEnvelopeOverlapNs;
    }
    return true;
}

bool Deep2RunDualGpuRowSplitGroup(
    VulkanCompute& g0,VulkanCompute& g1,
    const WeightTensor* const* weights,float* const* outputs,size_t count,
    const float* input,uint32_t inputCount,uint64_t epoch,
    RowSplitReceipt* receipt)
{
    const auto totalStart = std::chrono::steady_clock::now();
    if(receipt) *receipt={};
    if(!weights||!outputs||!input||!inputCount||count<2||count>3)
        return false;

    RowSplitPlan plans[3];
    GpuWeightView wv[3][2]{};

    for(size_t i=0;i<count;++i){
        if(!weights[i]||!outputs[i]||weights[i]->cols!=inputCount||
           weights[i]->rows<2||!supportedGpuType(weights[i]->type))
            return false;
        // Cached plan path: frozen split geometry + zero-copy row views
        // (identical to the single-GEMV lane). Only fall back to a direct
        // chooseThroughputSplit when the cache cannot serve this tensor.
        const CachedDualRowPlan* cp=
            Deep2GetCachedDualRowPlan(*weights[i],g0,g1);
        if(cp&&cp->valid){
            plans[i]=cp->split;
            wv[i][0]=cp->gpu0;
            wv[i][1]=cp->gpu1;
        } else {
            plans[i]=chooseThroughputSplit(
                (uint32_t)weights[i]->rows,g0,g1);
            if(!plans[i].valid) return false;
            if(!Deep2BuildGpuWeightView(
                    *weights[i],plans[i].row0Begin,plans[i].row0Count,
                    wv[i][0]) ||
               !Deep2BuildGpuWeightView(
                    *weights[i],plans[i].row1Begin,plans[i].row1Count,
                    wv[i][1]))
                return false;
        }
    }

    // Batch2 #7: each lane writes its row range of each grouped output
    // directly — staging row buffers and the merge loop are gone.
    float* outs0[3]{};
    float* outs1[3]{};
    GpuWeightView views0[3]{};
    GpuWeightView views1[3]{};
    for(size_t i=0;i<count;++i){
        views0[i]=wv[i][0];
        views1[i]=wv[i][1];
        outs0[i]=outputs[i]+plans[i].row0Begin;
        outs1[i]=outputs[i]+plans[i].row1Begin;
    }

    struct GroupCtx {
        VulkanCompute* g;
        GpuWeightView* views;
        float** outs;
        size_t count;
        const float* input;
        uint32_t inputCount;
        uint64_t epoch;
        uint64_t hostEnvelopeNs;
        bool ok;
    };
    auto runFn=[](void* p) noexcept -> bool {
        auto* c=static_cast<GroupCtx*>(p);
        const auto a = std::chrono::steady_clock::now();
        c->ok=c->g->RunWeightGroupHostRoundTrip(
            c->views,c->outs,c->count,c->input,c->inputCount,c->epoch);
        const auto z = std::chrono::steady_clock::now();
        c->hostEnvelopeNs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(z - a).count());
        return c->ok;
    };
    GroupCtx c0{&g0,views0,outs0,count,input,inputCount,epoch,0,false};
    GroupCtx c1{&g1,views1,outs1,count,input,inputCount,epoch,0,false};

    const auto execStart = std::chrono::steady_clock::now();
    const bool both=rowExecutor().run(
        DualRowJob{runFn,&c0},
        DualRowJob{runFn,&c1});
    const auto execEnd = std::chrono::steady_clock::now();
    if(!both||!c0.ok||!c1.ok) return false;

    // Host merge eliminated by direct final-range lane writes.
    const uint64_t hostMergeNs = 0;

    // Sampled overlap probe (1-in-N; call 0 samples; env full-rate override).
    GpuOverlapWitness overlap{};
    uint64_t overlapProbeNs = 0;
    {
        static std::atomic<uint64_t> groupProbeSeq{0};
        const uint64_t seq=groupProbeSeq.fetch_add(1,std::memory_order_relaxed);
        if(seq%envOverlapProbePeriod()==0){
            const auto overlapStart = std::chrono::steady_clock::now();
            overlap=Deep2Gpu_MeasureArithmeticOverlap(g0,g1,epoch);
            const auto overlapEnd = std::chrono::steady_clock::now();
            overlapProbeNs = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    overlapEnd - overlapStart).count());
        }
    }

    const uint64_t executorWallNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(execEnd - execStart).count());
    const uint64_t lane0HostEnvelopeNs = c0.hostEnvelopeNs;
    const uint64_t lane1HostEnvelopeNs = c1.hostEnvelopeNs;
    const uint64_t laneCriticalNs = std::max(lane0HostEnvelopeNs, lane1HostEnvelopeNs);
    const uint64_t totalWallNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            execEnd - totalStart).count()) + overlapProbeNs;

    gDualRowTimingCalls.fetch_add(1, std::memory_order_relaxed);
    gDualRowTimingGroupCalls.fetch_add(1, std::memory_order_relaxed);
    gDualRowTimingExecutorWallNs.fetch_add(executorWallNs, std::memory_order_relaxed);
    gDualRowTimingLane0HostEnvelopeNs.fetch_add(lane0HostEnvelopeNs, std::memory_order_relaxed);
    gDualRowTimingLane1HostEnvelopeNs.fetch_add(lane1HostEnvelopeNs, std::memory_order_relaxed);
    gDualRowTimingLaneCriticalNs.fetch_add(laneCriticalNs, std::memory_order_relaxed);
    gDualRowTimingHostMergeNs.fetch_add(hostMergeNs, std::memory_order_relaxed);
    gDualRowTimingOverlapProbeNs.fetch_add(overlapProbeNs, std::memory_order_relaxed);
    gDualRowTimingTotalWallNs.fetch_add(totalWallNs, std::memory_order_relaxed);

    // Same live-ratio feed as the single-GEMV lane: measured group lane
    // envelopes drive the split controller instead of a static 50/50.
    if(lane0HostEnvelopeNs>0&&lane1HostEnvelopeNs>0)
        updateAsyncRowRatio(lane0HostEnvelopeNs,lane1HostEnvelopeNs);

    if(receipt){
        receipt->valid=true;
        receipt->gpu0=true;
        receipt->gpu1=true;
        receipt->hostMerge=false; // lanes wrote final ranges directly (#7)
        for(size_t i=0;i<count;++i){
            receipt->rows0+=plans[i].row0Count;
            receipt->rows1+=plans[i].row1Count;
        }
        receipt->calibratedOverlapNs=overlap.calibratedOverlapNs;
        receipt->hostEnvelopeOverlapNs=overlap.hostEnvelopeOverlapNs;
    }
    return true;
}

bool Deep2RunDualGpuRowSplitBatch4(
    VulkanCompute& g0,VulkanCompute& g1,
    const WeightTensor& wt,
    const float* inputBatch,float* outputBatch,
    uint32_t batch,uint64_t epoch,
    RowSplitReceipt* receipt)
{
    if(receipt) *receipt={};
    if(!inputBatch||!outputBatch||batch==0||batch>4||
       wt.type!=(int)GGMLType::GGML_TYPE_Q4_K||
       wt.rows<2||!wt.cols) {
        std::fprintf(stderr,
            "[BATCH4_FAIL] input validation: ib=%p ob=%p batch=%zu "
            "type=%d rows=%zu cols=%zu\n",
            static_cast<const void*>(inputBatch),
            static_cast<void*>(outputBatch),(size_t)batch,
            wt.type,(size_t)wt.rows,(size_t)wt.cols);
        return false;
    }

    RowSplitPlan p=cachedThroughputSplit(wt,g0,g1);
    if(!p.valid) {
        std::fprintf(stderr,
            "[BATCH4_FAIL] cachedThroughputSplit invalid rows=%zu cols=%zu\n",
            (size_t)wt.rows,(size_t)wt.cols);
        return false;
    }
    GpuWeightView w0{},w1{};
    if(!Deep2BuildGpuWeightView(wt,p.row0Begin,p.row0Count,w0)||
       !Deep2BuildGpuWeightView(wt,p.row1Begin,p.row1Count,w1)) {
        std::fprintf(stderr,
            "[BATCH4_FAIL] Deep2BuildGpuWeightView r0=%zu c0=%zu r1=%zu c1=%zu\n",
            (size_t)p.row0Begin,(size_t)p.row0Count,(size_t)p.row1Begin,(size_t)p.row1Count);
        return false;
    }

    static thread_local std::vector<float> y0;
    static thread_local std::vector<float> y1;
    y0.resize((size_t)batch*p.row0Count);
    y1.resize((size_t)batch*p.row1Count);

    struct Batch4Ctx {
        VulkanCompute* g;
        const GpuWeightView* w;
        const float* inputBatch;
        float* y;
        uint32_t batch;
        uint64_t epoch;
        bool ok;
    };
    auto runFn=[](void* p) noexcept -> bool {
        auto* c=static_cast<Batch4Ctx*>(p);
        c->ok=c->g->RunWeightHostBatchQ4K(
            *c->w,c->inputBatch,c->y,c->batch,c->epoch);
        return c->ok;
    };
    Batch4Ctx c0{&g0,&w0,inputBatch,y0.data(),batch,epoch,false};
    Batch4Ctx c1{&g1,&w1,inputBatch,y1.data(),batch,epoch,false};

    const bool both=rowExecutor().run(
        DualRowJob{runFn,&c0},
        DualRowJob{runFn,&c1});
    if(!both||!c0.ok||!c1.ok) {
        std::fprintf(stderr,
            "[BATCH4_FAIL] RunWeightHostBatchQ4K both=%d ok0=%d ok1=%d\n",
            both?1:0,c0.ok?1:0,c1.ok?1:0);
        return false;
    }

    for(uint32_t b=0;b<batch;++b) {
        float* dst=outputBatch+(size_t)b*wt.rows;
        std::memcpy(dst+p.row0Begin,
                    y0.data()+(size_t)b*p.row0Count,
                    (size_t)p.row0Count*sizeof(float));
        std::memcpy(dst+p.row1Begin,
                    y1.data()+(size_t)b*p.row1Count,
                    (size_t)p.row1Count*sizeof(float));
    }

    if(receipt) {
        receipt->valid=true;receipt->gpu0=true;receipt->gpu1=true;
        receipt->hostMerge=true;
        receipt->rows0=p.row0Count;receipt->rows1=p.row1Count;
        auto ov=Deep2Gpu_MeasureArithmeticOverlap(g0,g1,epoch);
        receipt->calibratedOverlapNs=ov.calibratedOverlapNs;
        receipt->hostEnvelopeOverlapNs=ov.hostEnvelopeOverlapNs;
    }
    return true;
}

bool Deep2RunDualGpuRowSplitBatchTop1(
    VulkanCompute& g0,VulkanCompute& g1,const WeightTensor& wt,
    const float* inputBatch,uint32_t batch,
    uint32_t* outToken,float* outValue,uint64_t epoch)
{
    if(!inputBatch||!outToken||!outValue||!batch||batch>4||
       wt.type!=(int)GGMLType::GGML_TYPE_Q4_K) return false;
    RowSplitPlan p=cachedThroughputSplit(wt,g0,g1);
    if(!p.valid) return false;
    GpuWeightView w0{},w1{};
    if(!Deep2BuildGpuWeightView(wt,p.row0Begin,p.row0Count,w0)||
       !Deep2BuildGpuWeightView(wt,p.row1Begin,p.row1Count,w1))
        return false;
    uint32_t i0[4]{},i1[4]{};
    float v0[4]{},v1[4]{};

    struct Top1Ctx {
        VulkanCompute* g;
        const GpuWeightView* w;
        const float* inputBatch;
        uint32_t batch;
        uint32_t rowBegin;
        uint32_t* outToken;
        float* outValue;
        uint64_t epoch;
        bool ok;
    };
    auto runFn=[](void* p) noexcept -> bool {
        auto* c=static_cast<Top1Ctx*>(p);
        c->ok=c->g->RunWeightBatchQ4KTop1(
            *c->w,c->inputBatch,c->batch,c->rowBegin,
            c->outToken,c->outValue,c->epoch);
        return c->ok;
    };
    Top1Ctx c0{&g0,&w0,inputBatch,batch,p.row0Begin,i0,v0,epoch,false};
    Top1Ctx c1{&g1,&w1,inputBatch,batch,p.row1Begin,i1,v1,epoch,false};

    const bool both=rowExecutor().run(
        DualRowJob{runFn,&c0},
        DualRowJob{runFn,&c1});
    if(!both||!c0.ok||!c1.ok) return false;
    for(uint32_t n=0;n<batch;++n) {
        if(v1[n]>v0[n] || (v1[n]==v0[n]&&i1[n]<i0[n])) {
            outToken[n]=i1[n];outValue[n]=v1[n];
        } else {
            outToken[n]=i0[n];outValue[n]=v0[n];
        }
    }
    return true;
}

bool Deep2RunDualGpuColumnSplitBatch4PrimaryResident(
    VulkanCompute& primary,VulkanCompute& secondary,
    const WeightTensor& wt,const float* inputBatch,
    VulkanCompute::DeviceBuf& primaryOutput,
    uint32_t batch,uint64_t epoch)
{
    if(!inputBatch||!primaryOutput||!batch||batch>4) return false;
    const Q4KColumnSlices* s=q4kColumnSlices(wt);
    if(!s) return false;
    const uint32_t rows=(uint32_t)wt.rows;
    const size_t n=(size_t)batch*rows;

    static thread_local std::vector<float> x0;
    static thread_local std::vector<float> x1;
    static thread_local std::vector<float> y0;
    static thread_local std::vector<float> y1;
    x0.resize((size_t)batch*s->cols0);
    x1.resize((size_t)batch*s->cols1);
    for(uint32_t b=0;b<batch;++b) {
        const float* src=inputBatch+(size_t)b*wt.cols;
        std::memcpy(x0.data()+(size_t)b*s->cols0,src,
                    (size_t)s->cols0*sizeof(float));
        std::memcpy(x1.data()+(size_t)b*s->cols1,src+s->cols0,
                    (size_t)s->cols1*sizeof(float));
    }

    GpuWeightView w0{},w1{};
    w0.data=s->w0.data();w0.bytes=s->w0.size();w0.type=12;
    w0.rows=rows;w0.cols=s->cols0;
    w1.data=s->w1.data();w1.bytes=s->w1.size();w1.type=12;
    w1.rows=rows;w1.cols=s->cols1;

    y0.resize(n);
    y1.resize(n);

    struct ResidentCtx {
        VulkanCompute* g;
        const GpuWeightView* w;
        const float* x;
        float* y;
        uint32_t batch;
        uint64_t epoch;
        bool ok;
    };
    auto runFn=[](void* p) noexcept -> bool {
        auto* c=static_cast<ResidentCtx*>(p);
        c->ok=c->g->RunWeightHostBatchQ4K(
            *c->w,c->x,c->y,c->batch,c->epoch);
        return c->ok;
    };
    ResidentCtx c0{&primary,&w0,x0.data(),y0.data(),batch,epoch,false};
    ResidentCtx c1{&secondary,&w1,x1.data(),y1.data(),batch,epoch,false};

    const bool both=rowExecutor().run(
        DualRowJob{runFn,&c0},
        DualRowJob{runFn,&c1});
    if(!both||!c0.ok||!c1.ok) return false;

    // One host->GPU0 materialization for the owner partial, then reduce only
    // GPU1's partial into it. The next operation can remain on GPU0.
    if(!primary.UploadVector(primaryOutput,y0.data(),n)) return false;
    return primary.ReduceHostPartialInto(primaryOutput,y1.data(),(uint32_t)n);
}
bool Deep2RunDualGpuRowSplitBatch4PrimaryAssembled(
    VulkanCompute& primary,VulkanCompute& secondary,
    const WeightTensor& wt,const float* inputBatch,
    uint32_t batch,uint64_t epoch,
    VulkanCompute::DeviceBuf** fullOutput)
{
    if(!inputBatch||!batch||batch>4) return false;
    const CachedDualRowPlan* cp=
        Deep2GetCachedDualRowPlan(wt,primary,secondary);
    if(!cp||!cp->valid) return false;
    const auto& p=cp->split;
    const auto& w0=cp->gpu0;
    const auto& w1=cp->gpu1;

    // One shared activation upload to each card.
    if(!primary.UploadResidentBatchInput(
            inputBatch,w0.cols,batch,epoch)||
       !secondary.UploadResidentBatchInput(
            inputBatch,w1.cols,batch,epoch))
        return false;

    if(!primary.EnsureScratch(140,(size_t)batch*w0.rows)||
       !secondary.EnsureScratch(140,(size_t)batch*w1.rows))
        return false;
    auto& y0=primary.Scratch(140);
    auto& y1=secondary.Scratch(140);

    struct AssembledCtx {
        VulkanCompute* g;
        const void* wdata;
        size_t wbytes;
        VulkanCompute::DeviceBuf input;
        VulkanCompute::DeviceBuf output;
        uint32_t rows;
        uint32_t cols;
        uint32_t batch;
        bool ok;
    };
    auto runFn=[](void* p) noexcept -> bool {
        auto* c=static_cast<AssembledCtx*>(p);
        c->ok=c->g->DispatchGemvQ4KBatch(
            c->wdata,c->wbytes,c->input,c->output,
            c->rows,c->cols,c->batch);
        return c->ok;
    };
    AssembledCtx c0{&primary,w0.data,w0.bytes,
        primary.ResidentBatchInput(),y0,
        w0.rows,w0.cols,batch,false};
    AssembledCtx c1{&secondary,w1.data,w1.bytes,
        secondary.ResidentBatchInput(),y1,
        w1.rows,w1.cols,batch,false};

    const bool both=rowExecutor().run(
        DualRowJob{runFn,&c0},
        DualRowJob{runFn,&c1});
    if(!both||!c0.ok||!c1.ok) return false;

    if(!primary.CopyDeviceSliceIntoFullOutput(
            y0,w0.rows,p.row0Begin,(uint32_t)wt.rows,batch))
        return false;

    std::vector<float> remote((size_t)batch*w1.rows);
    if(!secondary.DownloadVector(y1,remote.data(),remote.size()))
        return false;
    if(!primary.ImportHostRowsIntoFullOutput(
            remote.data(),w1.rows,p.row1Begin,(uint32_t)wt.rows,batch))
        return false;

    if(fullOutput) *fullOutput=&primary.ResidentFullOutput();
    return true;
}
bool Deep2RunDualGpuRowSplitBatch4Async(
    VulkanCompute& g0,VulkanCompute& g1,
    const WeightTensor& wt,const float* inputBatch,
    float* outputBatch,uint32_t batch,uint64_t epoch,
    uint64_t* overlapNs,uint64_t* wallNs)
{
    if(overlapNs) *overlapNs=0;
    if(wallNs) *wallNs=0;
    if(!inputBatch||!outputBatch||!batch||batch>4) return false;
    const CachedDualRowPlan* cp=Deep2GetCachedDualRowPlan(wt,g0,g1);
    if(!cp||!cp->valid) return false;
    const auto& p=cp->split;
    const auto& w0=cp->gpu0;
    const auto& w1=cp->gpu1;

    if(!g0.UploadResidentBatchInput(inputBatch,w0.cols,batch,epoch)||
       !g1.UploadResidentBatchInput(inputBatch,w1.cols,batch,epoch))
        return false;
    if(!g0.EnsureScratch(150,(size_t)batch*w0.rows)||
       !g1.EnsureScratch(150,(size_t)batch*w1.rows))
        return false;
    auto& y0=g0.Scratch(150);
    auto& y1=g1.Scratch(150);

    VulkanCompute::Q4KAsyncTicket a0{},a1{};
    const auto start=std::chrono::steady_clock::now();
    if(!g0.BeginQ4KResidentAsync(w0,g0.ResidentBatchInput(),y0,batch,epoch,a0))
        return false;
    if(!g1.BeginQ4KResidentAsync(w1,g1.ResidentBatchInput(),y1,batch,epoch,a1)) {
        g0.CancelQ4KAsync(a0);
        return false;
    }

    uint64_t n0=0,n1=0;
    if(!g0.WaitQ4KResidentAsync(a0,&n0)) {
        g1.CancelQ4KAsync(a1); return false;
    }
    if(!g1.WaitQ4KResidentAsync(a1,&n1)) return false;

    // Launch secondary transfer through persistent ring after arithmetic.
    uint32_t ringSlot=0;
    const size_t bytes1=(size_t)batch*w1.rows*sizeof(float);
    if(!g1.SubmitDownloadRing(y1,bytes1,ringSlot)) return false;

    // GPU0 slice can be returned/placed while the secondary transfer is live.
    static thread_local std::vector<float> h0;
    static thread_local std::vector<float> h1;
    h0.resize((size_t)batch*w0.rows);
    if(!g0.DownloadVector(y0,h0.data(),h0.size())) return false;

    h1.resize((size_t)batch*w1.rows);
    if(!g1.WaitDownloadRing(ringSlot,h1.data(),bytes1)) return false;
    for(uint32_t b=0;b<batch;++b) {
        float* dst=outputBatch+(size_t)b*wt.rows;
        std::memcpy(
            dst+p.row0Begin,h0.data()+(size_t)b*w0.rows,
            (size_t)w0.rows*sizeof(float));
        std::memcpy(
            dst+p.row1Begin,h1.data()+(size_t)b*w1.rows,
            (size_t)w1.rows*sizeof(float));
    }
    const auto finish=std::chrono::steady_clock::now();
    const uint64_t wall=(uint64_t)std::chrono::duration_cast<
        std::chrono::nanoseconds>(finish-start).count();
    const uint64_t ov=n0+n1>wall ? n0+n1-wall : 0;
    if(overlapNs) *overlapNs=ov;
    if(wallNs) *wallNs=wall;
    return true;
}
bool Deep2WaitDualQ4KFanIn(
    VulkanCompute& g0,VulkanCompute::Q4KAsyncTicket& t0,
    VulkanCompute& g1,VulkanCompute::Q4KAsyncTicket& t1,
    DualAsyncFanIn& out)
{
    out={};
    if(!t0.active||!t1.active) return false;
    const auto begin=std::chrono::steady_clock::now();

    // Polling interval is deliberately coarse enough not to burn a CPU core.
    // Actual GPU completion still uses Vulkan fences as authority.
    bool d0=false,d1=false;
    auto done=[&](VkDevice dev,VkFence f)->bool {
        const VkResult r=vkGetFenceStatus(dev,f);
        return r==VK_SUCCESS;
    };
    while(!(d0&&d1)) {
        d0=d0||done(g0.DeviceHandle(),t0.fence);
        d1=d1||done(g1.DeviceHandle(),t1.fence);
        if(!(d0&&d1))
            std::this_thread::yield();
    }
    const auto ready=std::chrono::steady_clock::now();
    out.hostSpinNs=(uint64_t)std::chrono::duration_cast<
        std::chrono::nanoseconds>(ready-begin).count();

    uint64_t n0=0,n1=0;
    if(!g0.WaitQ4KResidentAsync(t0,&n0)) return false;
    if(!g1.WaitQ4KResidentAsync(t1,&n1)) return false;
    const auto finish=std::chrono::steady_clock::now();
    out.gpu0Ns=n0;out.gpu1Ns=n1;
    out.wallNs=(uint64_t)std::chrono::duration_cast<
        std::chrono::nanoseconds>(finish-begin).count();
    out.overlapNs=(n0+n1>out.wallNs)?n0+n1-out.wallNs:0;
    updateOverlapEfficiency(n0,n1,out.wallNs);
    return true;
}

} // namespace Deep2
