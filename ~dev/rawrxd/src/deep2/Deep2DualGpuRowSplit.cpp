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
namespace {

long double envThroughput(const char* name) noexcept;
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
}

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
struct ColKey {
    const void* p=nullptr;size_t bytes=0;uint32_t rows=0,cols=0;
    uint16_t ratioPermille=500;
    bool operator==(const ColKey& o) const noexcept {
        return p==o.p&&bytes==o.bytes&&rows==o.rows&&cols==o.cols&&
               ratioPermille==o.ratioPermille;
    }
};
struct ColHash {
    size_t operator()(const ColKey& k) const noexcept {
        return (size_t)(uintptr_t)k.p ^ k.bytes ^
               ((size_t)k.rows<<32) ^ k.cols ^
               ((size_t)k.ratioPermille<<11);
    }
};

const Q4KColumnSlices* q4kColumnSlices(const WeightTensor& wt) {
    if(wt.type!=(int)GGMLType::GGML_TYPE_Q4_K||!wt.data||
       !wt.rows||!wt.cols||wt.cols%256u!=0u) return nullptr;
    static std::mutex mu;
    static std::unordered_map<ColKey,Q4KColumnSlices,ColHash> cache;
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
    const ColKey key{
        wt.data,wt.sizeBytes,(uint32_t)wt.rows,(uint32_t)wt.cols,pm};
    std::lock_guard<std::mutex> g(mu);
    auto it=cache.find(key);
    if(it!=cache.end()) return &it->second;

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

    Q4KColumnSlices s{};
    s.cols0=b0*256u;s.cols1=b1*256u;
    s.w0.resize((size_t)wt.rows*row0);
    s.w1.resize((size_t)wt.rows*row1);
    const auto* src=(const uint8_t*)wt.data;
    for(size_t r=0;r<wt.rows;++r) {
        std::memcpy(s.w0.data()+r*row0,src+r*rowBytes,row0);
        std::memcpy(s.w1.data()+r*row1,src+r*rowBytes+row0,row1);
    }
    auto ins=cache.emplace(key,std::move(s));
    return &ins.first->second;
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
    std::vector<float> x0((size_t)batch*s->cols0);
    std::vector<float> x1((size_t)batch*s->cols1);
    for(uint32_t b=0;b<batch;++b) {
        const float* src=inputBatch+(size_t)b*wt.cols;
        std::memcpy(x0.data()+(size_t)b*s->cols0,src,
                    (size_t)s->cols0*sizeof(float));
        std::memcpy(x1.data()+(size_t)b*s->cols1,src+s->cols0,
                    (size_t)s->cols1*sizeof(float));
    }
    std::vector<float> y0((size_t)batch*rows);
    std::vector<float> y1((size_t)batch*rows);
    GpuWeightView w0{},w1{};
    w0.data=s->w0.data();w0.bytes=s->w0.size();w0.type=12;
    w0.rows=rows;w0.cols=s->cols0;
    w1.data=s->w1.data();w1.bytes=s->w1.size();w1.type=12;
    w1.rows=rows;w1.cols=s->cols1;

    bool ok0=false,ok1=false;
    uint64_t ns0=0,ns1=0;
    const bool both=rowExecutor().run(
        [&]{
            const auto a=std::chrono::steady_clock::now();
            ok0=g0.RunWeightHostBatchQ4K(
                w0,x0.data(),y0.data(),batch,epoch);
            const auto z=std::chrono::steady_clock::now();
            ns0=(uint64_t)std::chrono::duration_cast<
                std::chrono::nanoseconds>(z-a).count();
            return ok0;
        },
        [&]{
            const auto a=std::chrono::steady_clock::now();
            ok1=g1.RunWeightHostBatchQ4K(
                w1,x1.data(),y1.data(),batch,epoch);
            const auto z=std::chrono::steady_clock::now();
            ns1=(uint64_t)std::chrono::duration_cast<
                std::chrono::nanoseconds>(z-a).count();
            return ok1;
        });
    if(!both||!ok0||!ok1) return false;
    updateColSpeed(0,s->cols0,ns0);
    updateColSpeed(1,s->cols1,ns1);

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
    struct Item {
        RowSplitPlan p{};
        GpuWeightView w[2]{};
        std::vector<float> y[2];
    };
    std::vector<Item> it(weightCount);
    for(size_t i=0;i<weightCount;++i) {
        if(!weights[i]||!outputs[i]||
           weights[i]->type!=(int)GGMLType::GGML_TYPE_Q4_K)
            return false;
        it[i].p=cachedThroughputSplit(*weights[i],g0,g1);
        if(!it[i].p.valid||
           !Deep2BuildGpuWeightView(
               *weights[i],it[i].p.row0Begin,it[i].p.row0Count,it[i].w[0])||
           !Deep2BuildGpuWeightView(
               *weights[i],it[i].p.row1Begin,it[i].p.row1Count,it[i].w[1]))
            return false;
        it[i].y[0].resize((size_t)batch*it[i].p.row0Count);
        it[i].y[1].resize((size_t)batch*it[i].p.row1Count);
    }
    // Both cards receive the shared activation ONCE.
    if(!g0.UploadResidentBatchInput(
            inputBatch,weights[0]->cols,batch,epoch)||
       !g1.UploadResidentBatchInput(
            inputBatch,weights[0]->cols,batch,epoch))
        return false;

    std::vector<float> slab[2];
    size_t offsets[2][3]{};
    for(unsigned s=0;s<2;++s) {
        size_t total=0;
        for(size_t i=0;i<weightCount;++i)
            total+=(size_t)batch*it[i].w[s].rows;
        slab[s].resize(total);
    }

    auto lane=[&](unsigned s,VulkanCompute& g)->bool {
        GpuWeightView views[3]{};
        for(size_t i=0;i<weightCount;++i) {
            views[i]=it[i].w[s];
        }
        return g.RunWeightGroupResidentInputQ4KSingleReturn(
            views,slab[s].data(),offsets[s],
            weightCount,weights[0]->cols,batch,epoch);
    };

    bool a=false,b=false;
    const bool both=rowExecutor().run(
        [&]{a=lane(0,g0);return a;},
        [&]{b=lane(1,g1);return b;});
    if(!both||!a||!b) return false;
    for(size_t i=0;i<weightCount;++i) {
        for(uint32_t t=0;t<batch;++t) {
            float* dst=outputs[i]+(size_t)t*weights[i]->rows;
            std::memcpy(
                dst+it[i].p.row0Begin,
                slab[0].data()+offsets[0][i]+
                    (size_t)t*it[i].p.row0Count,
                (size_t)it[i].p.row0Count*sizeof(float));
            std::memcpy(
                dst+it[i].p.row1Begin,
                slab[1].data()+offsets[1][i]+
                    (size_t)t*it[i].p.row1Count,
                (size_t)it[i].p.row1Count*sizeof(float));
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

long double envThroughput(const char* name) noexcept {
    const char* s=std::getenv(name);
    if(!s||!*s) return 1.0L;
    char* end=nullptr;
    const long double v=std::strtold(s,&end);
    return end!=s && v>0.0L ? v : 1.0L;
}

RowSplitPlan chooseThroughputSplit(
    uint32_t rows,const VulkanCompute& g0,const VulkanCompute& g1) noexcept
{
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

    bool run(std::function<bool()> a, std::function<bool()> b) {
        std::unique_lock<std::mutex> lk(mu_);
        done_[0] = done_[1] = false;
        result_[0] = result_[1] = false;
        job_[0] = std::move(a);
        job_[1] = std::move(b);
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
            std::function<bool()> fn;
            uint64_t g = 0;
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait(lk, [&]{ return stop_ || generation_ != seen; });
                if (stop_) return;
                seen = generation_;
                g = seen;
                fn = job_[lane];
            }
            const bool r = fn ? fn() : false;
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
    std::function<bool()> job_[2];
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

    RowSplitPlan plan=cachedThroughputSplit(wt,g0,g1);
    if(!plan.valid) return false;

    GpuWeightView w0{},w1{};
    if(!Deep2BuildGpuWeightView(wt,plan.row0Begin,plan.row0Count,w0) ||
       !Deep2BuildGpuWeightView(wt,plan.row1Begin,plan.row1Count,w1))
        return false;

    auto run=[&](unsigned lane,VulkanCompute& g,const GpuWeightView& w,
                 float* dst)->bool{
        const auto t0=std::chrono::steady_clock::now();
        const bool ok=g.RunWeightHostRoundTrip(w,input,dst,epoch);
        const auto t1=std::chrono::steady_clock::now();
        if(ok){
            const uint64_t ns=(uint64_t)
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    t1-t0).count();
            updateAutoSpeed(lane,w.rows,ns);
        }
        return ok;
    };

    // Reuse caller-thread buffers across all matrices/tokens.
    static thread_local std::vector<float> y0;
    static thread_local std::vector<float> y1;
    y0.resize(plan.row0Count);
    y1.resize(plan.row1Count);

    bool ok0=false,ok1=false;
    const bool both = rowExecutor().run(
        [&]{ ok0=run(0,g0,w0,y0.data()); return ok0; },
        [&]{ ok1=run(1,g1,w1,y1.data()); return ok1; });

    if(!both||!ok0||!ok1) return false;

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

bool Deep2RunDualGpuRowSplitGroup(
    VulkanCompute& g0,VulkanCompute& g1,
    const WeightTensor* const* weights,float* const* outputs,size_t count,
    const float* input,uint32_t inputCount,uint64_t epoch,
    RowSplitReceipt* receipt)
{
    if(receipt) *receipt={};
    if(!weights||!outputs||!input||!inputCount||count<2||count>3)
        return false;

    struct Item {
        RowSplitPlan p{};
        GpuWeightView w[2]{};
        std::vector<float> y[2];
    };
    std::vector<Item> items(count);

    for(size_t i=0;i<count;++i){
        if(!weights[i]||!outputs[i]||weights[i]->cols!=inputCount||
           weights[i]->rows<2||!supportedGpuType(weights[i]->type))
            return false;
        items[i].p=chooseThroughputSplit(
            (uint32_t)weights[i]->rows,g0,g1);

        if(!items[i].p.valid) return false;
        if(!Deep2BuildGpuWeightView(
                *weights[i],items[i].p.row0Begin,items[i].p.row0Count,
                items[i].w[0]) ||
           !Deep2BuildGpuWeightView(
                *weights[i],items[i].p.row1Begin,items[i].p.row1Count,
                items[i].w[1]))
            return false;
        items[i].y[0].resize(items[i].p.row0Count);
        items[i].y[1].resize(items[i].p.row1Count);
    }

    auto laneRun=[&](unsigned lane,VulkanCompute& g)->bool{
        GpuWeightView views[3]{};
        float* outs[3]{};
        for(size_t i=0;i<count;++i){
            views[i]=items[i].w[lane];
            outs[i]=items[i].y[lane].data();
        }
        return g.RunWeightGroupHostRoundTrip(
            views,outs,count,input,inputCount,epoch);
    };

    bool ok0=false,ok1=false;
    const bool both=rowExecutor().run(
        [&]{ok0=laneRun(0,g0);return ok0;},
        [&]{ok1=laneRun(1,g1);return ok1;});
    if(!both||!ok0||!ok1) return false;

    for(size_t i=0;i<count;++i){
        std::memcpy(outputs[i]+items[i].p.row0Begin,items[i].y[0].data(),
                    items[i].y[0].size()*sizeof(float));
        std::memcpy(outputs[i]+items[i].p.row1Begin,items[i].y[1].data(),
                    items[i].y[1].size()*sizeof(float));
    }

    if(receipt){
        receipt->valid=true;
        receipt->gpu0=true;
        receipt->gpu1=true;
        receipt->hostMerge=true;
        for(size_t i=0;i<count;++i){
            receipt->rows0+=items[i].p.row0Count;
            receipt->rows1+=items[i].p.row1Count;
        }
        auto overlap=Deep2Gpu_MeasureArithmeticOverlap(g0,g1,epoch);
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
       wt.rows<2||!wt.cols)
        return false;

    RowSplitPlan p=cachedThroughputSplit(wt,g0,g1);
    if(!p.valid) return false;
    GpuWeightView w0{},w1{};
    if(!Deep2BuildGpuWeightView(wt,p.row0Begin,p.row0Count,w0)||
       !Deep2BuildGpuWeightView(wt,p.row1Begin,p.row1Count,w1))
        return false;

    std::vector<float> y0((size_t)batch*p.row0Count);
    std::vector<float> y1((size_t)batch*p.row1Count);
    bool ok0=false,ok1=false;
    const bool both=rowExecutor().run(
        [&]{
            ok0=g0.RunWeightHostBatchQ4K(
                w0,inputBatch,y0.data(),batch,epoch);
            return ok0;
        },
        [&]{
            ok1=g1.RunWeightHostBatchQ4K(
                w1,inputBatch,y1.data(),batch,epoch);
            return ok1;
        });
    if(!both||!ok0||!ok1) return false;

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
    bool a=false,b=false;
    const bool both=rowExecutor().run(
        [&]{a=g0.RunWeightBatchQ4KTop1(
            w0,inputBatch,batch,p.row0Begin,i0,v0,epoch);return a;},
        [&]{b=g1.RunWeightBatchQ4KTop1(
            w1,inputBatch,batch,p.row1Begin,i1,v1,epoch);return b;});
    if(!both||!a||!b) return false;
    for(uint32_t n=0;n<batch;++n) {
        if(v1[n]>v0[n] || (v1[n]==v0[n]&&i1[n]<i0[n])) {
            outToken[n]=i1[n];outValue[n]=v1[n];
        } else {
            outToken[n]=i0[n];outValue[n]=v0[n];
        }
    }
    return true;
}

} // namespace Deep2

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

    std::vector<float> x0((size_t)batch*s->cols0);
    std::vector<float> x1((size_t)batch*s->cols1);
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

    std::vector<float> y0(n),y1(n);
    bool a=false,b=false;
    const bool both=rowExecutor().run(
        [&]{a=primary.RunWeightHostBatchQ4K(
            w0,x0.data(),y0.data(),batch,epoch);return a;},
        [&]{b=secondary.RunWeightHostBatchQ4K(
            w1,x1.data(),y1.data(),batch,epoch);return b;});
    if(!both||!a||!b) return false;

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

    bool ok0=false,ok1=false;
    const bool both=rowExecutor().run(
        [&]{
            ok0=primary.DispatchGemvQ4KBatch(
                w0.data,w0.bytes,
                primary.ResidentBatchInput(),y0,
                w0.rows,w0.cols,batch);
            return ok0;
        },
        [&]{
            ok1=secondary.DispatchGemvQ4KBatch(
                w1.data,w1.bytes,
                secondary.ResidentBatchInput(),y1,
                w1.rows,w1.cols,batch);
            return ok1;
        });
    if(!both||!ok0||!ok1) return false;

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
    std::vector<float> h0((size_t)batch*w0.rows);
    if(!g0.DownloadVector(y0,h0.data(),h0.size())) return false;

    std::vector<float> h1((size_t)batch*w1.rows);
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
