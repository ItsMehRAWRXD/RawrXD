#include "deep2/ReapQ4KToQ2K.hpp"
#include "deep2/ReapMixedPrecision.hpp"
#include "deep2/ReapShardIndex.hpp"
#include "deep2/ReapRetainedRouting.hpp"
#include "deep2/ReapBoundedExpertCache.hpp"
#include "deep2/ReapExpertPrefetch.hpp"
#include "deep2/ReapVirtualPayload.hpp"
#include "deep2/ReapSubmissionPins.hpp"
#include "deep2/ReapStrataBudget.hpp"
#include "deep2/ReapExpertCompute.hpp"
#include "deep2/ReapGlmMoe.hpp"
#include "deep2/ReapMlaReference.hpp"
#include "deep2/ReapLocalRequest.hpp"
#include "deep2/ReapAgentGroup.hpp"
#include "deep2/ReapFairDispatch.hpp"
#include "deep2/ReapDemandHistory.hpp"
#include <thread>
#include <atomic>
#include "deep2/ReapNativeShardReader.hpp"
#include <cstdio>
#if defined(_WIN32) && defined(_MSC_VER)
#include <intrin.h>
static bool hasAvx2(){
    int info[4]{};
    __cpuid(info,0);
    if(info[0]<7)return false;
    __cpuid(info,1);
    if((info[2]&((1<<27)|(1<<28)))!=((1<<27)|(1<<28)))return false;
    if((_xgetbv(0)&6)!=6)return false;
    __cpuidex(info,7,0);
    return (info[1] & (1<<5)) != 0;
}
#endif
using namespace Deep2::ReapQuant;
int main(){
    int pass=0,fail=0;auto check=[&](bool ok,const char* n){std::printf("%s %s\n",ok?"PASS":"FAIL",n);ok?++pass:++fail;};
    std::vector<ExpertCost> costs{{1,1,10,10,2},{2,1,1,10,2}};
    MixedPlan plan;
    check(PlanMixed(costs,168,plan)&&plan.bytes==168&&plan.weightedError==110,"mixed minimum budget");
    check(PlanMixed(costs,194,plan)&&plan.choices[0].precision==Precision::Q3&&plan.choices[1].precision==Precision::Q2&&plan.weightedError==30,"mixed importance prioritizes upgrade");
    check(PlanMixed(costs,288,plan)&&plan.bytes==288&&plan.weightedError==0,"mixed full precision budget");
    check(!PlanMixed(costs,167,plan)&&plan.bytes==288,"mixed infeasible budget preserves output");
    auto invalid=costs;invalid[1].id=1;
    check(!PlanMixed(invalid,288,plan),"mixed duplicate expert rejected");
    invalid=costs;invalid[0].importance=std::numeric_limits<double>::infinity();
    check(!PlanMixed(invalid,288,plan),"mixed nonfinite importance rejected");
    invalid=costs;invalid[0].blocks=UINT64_MAX;
    check(!PlanMixed(invalid,UINT64_MAX,plan),"mixed overflow rejected");
    ShardIndex index; ShardRange range{};
    check(index.AddShard(1,UINT64_C(1)<<40)&&index.AddShard(2,4096),"shard register large and small");
    check(!index.AddShard(1,128),"shard duplicate rejected");
    check(index.AddTensor("gate",{1,UINT64_C(1)<<39,1024})&&index.AddTensor("up",{2,128,1024}),"tensor register across shards");
    check(!index.AddTensor("bad",{2,4090,8}),"tensor outside shard rejected");
    check(!index.AddTensor("gate",{2,0,32}),"tensor duplicate rejected");
    check(!index.Resolve("gate",0,16,range),"unsealed lookup rejected");
    check(index.Seal()&&!index.AddShard(3,4096),"sealed index immutable");
    check(index.ResolveExpert("gate",3,8,128,84,range)&&range.shard==1&&range.offset==(UINT64_C(1)<<39)+384&&range.bytes==84,"expert 64-bit shard address");
    check(index.ResolveExpert("up",7,8,128,110,range)&&range.shard==2&&range.offset==1024,"expert second shard address");
    check(!index.ResolveExpert("up",8,8,128,110,range),"expert index bounds");
    check(!index.ResolveExpert("up",0,UINT64_MAX,128,110,range),"expert stride overflow");
    check(!index.Resolve("up",1020,8,range)&&range.shard==2&&range.offset==1024,"failed lookup preserves output");
#ifdef _WIN32
    {
        wchar_t dir[MAX_PATH]{},name[MAX_PATH]{};
        const DWORD n=GetTempPathW(MAX_PATH,dir);
        const bool temp=n>0&&n<MAX_PATH&&GetTempFileNameW(dir,L"rxq",0,name)!=0;
        check(temp,"native shard temporary fixture");
        if(temp){
            const std::vector<uint8_t> fixture{10,20,30,40,50,60,70,80};
            HANDLE h=CreateFileW(name,GENERIC_WRITE,0,nullptr,TRUNCATE_EXISTING,0,nullptr);
            DWORD written=0;
            bool ready=h!=INVALID_HANDLE_VALUE&&WriteFile(h,fixture.data(),DWORD(fixture.size()),&written,nullptr)&&written==fixture.size();
            if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);
            check(ready,"native shard fixture write");
            if(ready){
                NativeShardReader reader;
                check(!reader.Open(1,name,7),"native shard size mismatch rejected");
                check(reader.Open(1,name,8),"native shard open");
                std::vector<uint8_t> data{99};
                check(!reader.Read({1,2,3},3,data)&&data==std::vector<uint8_t>{99},"native shard unsealed read rejected");
                check(reader.Seal(),"native shard seal");
                check(reader.Read({1,2,3},3,data)&&data==std::vector<uint8_t>({30,40,50}),"native shard exact offset read");
                check(!reader.Read({1,2,3},2,data)&&data==std::vector<uint8_t>({30,40,50}),"native shard budget preserves output");
                check(!reader.Read({1,7,2},8,data),"native shard EOF bounds");
                HANDLE writer=CreateFileW(name,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
                check(writer==INVALID_HANDLE_VALUE,"native shard denies concurrent writer");
                if(writer!=INVALID_HANDLE_VALUE)CloseHandle(writer);
                check(!reader.Open(2,name,8),"native shard sealed registration refused");
            }
            check(DeleteFileW(name)!=0,"native shard handle released");
        }
    }
#endif
    std::vector<RouteChoice> routes;
    check(RouteRetained({0,100,0},{2,0},{},RouterScore::Softmax,2,true,1.8,routes)&&routes.size()==2&&routes[0].original==0&&routes[0].retained==1&&std::abs(routes[0].weight-0.9)<1e-12,"retained softmax mapping and stable tie");
    check(RouteRetained({0,100,0},{2,0},{},RouterScore::Softmax,1,false,1,routes)&&routes[0].weight==0.5,"retained softmax excludes pruned logits");
    check(RouteRetained({0,2},{0,1},{2,0},RouterScore::Sigmoid,1,false,1,routes)&&routes[0].original==0&&routes[0].weight==0.5,"sigmoid bias only affects rank");
    check(RouteRetained({-1000,1000},{0,1},{},RouterScore::Sigmoid,1,true,2,routes)&&routes[0].original==1&&routes[0].weight==2,"stable sigmoid extremes");
    check(!RouteRetained({0,1},{0,0},{},RouterScore::Softmax,1,true,1,routes)&&routes[0].weight==2,"duplicate mapping preserves output");
    check(!RouteRetained({0,1},{0,2},{},RouterScore::Softmax,1,true,1,routes),"invalid original expert rejected");
    check(!RouteRetained({0,1},{0},{},RouterScore::Softmax,2,true,1,routes),"invalid top k rejected");
    check(!RouteRetained({-1000},{0},{},RouterScore::Sigmoid,1,true,1,routes),"zero selected mass rejected");
    {
        BoundedExpertCache cache(16);
        BoundedExpertCache::Lease a,b,c;
        std::atomic<unsigned> loads{0};
        auto fill=[&](uint8_t* p,size_t n){++loads;std::fill(p,p+n,42);return true;};
        check(cache.Acquire("a",8,fill,a)&&cache.Reserved()==8,"cache first load");
        check(cache.Acquire("a",8,fill,b)&&a==b&&loads==1,"cache shared hit");
        check(cache.Acquire("b",8,fill,c)&&cache.Reserved()==16,"cache budget filled");
        check(!cache.Acquire("c",8,fill,c)&&cache.Reserved()==16&&(*c)[0]==42,"cache pinned budget refusal");
        a.reset();b.reset();
        check(cache.Acquire("c",8,fill,a)&&cache.Reserved()==16,"cache evicts unpinned entry");
        c.reset();
        auto failLoad=[](uint8_t*,size_t){return false;};
        check(!cache.Acquire("d",8,failLoad,b)&&cache.Reserved()==8,"cache failed load rollback");
        check(!cache.Acquire("c",7,fill,b),"cache conflicting size rejected");
        BoundedExpertCache shared(8);
        std::atomic<unsigned> sharedLoads{0}, successes{0};
        std::vector<std::thread> workers;
        std::array<BoundedExpertCache::Lease,6> leases{};
        for(size_t i=0;i<leases.size();++i)workers.emplace_back([&,i]{
            if(shared.Acquire("shared",8,[&](uint8_t* p,size_t n){++sharedLoads;std::fill(p,p+n,17);return true;},leases[i]))++successes;
        });
        for(auto& worker:workers)worker.join();
        check(successes==6&&sharedLoads==1&&shared.Reserved()==8,"cache six worker coalesced load");
        bool same=true;for(const auto& lease:leases)same=same&&lease&&lease==leases[0]&&(*lease)[0]==17;
        check(same,"cache six worker identical payload");
    }
    {
        BoundedExpertCache cache(32);
        ExpertPrefetch prefetch(cache,3);
        std::mutex gate;
        std::condition_variable signal;
        bool started=false,released=false;
        std::vector<int> order;
        auto blocking=[&](uint8_t* p,size_t n){
            std::unique_lock<std::mutex> lock(gate);
            started=true;signal.notify_all();
            signal.wait(lock,[&]{return released;});
            std::fill(p,p+n,11);return true;
        };
        auto load=[&](int id){return [&,id](uint8_t* p,size_t n){
            order.push_back(id);std::fill(p,p+n,uint8_t(id));return true;
        };};
        const bool submitted=prefetch.Submit("running",8,0,blocking);
        check(submitted,"prefetch initial submit");
        if(submitted){
            {std::unique_lock<std::mutex> lock(gate);signal.wait(lock,[&]{return started;});}
            check(prefetch.Submit("low",8,1,load(1)),"prefetch low priority queued");
            check(prefetch.Submit("high",8,9,load(9)),"prefetch high priority queued");
            check(!prefetch.Submit("running",8,1,load(2)),"prefetch duplicate rejected");
            check(!prefetch.Submit("overflow",8,1,load(2)),"prefetch outstanding bound");
            check(prefetch.CancelQueued("low")&&!prefetch.CancelQueued("running"),"prefetch queued-only cancellation");
            check(prefetch.Submit("medium",8,4,load(4)),"prefetch slot reused");
            {std::lock_guard<std::mutex> lock(gate);released=true;signal.notify_all();}
            prefetch.WaitIdle();
            check(order==std::vector<int>({9,4}),"prefetch priority and canceled job order");
            BoundedExpertCache::Lease lease;
            check(cache.Acquire("high",8,[](uint8_t*,size_t){return false;},lease)&&lease&&(*lease)[0]==9,"prefetch actual cache residency");
        }
        prefetch.Stop();
        check(!prefetch.Submit("closed",8,1,load(1)),"prefetch stopped admission");
    }
    {
        struct FixtureReader {
            std::vector<uint8_t> bytes=std::vector<uint8_t>(2*Q4Bytes,0);
            unsigned reads=0;
            bool Read(ShardRange r,uint64_t limit,std::vector<uint8_t>& out){
                if(r.shard!=1||r.bytes>limit||r.offset>bytes.size()||r.bytes>bytes.size()-r.offset)return false;
                ++reads;out.assign(bytes.begin()+r.offset,bytes.begin()+r.offset+r.bytes);return true;
            }
        } reader;
        BoundedExpertCache cache(1024);
        BoundedExpertCache::Lease a,b;
        const ShardRange source{1,0,2*Q4Bytes};
        check(AcquireVirtualPayload(reader,cache,source,Precision::Q2,Q4Bytes,a)&&a->size()==2*Q2Bytes&&reader.reads==2,"virtual Q2 bounded conversion");
        check(AcquireVirtualPayload(reader,cache,source,Precision::Q2,Q4Bytes,b)&&a==b&&reader.reads==2,"virtual cache hit no extra reads");
        check(AcquireVirtualPayload(reader,cache,source,Precision::Q3,Q4Bytes,b)&&b->size()==2*Q3Bytes&&reader.reads==4,"virtual Q3 conversion");
        check(AcquireVirtualPayload(reader,cache,source,Precision::Q4,Q4Bytes,b)&&*b==reader.bytes,"virtual Q4 exact bytes");
        check(!AcquireVirtualPayload(reader,cache,{1,0,143},Precision::Q2,Q4Bytes,b),"virtual partial block rejected");
        check(!AcquireVirtualPayload(reader,cache,source,Precision::Q2,Q4Bytes-1,b),"virtual source budget rejected");
        const auto before=cache.Reserved();
        check(!AcquireVirtualPayload(reader,cache,{2,0,Q4Bytes},Precision::Q2,Q4Bytes,b)&&cache.Reserved()==before&&b->size()==2*Q4Bytes,"virtual read failure rollback");
    }
    {
        BoundedExpertCache cache(8);
        BoundedExpertCache::Lease lease;
        auto fill=[](uint8_t* p,size_t n){std::fill(p,p+n,7);return true;};
        SubmissionPins pins(2);
        check(cache.Acquire("gpu",8,fill,lease),"submission pin fixture");
        const auto t=pins.Retain(1,{lease});lease.reset();
        check(t!=0&&!cache.Acquire("other",8,fill,lease),"submission pin prevents eviction");
        check(!pins.Resolve(1,t,SubmissionPins::Outcome::WaitFailed)&&pins.Outstanding()==1,"failed wait retains pin");
        check(!pins.Resolve(1,t,SubmissionPins::Outcome::DeviceLost),"device loss alone retains pin");
        check(!pins.Resolve(2,t,SubmissionPins::Outcome::FenceComplete),"wrong generation rejected");
        const auto mark=pins.Watermark();
        check(cache.Acquire("gpu",8,fill,lease),"submission second lease");
        const auto newer=pins.Retain(1,{lease});
        check(newer!=0&&pins.Retain(1,{lease})==0,"submission capacity enforced");
        lease.reset();
        check(pins.ReclaimConfirmedIdle(1,mark)==1&&pins.Outstanding()==1,"idle watermark excludes newer ticket");
        check(!cache.Acquire("other",8,fill,lease),"newer submission remains pinned");
        check(pins.Resolve(1,newer,SubmissionPins::Outcome::FenceComplete)&&pins.Outstanding()==0,"completion releases pin");
        check(!pins.Resolve(1,newer,SubmissionPins::Outcome::FenceComplete),"duplicate completion rejected");
        check(cache.Acquire("other",8,fill,lease),"completed payload evictable");
    }
    {
        StrataBudget budget({16,32,16,64,2});
        StrataBudget::Lease a,b;
        check(budget.Acquire({8,16,0,32,1},a),"strata atomic acquisition");
        check(budget.Used()==StrataBudget::Amount({8,16,0,32,1}),"strata exact accounting");
        check(!budget.Acquire({1,17,0,1,1},b)&&!b&&budget.Used()==StrataBudget::Amount({8,16,0,32,1}),"strata failed admission no partial reservation");
        check(budget.Acquire({8,0,16,32,1},b),"strata independent second GPU");
        check(!budget.SetLimits({15,32,16,64,2}),"strata refuses unsafe shrink");
        auto copy=a;a.reset();
        check(budget.Used()[0]==16,"strata shared lease retains reservation");
        copy.reset();
        check(budget.Used()==StrataBudget::Amount({8,0,16,32,1}),"strata final lease releases");
        check(budget.SetLimits({8,32,16,32,1}),"strata safe resize");
        check(budget.Available()==StrataBudget::Amount({0,32,0,0,0}),"strata available accounting");
        check(!budget.Acquire({0,0,0,0,0},a),"strata zero reservation rejected");
        b.reset();
        check(budget.Used()==StrataBudget::Amount{},"strata all reservations released");
        StrataBudget shared({6,6,0,0,6});
        std::array<StrataBudget::Lease,12> leases{};
        std::atomic<unsigned> successes{0};
        std::vector<std::thread> workers;
        for(size_t i=0;i<leases.size();++i)workers.emplace_back([&,i]{
            if(shared.Acquire({1,1,0,0,1},leases[i]))++successes;
        });
        for(auto& worker:workers)worker.join();
        check(successes==6&&shared.Used()==StrataBudget::Amount({6,6,0,0,6}),"strata concurrent admission exact bound");
    }
    {
        Values weights{};weights.fill(1.0f);
        Q3Block block{};
        const bool encoded=EncodeQ3(weights,block);
        check(encoded,"expert compute packed fixture");
        if(encoded){
            BoundedExpertCache fixtureCache(256*Q3Bytes);
            BoundedExpertCache::Lease payload;
            check(fixtureCache.Acquire("fixture",256*Q3Bytes,[&](uint8_t* p,size_t){
                for(size_t i=0;i<256;++i)std::memcpy(p+i*Q3Bytes,block.data(),Q3Bytes);
                return true;
            },payload),"expert fixture cache acquisition");
            ExpertMatrix m{256,256,Precision::Q3,payload};
            std::vector<float> x(256,1.0f/256),y;
            Values decoded{};DecodeQ3(block,decoded);
            double reference=0;for(float v:decoded)reference+=double(v)/256;
            check(ExpertMatVec(m,x,y)&&y.size()==256&&std::abs(y[0]-reference)<1e-5,"expert matrix numerical oracle");
            SwiGluExpert e{m,m,m};
            double rowSum=reference*256;
            double expected=rowSum*reference*reference/(1+std::exp(-reference));
            check(ExecuteExpert(e,x,y)&&y.size()==256&&std::abs(y[0]-expected)<1e-3,"expert SwiGLU numerical oracle");
            const std::vector<RouteChoice> routes{{0,0,0.25},{1,1,0.75}};
            check(ExecuteRoutedExperts(routes,x,[&](uint32_t,SwiGluExpert& out){out=e;return true;},y)&&std::abs(y[0]-expected)<1e-3,"expert weighted accumulation oracle");
            const auto previous=y;
            auto bad=m;bad.cols=255;
            check(!ExpertMatVec(bad,x,y)&&y==previous,"expert invalid geometry preserves output");
            check(!ExecuteRoutedExperts(routes,x,[](uint32_t,SwiGluExpert&){return false;},y)&&y==previous,"expert missing payload preserves output");
        }
    }
    {
        Values w{};w.fill(1.f);Q3Block block{};
        if(EncodeQ3(w,block)){
            BoundedExpertCache fixtureCache(256*Q3Bytes);
            BoundedExpertCache::Lease payload;
            check(fixtureCache.Acquire("fixture",256*Q3Bytes,[&](uint8_t* p,size_t){
                for(size_t i=0;i<256;++i)std::memcpy(p+i*Q3Bytes,block.data(),Q3Bytes);
                return true;
            },payload),"expert fixture cache acquisition");
            ExpertMatrix m{256,256,Precision::Q3,payload};
            SwiGluExpert e{m,m,m};
            std::vector<float> x(256,1.f/256),y;
            Values decoded{};DecodeQ3(block,decoded);
            double a=0;for(float v:decoded)a+=double(v)/256;
            const double expected=2.8*256*a*a*a/(1+std::exp(-a));
            unsigned routed=0,shared=0;
            auto rr=[&](uint32_t slot,SwiGluExpert& out){++routed;out=e;return slot<4;};
            auto sr=[&](size_t slot,SwiGluExpert& out){++shared;out=e;return slot==0;};
            const bool ok=ExecuteGlmMoe(x,{0,1,2,3},{3,1,0,2},4,1.8,1,rr,sr,y);
            check(ok&&routed==4&&shared==1,"GLM four routed one shared");
            bool parity=ok&&y.size()==256;
            for(float v:y)parity=parity&&std::abs(v-expected)<0.005;
            check(parity,"GLM shared plus routed analytical parity");
            const auto previous=y;
            check(!ExecuteGlmMoe(x,{0,1,2,3},{3,1,0,2},4,1.8,0,rr,sr,y)&&y==previous,"GLM missing shared configuration rejected");
            check(!ExecuteGlmMoe(x,{0,1,2,3},{3,1,0,2},4,1.8,1,rr,[](size_t,SwiGluExpert&){return false;},y)&&y==previous,"GLM missing shared weights transactional");
        }else check(false,"GLM fixture encoding");
    }
    {
        const std::vector<float> q{2,1,1,-1},latent{1,2,3,4,99,99},rotary{0,1,99};
        const std::vector<float> wk{1,0,0,1},wv{1,2,3,4,2,1,4,3};
        std::vector<float> y;
        check(MlaReference(2,2,1,1,2,3,0,1,q,latent,rotary,wk,wv,y)&&y==std::vector<float>({5,11,4,10}),"MLA position zero equals reconstructed V");
        const double p=1/(1+std::exp(-5.0)),s=1/(1+std::exp(-1.0));
        const std::vector<double> expected{5+6*p,11+14*p,4+6*s,10+14*s};
        bool ok=MlaReference(2,2,1,1,2,3,1,1,q,latent,rotary,wk,wv,y)&&y.size()==4;
        for(size_t i=0;i<y.size()&&i<expected.size();++i)ok=ok&&std::abs(y[i]-expected[i])<1e-5;
        check(ok,"MLA two position explicit expanded attention oracle");
        const auto old=y;
        check(!MlaReference(2,2,1,1,2,3,3,1,q,latent,rotary,wk,wv,y)&&y==old,"MLA invalid position transactional");
        check(!MlaReference(2,2,1,1,2,3,1,1,q,latent,rotary,wk,{},y)&&y==old,"MLA invalid projection geometry");
        auto bad=q;bad[0]=std::numeric_limits<float>::infinity();
        check(!MlaReference(2,2,1,1,2,3,1,1,bad,latent,rotary,wk,wv,y)&&y==old,"MLA nonfinite score rejected");
        auto future=latent;future[4]=-1000;future[5]=-1000;
        check(MlaReference(2,2,1,1,2,3,1,1,q,future,rotary,wk,wv,y)&&y==old,"MLA future latent causally excluded");
    }
    {
        struct Backend {
            unsigned pos=0;
            TokenStep Step(uint32_t& t,const std::atomic<bool>&){if(pos==3)return TokenStep::End;t=++pos;return TokenStep::Token;}
        };
        StrataBudget budget({8,0,0,0,1});
        std::atomic<bool> cancel{false};
        unsigned created=0;
        auto factory=[&](){++created;return std::make_unique<Backend>();};
        std::vector<uint32_t> tokens;
        auto consume=[&](uint32_t t){tokens.push_back(t);return true;};
        const StrataBudget::Amount amount{8,0,0,0,1};
        check(RunLocalRequest(budget,amount,8,cancel,factory,consume)==LocalResult::Completed&&tokens==std::vector<uint32_t>({1,2,3}),"LTT inline stream order");
        check(budget.Used()==StrataBudget::Amount{},"LTT reservation released");
        check(RunLocalRequest(budget,{9,0,0,0,1},8,cancel,factory,consume)==LocalResult::AdmissionDenied&&created==1,"LTT admission before backend creation");
        cancel=true;
        check(RunLocalRequest(budget,amount,8,cancel,factory,consume)==LocalResult::Cancelled&&created==1,"LTT pre-cancel");
        cancel=false;
        check(RunLocalRequest(budget,amount,8,cancel,factory,[&](uint32_t){cancel=true;return true;})==LocalResult::Cancelled,"LTT cooperative cancellation");
        cancel=false;
        check(RunLocalRequest(budget,amount,8,cancel,factory,[](uint32_t){return false;})==LocalResult::ConsumerStopped,"LTT consumer stop");
        check(RunLocalRequest(budget,amount,8,cancel,[](){return std::unique_ptr<Backend>{};},consume)==LocalResult::BackendFailed,"LTT missing backend");
        check(budget.Used()==StrataBudget::Amount{},"LTT failure releases reservation");
    }
    {
        struct AgentBackend {
            std::shared_ptr<const uint32_t> model;
            uint32_t pos=0;
            TokenStep Step(uint32_t& t,const std::atomic<bool>&){t=*model+pos++;return TokenStep::Token;}
        };
        auto model=std::make_shared<const uint32_t>(42);
        StrataBudget budget({6,0,0,0,6});
        std::vector<StrataBudget::Amount> amounts(6,{1,0,0,0,1});
        std::vector<std::shared_ptr<std::atomic<bool>>> cancels;
        for(int i=0;i<6;++i)cancels.push_back(std::make_shared<std::atomic<bool>>(false));
        std::vector<std::vector<uint32_t>> streams(6);
        std::vector<AgentReport> reports;
        std::atomic<unsigned> sameModel{0};
        auto factory=[&](std::shared_ptr<const uint32_t> m,size_t){
            if(m==model)++sameModel;
            return std::make_unique<AgentBackend>(AgentBackend{m,0});
        };
        auto consumer=[&](size_t i,uint32_t t){streams[i].push_back(t);if(i==2)cancels[i]->store(true);return true;};
        check(RunAgentGroup(model,budget,amounts,3,6,cancels,factory,consumer,reports)&&reports.size()==6,"agent six request execution");
        check(sameModel==6,"agent shared immutable model identity");
        bool isolated=reports.size()==6;
        for(size_t i=0;i<6&&isolated;++i)
            isolated=streams[i]==(i==2?std::vector<uint32_t>{42}:std::vector<uint32_t>{42,43,44})&&reports[i].result==(i==2?LocalResult::Cancelled:LocalResult::Completed);
        check(isolated,"agent independent streams and cancellation");
        check(budget.Used()==StrataBudget::Amount{},"agent group reservations released");
        check(!RunAgentGroup(model,budget,amounts,3,5,cancels,factory,consumer,reports),"agent concurrency limit");
        cancels[1]=cancels[0];
        check(!RunAgentGroup(model,budget,amounts,3,6,cancels,factory,consumer,reports),"agent duplicate cancellation rejected");
    }
    {
        FairDispatch queue(4,2);
        const auto a=queue.Submit(1),b=queue.Submit(1),c=queue.Submit(2),d=queue.Submit(3);
        check(a&&b&&c&&d&&!queue.Submit(4),"dispatch bounded admission");
        FairDispatch::Job job;
        check(queue.Pop(job)&&job.ticket==a,"dispatch first agent");
        check(!queue.Submit(0),"dispatch invalid agent");
        check(queue.Pop(job)&&job.ticket==c,"dispatch round robin second agent");
        check(queue.CancelQueued(3)==1&&queue.Pending()==1,"dispatch queued cancellation");
        queue.Close();
        check(!queue.Submit(2)&&queue.Pop(job)&&job.ticket==b&&!queue.Pop(job),"dispatch close drains admitted work");
        DemandHistory history(4,0.5);
        check(history.Predict(2).empty(),"predictor cold start");
        check(history.Observe({0,1})&&history.Predict(2)==std::vector<uint32_t>({0,1}),"predictor deterministic tie");
        check(history.Observe({2})&&history.Predict(2)==std::vector<uint32_t>({2,0}),"predictor recency");
        check(!history.Observe({2,2})&&!history.Observe({4})&&history.Predict(2)==std::vector<uint32_t>({2,0}),"predictor invalid observation transactional");
    }
    uint16_t h=0;
    check(PositiveHalf(1,h)&&h==0x3c00&&Half(h)==1,"binary16 one");
    check(PositiveHalf(std::ldexp(1.0,-24),h)&&h==1,"binary16 subnormal");
    check(PositiveHalf(std::ldexp(1.0,-14),h)&&h==0x400,"binary16 min normal");
    check(PositiveHalf(65504,h)&&h==0x7bff,"binary16 max finite");
    check(PositiveHalf(1+std::ldexp(1.0,-11),h)&&h==0x3c00,"ties to even");
    check(!PositiveHalf(65505,h)&&!PositiveHalf(-1,h),"invalid scale rejected");
    Q4Block q4{};Q2Block q2{};Values x{},y{};Error e;
    check(Convert(q4,q2,e)&&e.squared==0&&e.signal==0,"zero block conversion");
    StoreHalf(q4.data(),0x3c00);StoreHalf(q4.data()+2,0x3c00);
    for(unsigned g=0;g<4;++g){q4[4+g]=1;q4[8+g]=2;q4[12+g]=0x21;}
    for(unsigned i=16;i<144;++i)q4[i]=0x53;
    check(DecodeQ4(q4,x)&&x[0]==1&&x[32]==3&&x[128]==1&&x[224]==3,"known Q4_K packed layout");
    q4[4]|=0x40;q4[8]|=0x80;
    check(DecodeQ4(q4,x)&&x[128]==3*17-34,"upper scale bits");
    q2={};StoreHalf(q2.data()+80,0x3c00);StoreHalf(q2.data()+82,0x3c00);
    for(unsigned i=0;i<16;++i)q2[i]=0x21;
    for(unsigned i=16;i<80;++i)q2[i]=0xe4;
    check(DecodeQ2(q2,y)&&y[0]==-2&&y[16]==-2&&y[32]==-1&&y[64]==0&&y[96]==1&&y[128]==-2,"known Q2_K bitplanes");
    for(unsigned i=0;i<256;++i)x[i]=float(int(i%4)-2);
    check(EncodeQ2(x,q2)&&DecodeQ2(q2,y),"encode signed four-level grid");
    double max=0;for(unsigned i=0;i<256;++i)max=std::max(max,std::abs(double(x[i])-y[i]));
    check(max<.003,"four-level reconstruction");
    x.fill(-2);check(EncodeQ2(x,q2)&&DecodeQ2(q2,y)&&std::abs(y[255]+2)<.003,"negative constant");
    x.fill(3);check(EncodeQ2(x,q2)&&DecodeQ2(q2,y)&&std::abs(y[255]-3)<.003,"positive constant");
    x[17]=std::numeric_limits<float>::quiet_NaN();auto prior=q2;
    check(!EncodeQ2(x,q2)&&q2==prior,"NaN rejected without publishing");
    check(Convert(q4,q2,e)&&e.signal>0&&e.squared>=0&&std::isfinite(e.maxAbs),"Q4_K to Q2_K actual conversion and error");
    // Independent Q3_K decode fixture: every scale group and signed code.
    Q3Block q3{}; Values q3Expected{},q3Actual{};
    StoreHalf(q3.data()+108,0x3c00);
    for(unsigned g=0;g<16;++g){
        const unsigned s=g*4;
        q3[96+g%8]|=uint8_t((s%16)<<(4*(g/8)));
        q3[104+g%4]|=uint8_t((s/16)<<(2*(g/4)));
    }
    for(unsigned i=0;i<32;++i)q3[i]=0xf0;
    for(unsigned i=32;i<96;++i)q3[i]=0xe4;
    for(unsigned i=0;i<256;++i)
        q3Expected[i]=float((int(i/16)*4-32)*(int(i/32%4)-(i<128?4:0)));
    check(DecodeQ3(q3,q3Actual)&&q3Actual==q3Expected,"Q3_K signed scales and bitplanes");
    Values grid{};for(unsigned i=0;i<256;++i)grid[i]=float(int(i%8)-4);
    check(EncodeQ3(grid,q3)&&DecodeQ3(q3,q3Actual),"Q3_K signed grid encode/decode");
    double q3Max=0;for(unsigned i=0;i<256;++i)q3Max=std::max(q3Max,std::abs(double(grid[i])-q3Actual[i]));
    check(q3Max<0.01,"Q3_K signed grid reconstruction");
    const auto q3Prior=q3;grid[0]=std::numeric_limits<float>::quiet_NaN();
    check(!EncodeQ3(grid,q3)&&q3==q3Prior,"Q3_K invalid input preserves destination");
    Error q3Error{};
    check(ConvertQ4ToQ3(q4,q3,q3Error)&&std::isfinite(q3Error.squared),"Q4_K to Q3_K physical block conversion");
    uint64_t q3Size=0;
    check(ConvertedQ3Bytes(7168,144*28*3,q3Size)&&q3Size==110*28*3,"Q3_K exact row bytes");
    check(!ConvertedQ3Bytes(512,144,q3Size),"Q3_K partial row rejected");
#if defined(__AVX2__)
#if defined(_WIN32) && defined(_MSC_VER)
    if(!hasAvx2()){
        std::printf("R23_AVX2_UNVERIFIED=CPU_DOES_NOT_REPORT_AVX2\n");
        return 2;
    }
#endif
    // Independent packed fixture: generate logical scales and codes first,
    // then encode the GGUF bytes without using either decoder.
    uint32_t rng=0x923abcdu;
    auto next=[&](){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;};
    bool oracle=true, bytesParity=true;
    for(unsigned trial=0;trial<4096 && oracle && bytesParity;++trial){
        Q4Block block{}; Values expected{}, a{}, b{};
        StoreHalf(block.data(),0x3c00); StoreHalf(block.data()+2,0x3800);
        for(unsigned g=0;g<8;++g){
            unsigned sc=next()&63u,mn=next()&63u;
            if(g<4){block[4+g]|=sc;block[8+g]|=mn;}
            else {
                block[g]|=(sc>>4)<<6;
                block[4+g]|=(mn>>4)<<6;
                block[8+g]=(sc&15u)|((mn&15u)<<4);
            }
            for(unsigned i=0;i<32;++i){
                unsigned q=next()&15u;
                block[16+32*(g/2)+i]|=q<<(4*(g%2));
                expected[32*g+i]=float(sc*q)-0.5f*float(mn);
            }
        }
        oracle=DecodeQ4(block,a)&&DecodeQ4AVX2(block,b)&&a==expected&&b==expected;
        Q2Block qa{},qb{}; Error ea{},eb{};
        bytesParity=Convert(block,qa,ea)&&ConvertAVX2(block,qb,eb)&&qa==qb&&
            ea.squared==eb.squared&&ea.signal==eb.signal&&ea.maxAbs==eb.maxAbs;
    }
    check(oracle,"R23 independent 4096-block packed oracle");
    check(bytesParity,"R23 independent fixtures exact conversion parity");
    Values scalarValues{},simdValues{};
    Q2Block scalarConverted{},simdConverted{};
    Error scalarError{},simdError{};
    const bool scalarDecoded=DecodeQ4(q4,scalarValues);
    const bool simdDecoded=DecodeQ4AVX2(q4,simdValues);
    bool decodeParity=scalarDecoded&&simdDecoded;
    unsigned firstDecodeMismatch=Elements; float maxDecodeDiff=0;
    for(unsigned i=0;i<Elements&&decodeParity;++i){
        const float diff=std::abs(scalarValues[i]-simdValues[i]);
        maxDecodeDiff=std::max(maxDecodeDiff,diff);
        if(!std::isfinite(diff)||diff>1e-6f){firstDecodeMismatch=i;decodeParity=false;}
    }
    if(!scalarDecoded||!simdDecoded) std::printf("R23_DECODE_FAILED scalar=%d simd=%d\n",int(scalarDecoded),int(simdDecoded));
    else if(!decodeParity && firstDecodeMismatch<Elements) std::printf("R23_DECODE_DIFF index=%u scalar=%g simd=%g max=%g\n",
                                  firstDecodeMismatch,scalarValues[firstDecodeMismatch],
                                  simdValues[firstDecodeMismatch],maxDecodeDiff);
    check(decodeParity,"R23 AVX2/scalar Q4_K decode parity");
    const bool converted=Convert(q4,scalarConverted,scalarError)&&
        ConvertAVX2(q4,simdConverted,simdError);
    const bool conversionParity=converted && scalarConverted==simdConverted &&
        std::abs(scalarError.squared-simdError.squared)<=1e-5 &&
        std::abs(scalarError.signal-simdError.signal)<=1e-5 &&
        std::abs(scalarError.maxAbs-simdError.maxAbs)<=1e-6;
    if(!conversionParity) std::printf("R23_CONVERSION_DIFF bytes=%d squared=%g/%g signal=%g/%g max=%g/%g\n",
                                      scalarConverted==simdConverted,
                                      scalarError.squared,simdError.squared,
                                      scalarError.signal,simdError.signal,
                                      scalarError.maxAbs,simdError.maxAbs);
    check(conversionParity,"R23 AVX2/scalar Q4_K to Q2_K parity");
#else
    std::printf("R23_AVX2_UNVERIFIED=SCALAR_BUILD\n");
#ifndef RAWRXD_REAP_SCALAR_ACCEPTANCE
    return 2;
#endif
#endif
    StoreHalf(q4.data(),0x7c00);prior=q2;check(!Convert(q4,q2,e)&&q2==prior,"nonfinite source rejected");
    uint64_t bytes=0;check(ConvertedBytes(7168,144*28*3,bytes)&&bytes==84*28*3,"exact Kimi row byte conversion");
    check(!ConvertedBytes(255,144,bytes)&&!ConvertedBytes(256,145,bytes)&&!ConvertedBytes(512,144,bytes),"partial blocks and rows rejected");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
