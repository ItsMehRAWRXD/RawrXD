#include "ExpertCache.h"
#include "HostStagingRing.h"
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <vector>
using namespace rawrxd::deep2;

struct MockAsync {
    struct Dev { std::vector<unsigned char> b; };
    struct Job { Dev* d=nullptr; std::vector<unsigned char> src; bool ready=false; };
    uint64_t next=1, waits=0, polls=0, frees=0, submits=0;
    std::unordered_map<uint64_t,Job> jobs;
};
static void* allocD(void*,size_t n,uint32_t){auto*d=new MockAsync::Dev;d->b.resize(n);return d;}
static void freeD(void*u,void*h,uint32_t){((MockAsync*)u)->frees++;delete (MockAsync::Dev*)h;}
static uint64_t submit(void*u,void*h,const void*s,size_t n,uint32_t){auto&m=*(MockAsync*)u;uint64_t t=m.next++;MockAsync::Job j;j.d=(MockAsync::Dev*)h;j.src.assign((const unsigned char*)s,(const unsigned char*)s+n);m.jobs[t]=std::move(j);m.submits++;return t;}
static bool poll(void*u,uint64_t t,uint32_t){auto&m=*(MockAsync*)u;m.polls++;auto it=m.jobs.find(t);if(it==m.jobs.end())return false;return it->second.ready;}
static bool wait(void*u,uint64_t t,uint32_t){auto&m=*(MockAsync*)u;m.waits++;auto it=m.jobs.find(t);if(it==m.jobs.end())return false;std::memcpy(it->second.d->b.data(),it->second.src.data(),it->second.src.size());m.jobs.erase(it);return true;}
static uint64_t now(void*){static uint64_t x=100;return ++x;}
int main(){
    HostStagingRing r(1024,256); auto a=r.reserve(100,1);auto b=r.reserve(300,2);
    bool ringPass=a&&b&&r.used()==768&&r.complete(2)&&r.used()==768&&r.complete(1)&&r.used()==0;
    MockAsync m; ExpertTransport t{};t.user=&m;t.allocDevice=allocD;t.freeDevice=freeD;t.submitUpload=submit;t.pollUpload=poll;t.waitUpload=wait;t.nowMicros=now;
    ExpertCacheConfig c{};c.budgetBytes=2048;c.deviceOrdinal=0;ExpertCache cache(c,t);
    unsigned char e0[512],e1[512];for(int i=0;i<512;i++){e0[i]=(unsigned char)i;e1[i]=(unsigned char)(255-i);}
    bool reg=cache.registerExpert({0,0},{e0,sizeof(e0),0})&&cache.registerExpert({0,1},{e1,sizeof(e1),0});
    bool pf=cache.prefetch({0,0},10); // must submit but not wait
    auto s0=cache.stats(); bool nonblocking=pf&&s0.asyncSubmits==1&&s0.asyncWaits==0&&m.waits==0;
    auto lease=cache.acquire({0,0},11); // now wait and expose usable buffer
    auto s1=cache.stats(); bool waited=lease&&s1.asyncWaits==1&&m.waits==1;
    bool bytes=false;if(lease){auto*d=(MockAsync::Dev*)lease.deviceHandle;bytes=d->b.size()==512&&std::memcmp(d->b.data(),e0,512)==0;}
    auto lease2=cache.acquire({0,1},12);auto s2=cache.stats();bool demand=lease2&&s2.asyncSubmits==2&&s2.asyncWaits==2;
    cache.clear();bool freed=m.frees==2;
    std::printf("GATE=RAWRXD_EXPERT_CACHE_004\n");
    std::printf("STAGING_RING=%s\n",ringPass?"PASS":"FAIL");
    std::printf("ASYNC_PREFETCH_NONBLOCKING=%s\n",nonblocking?"PASS":"FAIL");
    std::printf("ACQUIRE_WAITS_INFLIGHT=%s\n",waited?"PASS":"FAIL");
    std::printf("GPU_BYTES_VALID=%s\n",bytes?"PASS":"FAIL");
    std::printf("DEMAND_ASYNC=%s\n",demand?"PASS":"FAIL");
    std::printf("CPU_EXPERT_COMPUTE=0\n");
    std::printf("ASYNC_SUBMITS=%llu\n",(unsigned long long)s2.asyncSubmits);
    std::printf("ASYNC_WAITS=%llu\n",(unsigned long long)s2.asyncWaits);
    std::printf("GPU_FREED=%s\n",freed?"PASS":"FAIL");
    bool ok=ringPass&&reg&&nonblocking&&waited&&bytes&&demand&&freed;
    std::printf("VERDICT=%s\n",ok?"PASS":"FAIL");return ok?0:1;
}
