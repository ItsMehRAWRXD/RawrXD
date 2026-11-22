#include "deep2/ReapQ4KToQ2K.hpp"
#include "deep2/ReapMixedPrecision.hpp"
#include "deep2/ReapShardIndex.hpp"
#include "deep2/ReapRetainedRouting.hpp"
#include "deep2/ReapBoundedExpertCache.hpp"
#include <thread>
#include <atomic>
#include "deep2/ReapNativeShardReader.hpp"
#include <cstdio>
#if defined(_WIN32) && defined(_MSC_VER)
#include <intrin.h>
static bool hasAvx2(){
    int info[4]{};
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
        if(diff>1e-6f){firstDecodeMismatch=i;decodeParity=false;}
    }
    if(!decodeParity) std::printf("R23_DECODE_DIFF index=%u scalar=%g simd=%g max=%g\n",
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
    std::printf("R23_AVX2_UNVERIFIED=AVX2_BUILD_REQUIRED\n");
    return 2;
#endif
    StoreHalf(q4.data(),0x7c00);prior=q2;check(!Convert(q4,q2,e)&&q2==prior,"nonfinite source rejected");
    uint64_t bytes=0;check(ConvertedBytes(7168,144*28*3,bytes)&&bytes==84*28*3,"exact Kimi row byte conversion");
    check(!ConvertedBytes(255,144,bytes)&&!ConvertedBytes(256,145,bytes)&&!ConvertedBytes(512,144,bytes),"partial blocks and rows rejected");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
