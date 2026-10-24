#include "../src/deep2/reap/ReapProjectionBridge.hpp"
#include <cassert>
#include <iostream>
using namespace Deep2::ReapRom;
int main() {
    int handles[3]={1,2,3},reads=0,uploads=0,executions=0;
    ProjectionBridge b(
        [&](const std::string& path,uint64_t off,void* out,size_t n){
            assert(path=="immutable.gguf" && off>=100 && off<=108 && n==4);
            ++reads; auto* p=static_cast<uint8_t*>(out);
            for(size_t i=0;i<n;++i) p[i]=static_cast<uint8_t>(off+i);
            return true;
        },
        [&](Projection p,const Slice& s,const std::vector<uint8_t>& v,Binding& out){
            assert(v.size()==4 && v[0]==static_cast<uint8_t>(s.offset));
            ++uploads; out={&handles[static_cast<int>(p)],4,1}; return true;
        },
        [&](Projection p,const Binding& bind,uint32_t l,uint32_t e){
            assert(bind.deviceHandle==&handles[static_cast<int>(p)] && l==1 && e==9);
            ++executions; return true;
        },1024);
    bool rejected=false;
    try { b.Register(Projection::Gate,{"immutable.gguf",0,2048,1,9,0}); }
    catch(const std::invalid_argument&){rejected=true;}
    assert(rejected);
    b.Register(Projection::Gate,{"immutable.gguf",100,4,1,9,0});
    b.Register(Projection::Up,{"immutable.gguf",104,4,1,9,0});
    rejected=false;
    try { b.Retain(1,9); } catch(const std::invalid_argument&){rejected=true;}
    assert(rejected);
    b.Register(Projection::Down,{"immutable.gguf",108,4,1,9,0});
    b.Retain(1,9);
    assert(!b.Run(1,8));
    assert(b.Run(1,9) && b.Run(1,9));
    assert(reads==3 && uploads==3 && executions==6);
    assert(b.Stats().diskBytes==12 && b.Stats().rejected==1);
    assert(b.ResidentBytes()==12);
    assert(!b.ForgetAfterGpuIdle(1,9)); // no GPU fence proof
    assert(b.ResidentBytes()==12);
    // Total device budget must reject the third projection, not exceed the cap.
    int local[3]={4,5,6}, limitedExec=0, limitedReads=0;
    ProjectionBridge limited(
        [&](const std::string&,uint64_t,void* out,size_t n){
            ++limitedReads;
            for(size_t i=0;i<n;++i) static_cast<uint8_t*>(out)[i]=1;
            return true;
        },
        [&](Projection p,const Slice&,const std::vector<uint8_t>&,Binding& out){
            out={&local[static_cast<int>(p)],4,1}; return true;
        },
        [&](Projection,const Binding&,uint32_t,uint32_t){++limitedExec; return true;},
        1024,8,[]{return true;});
    for(auto p:{Projection::Gate,Projection::Up,Projection::Down})
        limited.Register(p,{"immutable.gguf",100,4,2,4,0});
    limited.Retain(2,4);
    assert(!limited.Run(2,4));
    assert(limited.ResidentBytes()==0 && limitedExec==0 && limitedReads==0);
    assert(limited.ForgetAfterGpuIdle(2,4));
    assert(limited.ResidentBytes()==0);
    int released=0, releaseHandles[3]={7,8,9};
    ProjectionBridge releasable(
        [](const std::string&,uint64_t,void* out,size_t n){
            for(size_t i=0;i<n;++i) static_cast<uint8_t*>(out)[i]=1;
            return true;
        },
        [&](Projection p,const Slice&,const std::vector<uint8_t>&,Binding& out){
            out={&releaseHandles[static_cast<int>(p)],4,1}; return true;
        },
        [](Projection,const Binding&,uint32_t,uint32_t){return true;},
        1024,12,[]{return true;},
        [&](Projection,const Binding& binding){assert(binding.deviceHandle); ++released;});
    for(auto p:{Projection::Gate,Projection::Up,Projection::Down})
        releasable.Register(p,{"immutable.gguf",100,4,3,5,0});
    releasable.Retain(3,5);
    assert(releasable.Run(3,5));
    assert(releasable.ForgetAfterGpuIdle(3,5));
    assert(released==3 && releasable.ResidentBytes()==0);
    int failedRelease=0, failedExec=0, failedHandle=10;
    ProjectionBridge uploadFailure(
        [](const std::string&,uint64_t,void* out,size_t n){
            for(size_t i=0;i<n;++i) static_cast<uint8_t*>(out)[i]=1;
            return true;
        },
        [&](Projection,const Slice&,const std::vector<uint8_t>&,Binding& out){
            out={&failedHandle,4,1}; return false;
        },
        [&](Projection,const Binding&,uint32_t,uint32_t){++failedExec; return true;},
        1024,12,[]{return true;},
        [&](Projection,const Binding& binding){
            assert(binding.deviceHandle==&failedHandle); ++failedRelease;
        });
    for(auto p:{Projection::Gate,Projection::Up,Projection::Down})
        uploadFailure.Register(p,{"immutable.gguf",100,4,4,6,0});
    uploadFailure.Retain(4,6);
    assert(!uploadFailure.Run(4,6));
    assert(failedRelease==1 && failedExec==0 && uploadFailure.ResidentBytes()==0);
    int lateExec=0, lateUploads=0, lateHandles[3]={11,12,13};
    ProjectionBridge lateFailure(
        [](const std::string&,uint64_t,void* out,size_t n){
            for(size_t i=0;i<n;++i) static_cast<uint8_t*>(out)[i]=1;
            return true;
        },
        [&](Projection p,const Slice&,const std::vector<uint8_t>&,Binding& out){
            ++lateUploads;
            if(p==Projection::Down) return false;
            out={&lateHandles[static_cast<int>(p)],4,1}; return true;
        },
        [&](Projection,const Binding&,uint32_t,uint32_t){++lateExec; return true;},
        1024,12);
    for(auto p:{Projection::Gate,Projection::Up,Projection::Down})
        lateFailure.Register(p,{"immutable.gguf",100,4,5,7,0});
    lateFailure.Retain(5,7);
    assert(!lateFailure.Run(5,7));
    assert(lateUploads==3 && lateExec==0);
    std::cout<<"REAP_PROJECTION_BRIDGE_SMOKE_PASS\n";
}
