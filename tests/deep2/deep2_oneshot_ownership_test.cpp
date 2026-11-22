#include "deep2/ReapOneShotOwnership.hpp"
#include <cstdio>
using namespace Deep2::Submit;
struct Handles { int cmd=0, query=0, fence=0; };
int main() {
    int pass=0, fail=0;
    auto check=[&](bool yes,const char* name){std::printf("%s %s\n",yes?"PASS":"FAIL",name);yes?++pass:++fail;};
    OneShotOwner<Handles> owner;
    int releases=0;
    Handles last{};
    auto reclaim=[&](const Handles& h){++releases;last=h;};
    check(!owner.Active(),"initial empty");
    check(!owner.Complete(0,1,reclaim),"empty completion rejected");
    check(owner.Acquire({1,2,3},1)&&owner.Active(),"own handles before submit");
    check(!owner.Acquire({4,5,6},1),"second acquisition rejected");
    check(!owner.Complete(2,1,reclaim)&&owner.Active()&&releases==0,"timeout retains handles");
    check(!owner.Complete(-4,1,reclaim)&&owner.Active(),"device loss not ordinary completion");
    check(!owner.Complete(0,2,reclaim)&&owner.Active(),"wrong generation rejected");
    check(!owner.Drain(-1,1,reclaim)&&owner.Active(),"ambiguous idle retains handles");
    check(!owner.Drain(2,1,reclaim)&&owner.Active(),"idle timeout retains handles");
    check(!owner.Drain(0,2,reclaim)&&owner.Active(),"stale teardown rejected");
    check(owner.Drain(0,1,reclaim)&&!owner.Active(),"idle success drains");
    check(releases==1&&last.cmd==1&&last.query==2&&last.fence==3,"original handles reclaimed exactly once");
    check(!owner.Drain(0,1,reclaim)&&releases==1,"repeated drain idempotence");
    check(owner.Acquire({7,8,9},2),"new generation acquisition");
    check(!owner.Complete(0,1,reclaim),"old generation completion rejected");
    check(owner.Complete(0,2,reclaim)&&releases==2&&!owner.Active(),"normal completion reclaims");
    check(owner.Acquire({10,11,12},2),"next submission same generation");
    check(owner.Drain(-4,2,reclaim)&&releases==3&&!owner.Active(),"terminal loss permits teardown");
    check(last.cmd==10&&last.query==11&&last.fence==12,"terminal teardown owns correct handles");
    check(MayTeardownAfterIdle(0)&&MayTeardownAfterIdle(-4),"exact teardown result allowlist");
    check(!MayTeardownAfterIdle(31)&&!MayTeardownAfterIdle(-2)&&!MayTeardownAfterIdle(1),"foreign and ambiguous codes rejected");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);
    return fail?1:0;
}
