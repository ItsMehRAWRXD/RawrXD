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
    // Empty completion rejected (no active acquisition; ticket 1 != epoch 0).
    check(!owner.Complete(0,1,reclaim),"empty completion rejected");
    // Acquire returns a per-acquisition ticket.
    const uint64_t t1 = owner.Acquire({1,2,3},1);
    check(t1!=0 && owner.Active(),"own handles before submit");
    // Second acquisition rejected while active.
    check(owner.Acquire({4,5,6},1)==0,"second acquisition rejected");
    // Timeout (result!=0) retains handles.
    check(!owner.Complete(2,t1,reclaim)&&owner.Active()&&releases==0,"timeout retains handles");
    // Device loss is not ordinary completion.
    check(!owner.Complete(-4,t1,reclaim)&&owner.Active(),"device loss not ordinary completion");
    // Wrong/stale ticket rejected.
    check(!owner.Complete(0,t1+1,reclaim)&&owner.Active(),"wrong ticket rejected");
    // Ambiguous idle retains handles.
    check(!owner.Drain(-1,1,reclaim)&&owner.Active(),"ambiguous idle retains handles");
    // Idle timeout retains handles.
    check(!owner.Drain(2,1,reclaim)&&owner.Active(),"idle timeout retains handles");
    // Stale teardown (wrong generation) rejected.
    check(!owner.Drain(0,2,reclaim)&&owner.Active(),"stale teardown rejected");
    // Idle success drains (generation-wide teardown).
    check(owner.Drain(0,1,reclaim)&&!owner.Active(),"idle success drains");
    check(releases==1&&last.cmd==1&&last.query==2&&last.fence==3,"original handles reclaimed exactly once");
    check(!owner.Drain(0,1,reclaim)&&releases==1,"repeated drain idempotence");
    // New acquisition, new generation, new ticket.
    const uint64_t t2 = owner.Acquire({7,8,9},2);
    check(t2!=0,"new generation acquisition");
    // Stale completion from t1 (old ticket) rejected.
    check(!owner.Complete(0,t1,reclaim)&&owner.Active(),"old ticket completion rejected");
    // Normal completion with matching ticket reclaims.
    check(owner.Complete(0,t2,reclaim)&&releases==2&&!owner.Active(),"normal completion reclaims");
    // S9.02: same device generation REUSED for a new submission -> new ticket.
    const uint64_t t3 = owner.Acquire({10,11,12},2);
    check(t3!=0 && t3!=t2,"next submission same generation, new ticket");
    // Stale Complete from t2 must NOT release t3's resources (S9.02).
    check(!owner.Complete(0,t2,reclaim)&&owner.Active(),"stale same-generation ticket rejected");
    check(releases==2,"stale same-generation no release");
    // Terminal loss teardown (generation-wide) reclaims t3's handles.
    check(owner.Drain(-4,2,reclaim)&&releases==3&&!owner.Active(),"terminal loss permits teardown");
    check(last.cmd==10&&last.query==11&&last.fence==12,"terminal teardown owns correct handles");
    // Teardown result allowlist.
    check(MayTeardownAfterIdle(0)&&MayTeardownAfterIdle(-4),"exact teardown result allowlist");
    check(!MayTeardownAfterIdle(31)&&!MayTeardownAfterIdle(-2)&&!MayTeardownAfterIdle(1),"foreign and ambiguous codes rejected");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);
    return fail?1:0;
}