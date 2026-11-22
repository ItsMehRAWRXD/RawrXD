#include "deep2/ReapOneShotOwnership.hpp"
#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>
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
    check(!owner.Drain(-1,t1,reclaim)&&owner.Active(),"ambiguous idle retains handles");
    // Idle timeout retains handles.
    check(!owner.Drain(2,t1,reclaim)&&owner.Active(),"idle timeout retains handles");
    // Stale teardown (wrong ticket) rejected.
    check(!owner.Drain(0,t1+1,reclaim)&&owner.Active(),"stale teardown rejected");
    // Idle success drains (ticket captured before idle; submitted first).
    owner.MarkSubmitted();
    check(owner.Drain(0,t1,reclaim)&&!owner.Active(),"idle success drains");
    check(releases==1&&last.cmd==1&&last.query==2&&last.fence==3,"original handles reclaimed exactly once");
    check(!owner.Drain(0,t1,reclaim)&&releases==1,"repeated drain idempotence");
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
    // H39: capture t3 as the drain ticket, then a new acquisition occurs; the
    // stale drain (t3) must NOT reclaim the new submission (t4).
    // (Simulate by completing t3 normally first, then acquiring t4, then a
    // stale Drain with t3 must be refused.)
    check(owner.Complete(0,t3,reclaim)&&releases==3&&!owner.Active(),"normal completion t3 reclaims");
    const uint64_t t4 = owner.Acquire({13,14,15},2);
    check(t4!=0 && t4!=t3,"new acquisition after t3");
    check(!owner.Drain(-4,t3,reclaim)&&owner.Active(),"stale drain ticket rejected (H39)");
    check(releases==3,"stale drain no release (H39)");
    // Terminal loss teardown (generation-wide) with the CURRENT ticket reclaims.
    owner.MarkSubmitted();
    check(owner.Drain(-4,t4,reclaim)&&releases==4&&!owner.Active(),"terminal loss permits teardown");
    check(last.cmd==13&&last.query==14&&last.fence==15,"terminal teardown owns correct handles");
    // Teardown result allowlist.
    check(MayTeardownAfterIdle(0)&&MayTeardownAfterIdle(-4),"exact teardown result allowlist");
    check(!MayTeardownAfterIdle(31)&&!MayTeardownAfterIdle(-2)&&!MayTeardownAfterIdle(1),"foreign and ambiguous codes rejected");
    // H47-C: Drain refuses an acquired-but-not-submitted acquisition (fail closed).
    {
        OneShotOwner<Handles> owner;
        int releases = 0;
        auto reclaim = [&](const Handles&) { ++releases; };
        const uint64_t t = owner.Acquire({1,2,3}, 1);
        // Not yet MarkSubmitted -> Drain must refuse (handles still about to be used).
        check(!owner.Drain(0, t, reclaim) && owner.Active(), "drain_unsubmitted_refused");
        check(releases == 0, "drain_unsubmitted_no_release");
        // After MarkSubmitted -> Drain succeeds.
        owner.MarkSubmitted();
        check(owner.Drain(0, t, reclaim) && !owner.Active(), "drain_submitted_ok");
        check(releases == 1, "drain_submitted_release");
    }
    // H52: concurrent Complete() with the same ticket -> exactly one wins
    // (atomic claim), exactly one native release.
    {
        OneShotOwner<Handles> owner;
        int releases = 0;
        auto reclaim = [&](const Handles&) { ++releases; };
        const uint64_t t = owner.Acquire({1,2,3}, 1);
        std::atomic<int> wins{0};
        std::thread thA([&]{ if (owner.Complete(0, t, reclaim)) wins.fetch_add(1); });
        std::thread thB([&]{ if (owner.Complete(0, t, reclaim)) wins.fetch_add(1); });
        thA.join(); thB.join();
        check(wins.load() == 1, "concurrent complete exactly one wins");
        check(releases == 1, "concurrent complete exactly one release");
        check(!owner.Active(), "concurrent complete clears active");
    }
    // H52: concurrent Drain() with the same ticket -> exactly one wins.
    {
        OneShotOwner<Handles> owner;
        int releases = 0;
        auto reclaim = [&](const Handles&) { ++releases; };
        const uint64_t t = owner.Acquire({4,5,6}, 1);
        owner.MarkSubmitted();
        std::atomic<int> wins{0};
        std::thread thA([&]{ if (owner.Drain(0, t, reclaim)) wins.fetch_add(1); });
        std::thread thB([&]{ if (owner.Drain(0, t, reclaim)) wins.fetch_add(1); });
        thA.join(); thB.join();
        check(wins.load() == 1, "concurrent drain exactly one wins");
        check(releases == 1, "concurrent drain exactly one release");
    }
    // H60: mixed concurrent Acquire/Complete/Drain stress — exactly-once.
    {
        OneShotOwner<Handles> owner;
        std::atomic<int> releases{0};
        std::atomic<int> acquired{0};
        auto reclaim = [&](const Handles&) { releases.fetch_add(1); };
        std::vector<std::thread> threads;
        for (int t = 0; t < 4; ++t) {
            threads.emplace_back([&]{
                for (int i = 0; i < 500; ++i) {
                    const uint64_t ticket = owner.Acquire({i, i, i}, 1);
                    if (!ticket) continue;
                    acquired.fetch_add(1);
                    owner.MarkSubmitted();
                    if (i & 1) (void)owner.Complete(0, ticket, reclaim);
                    else       (void)owner.Drain(0, ticket, reclaim);
                }
            });
        }
        for (auto& th : threads) th.join();
        check(releases.load() == acquired.load(), "mixed stress exactly-once release");
        check(!owner.Active(), "mixed stress ends inactive");
    }
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);
    return fail?1:0;
}