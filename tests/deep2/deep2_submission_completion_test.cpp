#include "deep2/ReapSubmissionCompletion.hpp"
#include <cstdio>
using namespace Deep2::Submit;
int main() {
    int passed=0, failed=0;
    auto check=[&](bool ok,const char* name){std::printf("%s %s\n",ok?"PASS":"FAIL",name);ok?++passed:++failed;};
    static_assert(kVkSuccess==0 && kVkTimeout==2 && kVkErrorDeviceLost==-4, "VkResult ABI drift");
    check(Classify(0,true)==Completion::Reclaim,"completed");
    check(Classify(1,true)==Completion::Retain,"not_ready");
    check(Classify(2,true)==Completion::Retain,"timeout");
    check(Classify(3,true)==Completion::Retain,"event_set");
    check(Classify(-5,true)==Completion::Retain,"unknown_error");
    check(Classify(31,true)==Completion::Retain,"foreign_result");
    check(Classify(-4,true)==Completion::TerminalTeardown,"device_lost_after_submit");
    check(Classify(-4,false)==Completion::TerminalTeardown,"device_lost_before_submit");
    check(Classify(2,false)==Completion::Reclaim,"confirmed_no_submission");
    check(MayReclaim(Completion::Reclaim),"reclaim");
    check(!MayReclaim(Completion::Retain),"retain");
    check(!MayReclaim(Completion::TerminalTeardown),"terminal_no_normal_reclaim");
    bool pending=false, fault=false, cleanup=false;
    check(MayReuseQuant(pending,fault,cleanup),"initial_reuse");
    check(MayReleaseQuantPins(pending,fault),"presubmit_pins");
    check(!RecordQuantWait(0,pending,fault),"wait_without_submission_rejected");
    check(RecordQuantSubmit(0,pending,fault)&&pending&&!fault,"submit_pending");
    check(!MayReuseQuant(pending,fault,cleanup),"pending_blocks_reuse");
    check(!MayReleaseQuantPins(pending,fault),"pending_retains_pins");
    check(!RecordQuantWait(2,pending,fault)&&pending&&fault,"timeout_quarantine");
    check(!MayReuseQuant(pending,fault,cleanup)&&!MayReleaseQuantPins(pending,fault),"timeout_blocks_reuse_and_unpin");
    check(RecordQuantWait(0,pending,fault)&&!pending&&!fault,"late_proven_completion");
    check(MayReuseQuant(pending,fault,cleanup)&&MayReleaseQuantPins(pending,fault),"completed_reuse_and_unpin");
    check(!RecordQuantSubmit(-4,pending,fault)&&pending&&fault,"lost_submit_quarantine");
    check(!MayReleaseQuantPins(pending,fault),"lost_submit_retains_pins");
    check(!RecordQuantWait(-4,pending,fault)&&pending&&fault,"lost_wait_quarantine");
    check(!RecordIdleWait(-4,cleanup)&&cleanup,"lost_idle_no_normal_cleanup");
    check(!RecordIdleWait(-1,cleanup)&&cleanup,"unknown_idle_no_normal_cleanup");
    check(!RecordIdleWait(2,cleanup)&&cleanup,"timeout_idle_no_normal_cleanup");
    check(!MayReuseQuant(false,false,cleanup),"cleanup_failure_blocks_reuse");
    check(RecordIdleWait(0,cleanup)&&!cleanup,"successful_idle_boundary");
    check(!MayReuseQuant(pending,fault,cleanup),"idle_policy_does_not_silently_clear_submission");
    check(!RecordQuantSubmit(-2,pending,fault)&&pending&&fault,"failed_submit_retained_conservatively");
    check(!MayReleaseQuantPins(false,true),"inconsistent_failed_state_retains_pins");
    check(!MayReuseQuant(false,true,false),"inconsistent_failed_state_blocks_reuse");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\nPROMOTE=0\n",passed,failed);
    return failed?1:0;
}
