#include "deep2/ReapBankContract.hpp"
#include <cstdio>
using namespace Deep2::ReapBank;
int main() {
    int pass=0,fail=0;
    auto check=[&](bool yes,const char* label){std::printf("%s %s\n",yes?"PASS":"FAIL",label);yes?++pass:++fail;};
    Contract c;
    check(!c.Allows(8),"empty inventory rejects export");
    check(c.ObserveAxis(384),"first expert tensor");
    check(c.ObserveAxis(384),"later expert shard");
    check(c.original==384,"dense-only shard leaves bank unchanged");
    check(!c.ObserveAxis(256)&&c.original==384,"inconsistent shard rejected");
    check(!c.ObserveAxis(0),"zero bank rejected");
    check(!c.ObserveAxis(uint64_t{UINT32_MAX}+1),"oversized bank rejected");
    check(c.ObserveTopK(8)&&c.ObserveTopK(8),"consistent top-k");
    check(!c.ObserveTopK(4)&&c.topK==8,"conflicting top-k rejected");
    check(!c.ObserveTopK(0),"zero top-k rejected");
    check(!c.ObserveTopK(uint64_t{UINT32_MAX}+1),"oversized top-k rejected");
    check(c.Allows(8)&&c.Allows(64)&&c.Allows(384),"valid retained counts");
    check(!c.Allows(7)&&!c.Allows(385)&&!c.Allows(0),"impossible retained counts");
    Contract bad; bad.ObserveAxis(4);bad.ObserveTopK(8);
    check(!bad.Allows(4),"invalid source top-k");
    check(HasField("deepseek2.expert_count","expert_count"),"exact bank metadata");
    check(!HasField("deepseek2.shared_expert_count","expert_count"),"shared count preserved");
    check(!HasField("deepseek2.expert_used_count","expert_count"),"top-k preserved");
    check(HasField("deepseek2.expert_used_count","expert_used_count"),"exact top-k metadata");
    check(!HasField("expert_count","expert_count"),"unqualified field rejected");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
