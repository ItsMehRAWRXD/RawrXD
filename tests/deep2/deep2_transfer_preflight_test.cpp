#include "deep2/ReapTransferPreflight.hpp"
#include <cstdio>
#include <cstring>
#include <string>

using namespace Deep2::Transfer;
int main() {
    int pass = 0, fail = 0;
    auto check = [&](bool ok, const char* name) {
        std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
        ok ? ++pass : ++fail;
    };
    const struct Case { bool idle, begin, record, submit; Stage result; const char* order; } cases[] = {
        {false,true,true,true,Stage::Idle,"i"},
        {true,false,true,true,Stage::Begin,"ib"},
        {true,true,false,true,Stage::Record,"ibrd"},
        {true,true,true,false,Stage::Submit,"ibrs"},
        {true,true,true,true,Stage::Complete,"ibrs"}
    };
    for (const auto& c : cases) {
        std::string calls;
        auto result = Execute([&]{calls+='i';return c.idle;},
                              [&]{calls+='b';return c.begin;},
                              [&]{calls+='r';return c.record;},
                              [&]{calls+='s';return c.submit;},
                              [&]{calls+='d';});
        check(result == c.result, StageName(c.result));
        check(calls == c.order, c.order);
    }
    check(RangeFits(16,0,16),"whole buffer");
    check(RangeFits(16,15,1),"last byte");
    check(!RangeFits(16,16,1),"end offset");
    check(!RangeFits(16,17,1),"offset outside");
    check(!RangeFits(16,0,0),"zero bytes");
    check(!RangeFits(0,0,1),"empty buffer");
    check(!RangeFits(UINT64_MAX,UINT64_MAX-1,4),"addition overflow rejected");
    check(RangeFits(UINT64_MAX,UINT64_MAX-1,1),"maximum boundary");
    check(!RangeFits(16,1,UINT64_MAX),"huge transfer rejected");
    check(std::strcmp(StageName(Stage::Idle),"queue_idle")==0,"idle diagnostic");
    check(std::strcmp(StageName(Stage::Submit),"transfer_wait")==0,"submit diagnostic");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n", pass, fail);
    return fail ? 1 : 0;
}
