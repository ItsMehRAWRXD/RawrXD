#include "Deep2RowSplitPlan.hpp"
#include <cstdio>

int main() {
    using namespace Deep2;
    {
        auto p=Deep2ChooseRowSplit(61,32ull<<30,16ull<<30);
        if(!p.valid || p.row0Count!=41 || p.row1Count!=20) return 1;
    }
    {
        auto p=Deep2ChooseRowSplit(60,32ull<<30,16ull<<30);
        if(!p.valid || p.row0Count!=40 || p.row1Count!=20) return 2;
    }
    {
        auto p=Deep2ChooseRowSplit(2,1,1);
        if(!p.valid || p.row0Count!=1 || p.row1Count!=1) return 3;
    }
    {
        auto p=Deep2ChooseRowSplit(1,32,16);
        if(p.valid) return 4;
    }
    std::puts("BATCH10_ROW_SPLIT_PLAN_SELFTEST=PASS");
    return 0;
}
