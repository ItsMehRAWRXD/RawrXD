#include "../src/deep2/ExpertSliceBounds.hpp"
#include <cassert>
#include <cstdint>
using namespace rawrxd::deep2;
int main() {
 uint64_t out=0;
 assert(checkedExpertSlice({100,48,16,3},2,out) && out==132);
 assert(!checkedExpertSlice({100,48,16,3},3,out));
 assert(!checkedExpertSlice({100,47,16,3},2,out));
 assert(!checkedExpertSlice({UINT64_MAX-8,48,16,3},1,out));
 assert(!checkedExpertSlice({100,48,0,3},1,out));
 assert(!checkedExpertSlice({100,UINT64_MAX,UINT64_MAX,UINT64_MAX},2,out));
}
