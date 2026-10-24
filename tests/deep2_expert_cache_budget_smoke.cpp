#include "../src/deep2/ExpertCacheBudget.hpp"
#include <cassert>
#include <limits>
using rawrxd::deep2::expertFitsBudget;
int main() {
 assert(expertFitsBudget(0,40,40));
 assert(expertFitsBudget(60,40,100));
 assert(!expertFitsBudget(61,40,100));
 assert(!expertFitsBudget(0,0,100));
 assert(!expertFitsBudget(0,101,100));
 assert(!expertFitsBudget(std::numeric_limits<std::size_t>::max(),2,100));
 assert(!expertFitsBudget(1,std::numeric_limits<std::size_t>::max(),100));
}
