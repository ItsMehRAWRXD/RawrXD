#include "../src/deep2/ExpertBatchPlanner.hpp"
#include <cassert>
#include <limits>
using namespace rawrxd::deep2;
int main() {
 ExpertResidencyPlanner p(100);
 assert(p.admit({0,0},40).status==AdmissionStatus::Admitted);
 auto a=planExpertBatch(p,{{{0,0},40,0.9f},{{0,1},40,0.8f}});
 assert(a.accepted && a.hits.size()==1 && a.loads.size()==1 && p.used()==80);
 assert(p.pin({0,0},true));
 auto b=planExpertBatch(p,{{{0,2},80,0.8f}});
 assert(!b.accepted && p.used()==80 && p.contains({0,1}));
 auto c=planExpertBatch(p,{{{0,2},40,0.8f}});
 assert(c.accepted && c.evictions.size()==1 && c.evictions[0]==(ExpertKey{0,1}));
 auto d=planExpertBatch(p,{{{0,3},40,std::numeric_limits<float>::quiet_NaN()}});
 assert(!d.accepted && p.used()==80);
 auto e=planExpertBatch(p,{{{0,2},41,0.8f}});
 assert(!e.accepted && p.used()==80);
}
