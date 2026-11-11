#include "../src/deep2/ExpertResidencyPlanner.hpp"
#include "../src/deep2/CompressThenCorrectPolicy.hpp"
#include <cassert>
#include <limits>
using namespace rawrxd::deep2;
int main() {
 ExpertResidencyPlanner p(100);
 assert(p.admit({0,0},40).status==AdmissionStatus::Admitted);
 assert(p.admit({0,1},40).status==AdmissionStatus::Admitted);
 assert(p.admit({0,0},40).status==AdmissionStatus::Hit);
 auto a=p.admit({0,2},40);
 assert(a.status==AdmissionStatus::Admitted && a.evictions.size()==1);
 assert(a.evictions[0]==(ExpertKey{0,1}));
 assert(p.used()==80 && p.contains({0,0}) && !p.contains({0,1}));
 assert(p.pin({0,0},true) && p.pin({0,2},true));
 auto b=p.admit({0,3},40);
 assert(b.status==AdmissionStatus::NoEvictableSpace && b.evictions.empty());
 assert(p.used()==80 && p.size()==2);
 assert(p.admit({0,3},101).status==AdmissionStatus::TooLarge);
 assert(p.admit({0,3},0).status==AdmissionStatus::InvalidSize);
 assert(p.admit({0,0},41).status==AdmissionStatus::InvalidSize);
 assert(!p.erase({0,0}));
 assert(p.pin({0,2},false) && p.erase({0,2}) && p.used()==40);
 assert(p.admit({0,3},60).status==AdmissionStatus::Admitted);
 ExpertResidencyPlanner zero(0);
 assert(zero.admit({1,1},1).status==AdmissionStatus::TooLarge);
 ExpertResidencyPlanner huge(UINT64_MAX);
 assert(huge.admit({1,1},UINT64_MAX).status==AdmissionStatus::Admitted);
 assert(huge.admit({1,2},1).status==AdmissionStatus::Admitted);
 assert(huge.used()==1);
 assert(decideCorrection(3,1,{})==CorrectionDecision::Exact);
 assert(decideCorrection(3,1,{0.45f,true})==CorrectionDecision::Approximate);
 assert(decideCorrection(1,0.8f,{0.45f,true})==CorrectionDecision::Exact);
 assert(decideCorrection(std::numeric_limits<float>::quiet_NaN(),0,{})==CorrectionDecision::Invalid);
 assert(decideCorrection(0,1,{})==CorrectionDecision::Invalid);
}
