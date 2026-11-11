#include "../src/deep2/StagedExpertBatch.hpp"
#include <cassert>
using namespace rawrxd::deep2;
int main() {
 ExpertResidencyPlanner live(80);
 assert(live.admit({0,0},40).status==AdmissionStatus::Admitted);
 StagedExpertBatch aborted(live,{{{0,1},40,0.9f}});
 assert(aborted.ready());
 assert(!live.contains({0,1}) && live.used()==40);
 aborted.abort();
 assert(!aborted.commit(live));
 assert(!live.contains({0,1}));
 StagedExpertBatch completed(live,{{{0,1},40,0.9f}});
 assert(completed.ready() && completed.commit(live));
 assert(live.contains({0,1}) && live.used()==80);
 assert(!completed.commit(live));
 StagedExpertBatch rejected(live,{{{0,2},100,0.9f}});
 assert(!rejected.ready() && !rejected.commit(live));
 assert(live.used()==80);
}
