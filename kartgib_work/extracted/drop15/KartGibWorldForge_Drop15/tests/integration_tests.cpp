#include "integration/runtime.hpp"
#include <cassert>
#include <cmath>
#include <vector>
int main(){
 using namespace worldforge::integration;
 Runtime r;
 assert(r.scene().nodes().size()==2);
 auto initial=r.vehicle().tick;
 auto f=r.advance({});
 assert(f.tick==initial+1);
 assert(r.scene().worldTransform(r.scene().nodes().front().id).has_value());
 std::vector<Command> inputs(180);
 for(size_t i=0;i<inputs.size();++i){inputs[i].driving.throttle=.5;inputs[i].fire=(i==0);}
 auto first=r.replay(inputs);
 auto second=r.replay(inputs);
 assert(first.size()==180&&second.size()==180);
 for(size_t i=0;i<first.size();++i){assert(first[i].tick==second[i].tick);assert(first[i].vehicleHash==second[i].vehicleHash);assert(first[i].combatHash==second[i].combatHash);}
 assert(first.back().tick==180);
 assert(std::isfinite(first.back().x)&&std::isfinite(first.back().z));
 r.reset();assert(r.vehicle().tick==0&&r.combat().tick==0);
}