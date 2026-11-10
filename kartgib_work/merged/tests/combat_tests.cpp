#ifdef NDEBUG
#undef NDEBUG
#endif
#include "combat/combat.hpp"
#include <cassert>
#include <cmath>
#include <iostream>
using namespace kartgib::combat;
int main(){Config c;assert(valid(c));assert(!valid(Config{.speed=0}));double t=0;assert(segmentSphere({0,0,0},{0,0,10},{0,0,5},1,t));assert(std::abs(t-0.4)<1e-9);assert(!segmentSphere({0,0,0},{0,0,10},{10,0,5},1,t));World w;w.targets.push_back({2,{0,0,5},0.7,100,true});assert(fire(w,1,{0,0,0},{0,0,1},c));assert(!fire(w,1,{0,0,0},{0,0,0},c));auto clone=w;auto hits=advance(w,c,0.1);auto hits2=advance(clone,c,0.1);assert(hits.size()==1&&hits2.size()==1&&hits[0].target==2);assert(!w.targets[0].alive);assert(fingerprint(w)==fingerprint(clone));emitImpact(w,hits[0].point,1,32);assert(w.particles.size()==32);updateParticles(w,0.1);assert(w.particles.size()==32);World blast;blast.targets.push_back({4,{0,0,1},0.5,100,true});assert(explode(blast,{{0,0,0},3,100}).size()==1);assert(blast.targets[0].health<100);std::cout<<"COMBAT_TESTS_PASS\n";}
