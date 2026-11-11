#include "combat/combat.hpp"
#include <iostream>
#include <string>
using namespace kartgib::combat;
int main(int argc,char** argv){unsigned ticks=120;for(int i=1;i<argc;++i)if(std::string(argv[i])=="--ticks"&&i+1<argc)ticks=static_cast<unsigned>(std::stoul(argv[++i]));if(ticks>100000)return 2;World w;w.targets.push_back({2,{0,0,25},1,100,true});Config c;c.speed=100;fire(w,1,{0,0,0},{0,0,1},c);unsigned hits=0;for(unsigned i=0;i<ticks;++i){auto found=advance(w,c,1.0/120);hits+=static_cast<unsigned>(found.size());for(auto& hit:found)emitImpact(w,hit.point,hit.projectile,12);updateParticles(w,1.0/120);}std::cout<<"COMBAT_SIM_PASS ticks="<<ticks<<" hits="<<hits<<" target_health="<<w.targets[0].health<<" fingerprint="<<fingerprint(w)<<"\n";return hits==1?0:3;}
