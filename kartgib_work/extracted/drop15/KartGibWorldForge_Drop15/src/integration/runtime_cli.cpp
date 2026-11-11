#include "integration/runtime.hpp"
#include <iostream>
#include <string>
#include <vector>
int main(int argc,char** argv){
 int ticks=600;
 if(argc>1){try{ticks=std::stoi(argv[1]);}catch(...){return 2;}}
 if(ticks<1||ticks>100000)return 2;
 std::vector<worldforge::integration::Command> inputs(static_cast<size_t>(ticks));
 for(int i=0;i<ticks;++i){inputs[i].driving.throttle=i<ticks/2?0.6:0.0;inputs[i].fire=(i==0);}
 worldforge::integration::Runtime run;
 auto a=run.replay(inputs),b=run.replay(inputs);
 if(a.size()!=b.size()||a.back().vehicleHash!=b.back().vehicleHash||a.back().combatHash!=b.back().combatHash)return 3;
 if(argc>2&&!run.exportScene(argv[2]))return 4;
 std::cout<<"INTEGRATION_PASS ticks="<<ticks<<" vehicle_hash="<<a.back().vehicleHash<<" combat_hash="<<a.back().combatHash<<" nodes="<<run.scene().nodes().size()<<"\n";
 return 0;
}