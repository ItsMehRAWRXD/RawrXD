#include "physics/vehicle.hpp"
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
using namespace kartgib::physics;
int main(int argc,char** argv){int ticks=600;std::string out="vehicle_telemetry.csv";for(int i=1;i<argc;i++){std::string a=argv[i];if(a=="--ticks"&&i+1<argc)ticks=std::atoi(argv[++i]);else if(a=="--out"&&i+1<argc)out=argv[++i];else {std::cerr<<"usage: worldforge-vehicle-cli [--ticks N] [--out telemetry.csv]\n";return 2;}}if(ticks<1||ticks>1000000)return 2;std::ofstream file(out);if(!file)return 3;file<<"tick,x,y,z,yaw,speed,boost_energy\n";State s;Config c;file<<std::setprecision(17);for(int i=0;i<ticks;i++){Input input;input.throttle=i<ticks*3/4?1:0;input.brake=i>=ticks*3/4?0.5:0;input.steer=(i>=ticks/3&&i<ticks*2/3)?0.3:0;input.boost=i>=ticks/4&&i<ticks/3;auto t=step(s,input,c,{},1.0/60);file<<s.tick<<','<<s.position.x<<','<<s.position.y<<','<<s.position.z<<','<<s.yaw<<','<<t.speed<<','<<s.boostEnergy<<'\n';}std::cout<<"VEHICLE_SIM_PASS ticks="<<ticks<<" hash="<<fingerprint(s)<<" out="<<out<<"\n";}
