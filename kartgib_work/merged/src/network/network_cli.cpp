#include "network.hpp"
#include <iostream>
using namespace worldforge::net;
int main(){State s{0,{{1,0,0,0,0},{2,1000,0,0,0}}};Replay replay{s,{}};for(uint32_t t=0;t<600;++t){replay.inputs.push_back({t,1,int16_t(t%120<60?120:-120),80,0});replay.inputs.push_back({t,2,0,70,0});}auto a=replay.play(600);auto b=replay.play(600);if(checksum(a)!=checksum(b))return 1;auto wire=encodeSnapshot(snapshot(a));if(!decodeSnapshot(wire))return 2;std::cout<<"NETWORK_SIM_PASS ticks="<<a.tick<<" players="<<a.players.size()<<" bytes="<<wire.size()<<" checksum="<<checksum(a)<<"\n";}
