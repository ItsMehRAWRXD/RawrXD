#include "gameplay/gameplay.hpp"
#include <cassert>
#include <cmath>
#include <stdexcept>
#include <iostream>
using namespace wf::gameplay;
int main(){Track t{{{0,{0,0,0}},{2,{4,2,0}}},false};assert(interpolate(t,1).x==2);t.loop=true;assert(interpolate(t,3).x==2);Clip c{{{0,{}},{2,{{4,0,0},{2,2,2},90}}},false};assert(sample(c,1).position.x==2);assert(blend({},{},.5).scale.x==1);assert(envelope({.1,.1,.5,.1},-.1,1)==0);assert(envelope({.1,.1,.5,.1},1.2,1)==0);assert(std::abs(oscillator(.25,0)-1)<1e-9);auto a=synthesize({440,.1,.3},{.01,.02,.5,.03},22050,0);assert(!a.empty());assert(mix({a,a}).size()==a.size());assert(lowpass(a,1000,22050).size()==a.size());assert(delay(a,20,.5).size()==a.size()+20);auto code=compile("set 0 0\nadd 0 1\nwait 0.01\nadd 0 2\nemit 5\nstop\n");VM v;execute(v,code,.016);assert(v.registers[0]==1&&v.events.empty());execute(v,code,.016);assert(v.registers[0]==3&&v.events.size()==1&&v.halted);VM w;execute(w,code,.016);execute(w,code,.016);assert(fingerprint(v)==fingerprint(w));auto loop=compile("set 0 0\nadd 0 1\njlt 0 3 1\nstop\n");VM l;execute(l,loop,0);assert(l.halted&&l.registers[0]==3);bool threw=false;try{compile("jlt 0 1 99");}catch(const std::invalid_argument&){threw=true;}assert(threw);std::cout<<"GAMEPLAY_TESTS_PASS\n";}
