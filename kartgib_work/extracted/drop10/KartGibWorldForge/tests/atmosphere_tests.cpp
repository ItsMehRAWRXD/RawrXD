#include "atmosphere/atmosphere.hpp"
#include <cassert>
#include <cmath>
#include <iostream>
int main(){using namespace kartgib::atmosphere; SkySettings s;assert(saturate(-1)==0&&saturate(2)==1);assert(std::abs(dot(normalize({3,0,4}),normalize({3,0,4}))-1)<1e-5f);assert(hash3(1,2,3,7)==hash3(1,2,3,7));assert(hash3(1,2,3,7)!=hash3(1,2,3,8));assert(noise3(2.2f,3.4f,4.5f,7)>=0);assert(fbm3(1,2,3,7)<=1);auto sky=skyColor({0,1,0},s);assert(std::isfinite(sky.x));assert(sunDisc(s.sunDirection,s.sunDirection)>.99f);assert(cloudDensity({1,2,3},s)>=0);assert(cloudShadow({1,2,3},s)<=1);assert(fogTransmittance(100,.1f)<fogTransmittance(10,.1f));auto fog=applyFog({1,0,0},{0,0,1},100,.1f);assert(fog.z>.9f);assert(std::isfinite(waterHeight(2,3,1,7)));auto normal=waterNormal(2,3,1,7);assert(normal.y>0);auto a=renderSky(32,16,s),b=renderSky(32,16,s);assert(a.rgb.size()==512&&a.rgb[10].x==b.rgb[10].x);assert(renderSky(-1,100,s).rgb.empty());std::cout<<"ATMOSPHERE_TESTS_PASS 15 functions\n";}
