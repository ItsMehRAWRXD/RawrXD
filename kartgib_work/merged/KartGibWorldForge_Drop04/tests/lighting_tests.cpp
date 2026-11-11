#include "render/lighting.hpp"
#include <cassert>
#include <cmath>
#include <iostream>
using namespace kg::render;
int main(){
 auto eq=[](float a,float b){return std::abs(a-b)<1e-4f;};
 assert(eq(dot({1,2,3},{4,5,6}),32)); // 01
 assert(eq(normalize({0,3,4}).y,.6f)); // 02
 Mat4 identity;identity.m={1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1};assert(eq(transformPoint(identity,{1,2,3}).z,3)); // 03
 auto proj=orthographic(-1,1,-1,1,1,11);assert(eq(transformPoint(proj,{0,0,-1}).z,0)); // 04
 auto view=lookAt({0,0,5},{0,0,0},{0,1,0});assert(eq(transformPoint(view,{0,0,0}).z,-5)); // 05
 auto c=cascadeSplits(1,100,4,.5f);assert(c.splits.size()==4&&eq(c.splits.back(),100)); // 06
 assert(chooseCascade(101,c)==3&&chooseCascade(1,c)==0); // 07
 assert(slopeBias({0,1,0},{0,1,0},{})<slopeBias({0,1,0},{1,0,0},{})); // 08
 ShadowMap map{4,4,std::vector<float>(16,.5f)};assert(map.valid());assert(eq(sampleShadowNearest(map,.5f,.5f,.4f,0),1));assert(eq(sampleShadowNearest(map,.5f,.5f,.6f,0),0)); // 09
 assert(eq(sampleShadowPcf(map,.5f,.5f,.4f,0,1),1)); // 10
 assert(eq(lambert({0,1,0},{0,1,0}),1)); // 11
 assert(ggxDistribution(1,.5f)>ggxDistribution(.5f,.5f)); // 12
 assert(smithGeometry(1,1,.5f)>.99f); // 13
 auto lit=shadeDirectional({.8f,.3f,.2f},{0,1,0},{0,1,0},{{0,-1,0},{1,1,1},3},.5f,0,1,.07f);assert(lit.r>lit.b&&lit.r>.05f); // 14
 auto point=shadePoint({1,1,1},{0,0,0},{0,1,0},{{0,2,0},{1,1,1},100,10});assert(point.r>0); // 15
 std::string err;ShadowSettings invalid;invalid.pcfRadius=100;assert(!validateShadowSettings(invalid,&err));
 std::cout<<"Shadow/lighting 15/15 checks PASS\n";
}
