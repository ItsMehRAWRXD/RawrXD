#include "render/hdr.hpp"
#include <cassert>
#include <cmath>
#include <iostream>
using namespace kg::render;
int main(){
Image img{8,8,std::vector<Rgb>(64,{.05f,.08f,.1f})};img.at(4,4)={8,4,2};assert(img.valid());
assert(std::abs(luminance({1,1,1})-1)<1e-5f);
assert(std::abs(exposureScale({1,.18f})-2)<1e-5f);
assert(std::abs(applyExposure({1,2,3},{1,.18f}).g-4)<1e-5f);
assert(acesToneMap({100,100,100}).r<=1);
assert(std::abs(linearToSrgb(0)-0)<1e-6f);
assert(std::abs(encodeSrgb({1,1,1}).r-1)<1e-5f);
assert(bloomPrefilter({8,4,2},{}).r>0);
auto half=downsample2x(img);assert(half.width==4&&half.height==4);
auto up=upsampleBilinear(half,8,8);assert(up.valid());
auto blur=blurSeparable(img,2);assert(blur.at(4,4).r<8);
auto bloom=makeBloom(img,{});assert(bloom.valid());
auto out=composite(img,bloom,{});assert(out.valid()&&out.at(4,4).r<=1);
auto m=analyze(img);assert(m.pixels==64&&m.maxLuminance>1&&m.clippedChannels==3);
std::string error;RenderSettings invalid;invalid.bloom.radius=40;assert(!validateSettings(invalid,&error)&&!error.empty());
auto v=viewportNormalized({0,0,8,8},8,8);assert(v[2]==1&&v[3]==1);
assert(writePpm(out,"worldforge_hdr_golden.ppm"));
std::cout<<"HDR reference 15/15 checks PASS\n";
}
