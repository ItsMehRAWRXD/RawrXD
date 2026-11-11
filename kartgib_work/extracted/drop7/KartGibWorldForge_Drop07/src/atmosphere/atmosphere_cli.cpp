#include "atmosphere/atmosphere.hpp"
#include <cstdlib>
#include <iostream>
int main(int argc,char**argv){using namespace kartgib::atmosphere; if(argc<2){std::cerr<<"usage: worldforge-sky-bake output.ppm [seed] [width] [height]\n";return 2;} SkySettings s;if(argc>2)s.seed=static_cast<uint32_t>(std::strtoul(argv[2],nullptr,10));int w=argc>3?std::atoi(argv[3]):960,h=argc>4?std::atoi(argv[4]):540;Image im=renderSky(w,h,s);if(!writePpm(im,argv[1])){std::cerr<<"sky export failed\n";return 1;}std::cout<<"SKY_BAKE_PASS "<<w<<"x"<<h<<" seed="<<s.seed<<"\n";return 0;}
