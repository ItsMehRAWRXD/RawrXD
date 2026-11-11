#include "assets/assets.hpp"
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
int main(int argc,char** argv){try{uint64_t seed=20261025;int count=300;kg::Biome biome=kg::Biome::Tropical;std::filesystem::path out="assets_out";for(int i=1;i<argc;i++){std::string a=argv[i];auto val=[&](){if(++i>=argc)throw std::invalid_argument("missing argument for "+a);return std::string(argv[i]);};if(a=="--seed")seed=std::stoull(val());else if(a=="--count")count=std::stoi(val());else if(a=="--biome")biome=kg::parseBiome(val());else if(a=="--out")out=val();else if(a=="--help"){std::cout<<"worldforge-assets --seed N --biome tropical|gothic|voxel|floating --count N --out DIR\n";return 0;}else throw std::invalid_argument("unknown argument: "+a);}auto c=kg::assets::generate(seed,biome,count);std::filesystem::create_directories(out);kg::assets::exportObj(c,out/"asset_library.obj");kg::assets::exportManifest(c,out/"placements.json");std::cout<<"ASSET_FORGE_PASS meshes="<<c.meshes.size()<<" placements="<<c.placements.size()<<'\n';return 0;}catch(const std::exception& e){std::cerr<<"ASSET_FORGE_FAIL "<<e.what()<<'\n';return 1;}}
