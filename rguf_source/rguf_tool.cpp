#include "RGUFWriter.hpp"
#include "RGUFLoader.hpp"
#include <iostream>
#include <cstring>
#include <fstream>
#include <vector>
static void usage(){std::cout<<"rguf_tool pack <in.gguf> <out.rguf> [32-byte-hex-key]\nrguf_tool inspect <model.rguf>\nrguf_tool patch <model.rguf> <patch.rgp> <tensor> <block> <replacement.bin>\n";}
static bool hexkey(const char*s,uint8_t k[32]){if(std::strlen(s)!=64)return false;for(int i=0;i<32;i++){unsigned v; if(std::sscanf(s+2*i,"%2x",&v)!=1)return false;k[i]=(uint8_t)v;}return true;}
int main(int ac,char**av){if(ac<2){usage();return 2;}std::string e; if(!std::strcmp(av[1],"inspect")&&ac==3){rguf::Model m;if(!m.open(av[2],e)){std::cerr<<e<<"\n";return 1;}std::cout<<"RGUF blocks: "<<m.block_count()<<"\n";return 0;}if(!std::strcmp(av[1],"pack")&&(ac==4||ac==5)){uint8_t k[32]{};bool enc=ac==5;if(enc&&!hexkey(av[4],k)){std::cerr<<"key must be 64 hex characters\n";return 2;}rguf::Writer w;if(!w.pack(av[2],av[3],enc,k,e)){std::cerr<<e<<"\n";return 1;}return 0;}if(!std::strcmp(av[1],"patch")&&ac==6){std::ifstream f(av[5],std::ios::binary);if(!f){std::cerr<<"replacement open failed\n";return 1;}f.seekg(0,std::ios::end);size_t n=(size_t)f.tellg();f.seekg(0);std::vector<uint8_t>b(n);f.read((char*)b.data(),n);rguf::Writer w;uint64_t t=std::stoull(av[3]),bl=std::stoull(av[4]);if(!w.make_patch(av[2],av[5],t,bl,b.data(),b.size(),e)){std::cerr<<e<<"\n";return 1;}return 0;}usage();return 2;}
