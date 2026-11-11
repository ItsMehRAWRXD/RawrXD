// RawrXD GGUF v2/v3 inventory reader. C++20 STL only. No model execution.
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <vector>
#include <limits>
#include <map>
#include <filesystem>
using u64=std::uint64_t;
struct Reader {
 std::ifstream f; u64 length=0;
 explicit Reader(const char* path):f(path,std::ios::binary){
  if(!f) throw std::runtime_error("open failed");
  f.seekg(0,std::ios::end); length=(u64)f.tellg(); f.seekg(0);
 }
 void need(u64 n){auto p=f.tellg(); if(p<0 || (u64)p>length || n>length-(u64)p) throw std::runtime_error("truncated or invalid GGUF");}
 template<class T> T get(){T x{};need(sizeof x);f.read(reinterpret_cast<char*>(&x),sizeof x);if(!f)throw std::runtime_error("read failed");return x;}
 std::string str(){auto n=get<u64>(); if(n>16*1024*1024)throw std::runtime_error("oversized string");need(n);std::string s((size_t)n,'\0');f.read(s.data(),(std::streamsize)n);return s;}
 void skip(u64 n){need(n);f.seekg((std::streamoff)n,std::ios::cur);if(!f)throw std::runtime_error("seek failed");}
};
static u64 elem_size(unsigned t){switch(t){case 0:case 1:case 7:return 1;case 2:case 3:return 2;case 4:case 5:case 6:return 4;case 10:case 11:case 12:return 8;default:throw std::runtime_error("unknown metadata scalar type");}}
static void skip_value(Reader& r,unsigned t,unsigned depth=0){
 if(depth>8)throw std::runtime_error("nested metadata too deep");
 if(t==8){(void)r.str();return;}
 if(t==9){auto subtype=r.get<std::uint32_t>();auto n=r.get<u64>();if(n>100000000)throw std::runtime_error("oversized metadata array");
  if(subtype==8){for(u64 i=0;i<n;++i)(void)r.str();}
  else if(subtype==9){throw std::runtime_error("nested arrays unsupported: fail closed");}
  else {auto s=elem_size(subtype);if(n>std::numeric_limits<u64>::max()/s)throw std::runtime_error("overflow");r.skip(n*s);}return;
 }
 r.skip(elem_size(t));
}
int main(int argc,char**argv){try{
 if(argc!=2){std::cerr<<"usage: gguf_inventory <model.gguf>\n";return 2;}
 Reader r(argv[1]);char magic[4];r.need(4);r.f.read(magic,4);
 if(std::string(magic,4)!="GGUF")throw std::runtime_error("not GGUF");
 auto version=r.get<std::uint32_t>();if(version!=2&&version!=3)throw std::runtime_error("unsupported GGUF version");
 auto tensors=r.get<u64>(), metadata=r.get<u64>();
 if(tensors>1000000||metadata>1000000)throw std::runtime_error("unreasonable counts");
 std::cout<<"GGUF_VERSION="<<version<<" TENSORS="<<tensors<<" METADATA="<<metadata<<"\n";
 std::string arch;std::map<std::uint32_t,u64> types;
 for(u64 i=0;i<metadata;++i){auto key=r.str();auto t=r.get<std::uint32_t>();
  if(key=="general.architecture" && t==8){arch=r.str();std::cout<<"ARCH="<<arch<<"\n";}
  else if((key.find("block_count")!=std::string::npos||key.find("context_length")!=std::string::npos||key.find("expert_count")!=std::string::npos) && (t==4||t==5||t==10||t==11)){
   std::cout<<"META "<<key<<"=";if(t==4)std::cout<<r.get<std::uint32_t>();else if(t==5)std::cout<<r.get<std::int32_t>();else if(t==10)std::cout<<r.get<u64>();else std::cout<<r.get<std::int64_t>();std::cout<<"\n";
  } else skip_value(r,t);
 }
 for(u64 i=0;i<tensors;++i){auto name=r.str();auto nd=r.get<std::uint32_t>();if(nd>8)throw std::runtime_error("invalid tensor dimensions");
  std::cout<<"TENSOR "<<name<<" dims=";for(unsigned j=0;j<nd;++j)std::cout<<(j?"x":"")<<r.get<u64>();
  auto t=r.get<std::uint32_t>();auto offset=r.get<u64>();++types[t];
  std::cout<<" ggml_type="<<t<<" relative_offset="<<offset<<"\n";
 }
 for(auto [t,n]:types)std::cout<<"TYPE "<<t<<" COUNT="<<n<<"\n";
 if(arch!="nemotron_h_moe") {std::cerr<<"NOT_BOLT_ARCHITECTURE: no execution authorized\n";return 3;}
 std::cout<<"INVENTORY_ONLY: operator/quantization compatibility NOT certified\n";return 0;
 }catch(const std::exception&e){std::cerr<<"FAIL_CLOSED: "<<e.what()<<"\n";return 1;}}
