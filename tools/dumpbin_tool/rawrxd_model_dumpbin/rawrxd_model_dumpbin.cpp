// RawrXD Model DumpBin - standalone read-only GGUF inspector, C++17.
// No inference claims. Never modifies input model files.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using u64 = uint64_t;
struct Error : std::runtime_error { using std::runtime_error::runtime_error; };
static std::string esc(const std::string& s) { std::ostringstream o; for(unsigned char c:s){ if(c=='"'||c=='\\')o<<'\\'<<c;else if(c=='\n')o<<"\\n";else if(c=='\r')o<<"\\r";else if(c=='\t')o<<"\\t";else if(c<32){o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)c<<std::dec;}else o<<c;} return o.str(); }
static u64 add(u64 a,u64 b){if(b>UINT64_MAX-a)throw Error("integer overflow");return a+b;}
static u64 mul(u64 a,u64 b){if(a && b>UINT64_MAX/a)throw Error("integer overflow");return a*b;}
class Reader {
 std::ifstream f; u64 n=0,p=0;
public:
 explicit Reader(const std::string& path):f(path,std::ios::binary){if(!f)throw Error("cannot open input"); f.seekg(0,std::ios::end);auto z=f.tellg();if(z<0)throw Error("cannot determine file size");n=(u64)z;f.seekg(0);}
 u64 pos()const{return p;} u64 size()const{return n;}
 void bytes(char* dst,u64 len){if(len>n-p)throw Error("truncated file at byte "+std::to_string(p));if(len>static_cast<u64>(std::numeric_limits<std::streamsize>::max()))throw Error("oversized read");f.read(dst,(std::streamsize)len);if(!f)throw Error("read failed");p+=len;}
 void skip(u64 len){if(len>n-p)throw Error("truncated value at byte "+std::to_string(p));p+=len;f.seekg((std::streamoff)p,std::ios::beg);if(!f)throw Error("seek failed");}
 uint8_t u8(){char b;bytes(&b,1);return (uint8_t)b;}
 uint16_t u16(){uint16_t v=0;for(int i=0;i<2;i++)v|=(uint16_t)u8()<<(8*i);return v;}
 uint32_t u32(){uint32_t v=0;for(int i=0;i<4;i++)v|=(uint32_t)u8()<<(8*i);return v;}
 u64 u64v(){u64 v=0;for(int i=0;i<8;i++)v|=(u64)u8()<<(8*i);return v;}
 std::string str(bool capture=true){u64 len=u64v();if(len>size()-pos())throw Error("invalid string length at "+std::to_string(pos()));if(!capture || len>4096){skip(len);return "<skipped "+std::to_string(len)+" bytes>";}std::string s((size_t)len,'\0');if(len)bytes(&s[0],len);return s;}
};
static const char* typ(uint32_t t){static const char* names[]={"UINT8","INT8","UINT16","INT16","UINT32","INT32","FLOAT32","BOOL","STRING","ARRAY","UINT64","INT64","FLOAT64"};return t<13?names[t]:"UNKNOWN";}
static u64 width(uint32_t t){switch(t){case 0:case 1:case 7:return 1;case 2:case 3:return 2;case 4:case 5:case 6:return 4;case 10:case 11:case 12:return 8;default:return 0;}}
static std::string scalar(Reader& r,uint32_t t,bool capture){
 if(t==8)return r.str(capture);
 if(t==9)throw Error("unexpected nested array");
 u64 w=width(t);if(!w)throw Error("unsupported metadata type "+std::to_string(t)+" at byte "+std::to_string(r.pos()));
 if(!capture){r.skip(w);return "";}
 u64 v=0;for(u64 i=0;i<w;i++)v|=(u64)r.u8()<<(8*i);
 if(t==7)return v?"true":"false";
 if(t==6){uint32_t bits=(uint32_t)v;float x;std::memcpy(&x,&bits,4);return std::to_string(x);}
 if(t==12){double x;std::memcpy(&x,&v,8);return std::to_string(x);}
 if(t==1)return std::to_string((int8_t)v);
 if(t==3)return std::to_string((int16_t)v);
 if(t==5)return std::to_string((int32_t)v);
 if(t==11)return std::to_string((int64_t)v);
 return std::to_string(v);
}
struct Meta{std::string key,value;uint32_t type;u64 offset,count=0;};
static Meta metadata(Reader& r){Meta m; m.offset=r.pos();m.key=r.str();m.type=r.u32();
 if(m.type==9){uint32_t elem=r.u32();u64 count=r.u64v();m.count=count;if(elem==9||elem>12)throw Error("invalid array element type "+std::to_string(elem)+" at "+std::to_string(r.pos()));
  u64 w=width(elem);if(w){r.skip(mul(count,w));}else if(elem==8){if(count>r.size()/8)throw Error("impossible string array length");for(u64 i=0;i<count;i++)r.str(false);}else throw Error("unsupported array element type");
  m.value="array<"+std::string(typ(elem))+"> count="+std::to_string(count);
 }else m.value=scalar(r,m.type,true);
 return m;}
struct Tensor{std::string name;std::vector<u64> dims;uint32_t type;u64 offset;};
static void usage(){std::cerr<<"Usage: rawrxd_model_dumpbin.exe --source model.gguf [--metadata] [--tensors] [--experts] [--reap-check] [--json] [--max-items N]\n";}
int main(int argc,char**argv){std::string path;bool showMeta=false,showTensor=false,experts=false,reap=false,json=false;u64 maxItems=100;
 try{
 for(int i=1;i<argc;i++){std::string a=argv[i];if(a=="--source"&&i+1<argc)path=argv[++i];else if(a=="--metadata")showMeta=true;else if(a=="--tensors")showTensor=true;else if(a=="--experts")experts=true;else if(a=="--reap-check")reap=true;else if(a=="--json")json=true;else if(a=="--max-items"&&i+1<argc){maxItems=std::stoull(argv[++i]);if(maxItems>100000)throw Error("max-items too large");}else if(a=="--help"||a=="-h"){usage();return 0;}else throw Error("unknown or incomplete argument: "+a);}
 if(path.empty()){usage();return 2;}Reader r(path);char magic[4];r.bytes(magic,4);if(std::memcmp(magic,"GGUF",4))throw Error("not a GGUF file");uint32_t ver=r.u32();if(ver!=2&&ver!=3)throw Error("unsupported GGUF version "+std::to_string(ver));u64 nt=r.u64v(),nm=r.u64v();if(nt>10000000||nm>10000000)throw Error("unreasonable GGUF entry counts");
 std::vector<Meta> ms;std::vector<Tensor> ts;ms.reserve((size_t)std::min<u64>(nm,100000));
 for(u64 i=0;i<nm;i++){u64 at=r.pos();try{ms.push_back(metadata(r));}catch(const std::exception&e){throw Error("metadata entry #"+std::to_string(i)+" at byte "+std::to_string(at)+": "+e.what());}}
 for(u64 i=0;i<nt;i++){Tensor t;t.name=r.str();uint32_t nd=r.u32();if(nd>8)throw Error("invalid tensor dimension count at "+std::to_string(r.pos()));for(uint32_t j=0;j<nd;j++)t.dims.push_back(r.u64v());t.type=r.u32();t.offset=r.u64v();ts.push_back(std::move(t));}
 u64 align=32;std::string arch="unknown";u64 expertCount=0,expertUsed=0;for(const auto&m:ms){if(m.key=="general.alignment"){try{align=std::stoull(m.value);}catch(...){}}if(m.key=="general.architecture")arch=m.value;if(m.key.find("expert_count")!=std::string::npos && m.key.find("expert_used_count")==std::string::npos){try{expertCount=std::stoull(m.value);}catch(...){}}if(m.key.find("expert_used_count")!=std::string::npos){try{expertUsed=std::stoull(m.value);}catch(...){}}}
 if(align==0||align>1048576||(align&(align-1)))throw Error("invalid GGUF alignment");u64 headerEnd=r.pos(),dataStart=add(headerEnd,(align-(headerEnd%align))%align);if(dataStart>r.size())throw Error("tensor data begins beyond EOF");
 u64 gates=0,ups=0,downs=0;for(const auto&t:ts){if(t.name.find(".ffn_gate_exps.weight")!=std::string::npos)gates++;if(t.name.find(".ffn_up_exps.weight")!=std::string::npos)ups++;if(t.name.find(".ffn_down_exps.weight")!=std::string::npos)downs++;}
 bool layout=gates>0&&gates==ups&&ups==downs;
 if(json){std::cout<<"{\"status\":\"INSPECT_OK\",\"source\":\""<<esc(path)<<"\",\"file_bytes\":"<<r.size()<<",\"gguf_version\":"<<ver<<",\"architecture\":\""<<esc(arch)<<"\",\"metadata_count\":"<<nm<<",\"tensor_count\":"<<nt<<",\"tensor_data_offset\":"<<dataStart<<",\"expert_count\":"<<expertCount<<",\"expert_used_count\":"<<expertUsed<<",\"stacked_expert_triplets\":"<<gates<<",\"reap_layout_candidate\":"<<(layout?"true":"false")<<",\"runtime_inference_observed\":false";
 if(showMeta){std::cout<<",\"metadata\":[";for(size_t i=0;i<ms.size()&&i<maxItems;i++){if(i)std::cout<<",";const auto&m=ms[i];std::cout<<"{\"key\":\""<<esc(m.key)<<"\",\"type\":\""<<typ(m.type)<<"\",\"offset\":"<<m.offset<<",\"value\":\""<<esc(m.value)<<"\"}";}std::cout<<"]";}
 if(showTensor){std::cout<<",\"tensors\":[";for(size_t i=0;i<ts.size()&&i<maxItems;i++){if(i)std::cout<<",";const auto&t=ts[i];std::cout<<"{\"name\":\""<<esc(t.name)<<"\",\"type_id\":"<<t.type<<",\"offset\":"<<t.offset<<",\"dims\":[";for(size_t j=0;j<t.dims.size();j++){if(j)std::cout<<",";std::cout<<t.dims[j];}std::cout<<"]}";}std::cout<<"]";}std::cout<<"}\n";
 }else{std::cout<<"RawrXD Model DumpBin | READ ONLY\nSource: "<<path<<"\nFile bytes: "<<r.size()<<"\nGGUF version: "<<ver<<"\nArchitecture: "<<arch<<"\nMetadata entries: "<<nm<<"\nTensors: "<<nt<<"\nTensor data begins: "<<dataStart<<"\n";
 if(showMeta)for(size_t i=0;i<ms.size()&&i<maxItems;i++){const auto&m=ms[i];std::cout<<"[META #"<<i<<" @"<<m.offset<<"] "<<m.key<<" ("<<typ(m.type)<<") = "<<m.value<<"\n";}
 if(showTensor)for(size_t i=0;i<ts.size()&&i<maxItems;i++){const auto&t=ts[i];std::cout<<"[TENSOR #"<<i<<"] "<<t.name<<" type="<<t.type<<" offset="<<t.offset<<" dims=";for(auto d:t.dims)std::cout<<d<<"x";std::cout<<"\n";}
 if(experts||reap)std::cout<<"MoE: expert_count="<<expertCount<<" expert_used_count="<<expertUsed<<" stacked gate/up/down="<<gates<<"/"<<ups<<"/"<<downs<<"\n";
 if(reap)std::cout<<"REAP: "<<(layout?"candidate tensor names found; verify geometry, calibration, manifest and transformer architecture support":"required stacked tensor triplets not found")<<"\n";
 std::cout<<"Runtime inference: NOT OBSERVED (offline inspection only)\n";}
 return 0;
 }catch(const std::exception&e){if(json)std::cout<<"{\"status\":\"FAIL\",\"error\":\""<<esc(e.what())<<"\"}\n";else std::cerr<<"MODEL_DUMPBIN_FAIL: "<<e.what()<<"\n";return 1;}
}
