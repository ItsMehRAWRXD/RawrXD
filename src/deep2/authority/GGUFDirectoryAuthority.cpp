#include "GGUFDirectoryAuthority.hpp"
#include <fstream>
#include <limits>
#include <unordered_set>
#include <stdexcept>
#include <algorithm>
namespace Deep2::Directory {
namespace {
bool add(uint64_t a,uint64_t b,uint64_t& o){if(b>UINT64_MAX-a)return false;o=a+b;return true;}
bool mul(uint64_t a,uint64_t b,uint64_t& o){if(a && b>UINT64_MAX/a)return false;o=a*b;return true;}
struct Reader {
 std::ifstream f; uint64_t size=0, pos=0;
 explicit Reader(const std::string& p):f(p,std::ios::binary|std::ios::ate){if(!f)throw std::runtime_error("cannot open GGUF");auto n=f.tellg();if(n<0)throw std::runtime_error("invalid file size");size=static_cast<uint64_t>(n);f.seekg(0);}
 void take(char* p,uint64_t n){uint64_t end;if(!add(pos,n,end)||end>size)throw std::runtime_error("truncated GGUF");if(n>0){f.read(p,static_cast<std::streamsize>(n));if(!f)throw std::runtime_error("read failure");}pos=end;}
 uint32_t u32(){unsigned char b[4];take(reinterpret_cast<char*>(b),4);return uint32_t(b[0])|(uint32_t(b[1])<<8)|(uint32_t(b[2])<<16)|(uint32_t(b[3])<<24);}
 uint64_t u64(){uint64_t lo=u32(),hi=u32();return lo|(hi<<32);}
 std::string str(){uint64_t n=u64();if(n>1'048'576)throw std::runtime_error("oversized string");std::string s(static_cast<size_t>(n),'\0');if(n)take(s.data(),n);return s;}
 void skip(uint64_t n){uint64_t end;if(!add(pos,n,end)||end>size)throw std::runtime_error("metadata outside file");f.seekg(static_cast<std::streamoff>(end));if(!f)throw std::runtime_error("seek failed");pos=end;}
 void value(uint32_t type,int depth=0){if(depth>3)throw std::runtime_error("nested metadata too deep");switch(type){case 0:case 1:case 7:skip(1);break;case 2:case 3:skip(2);break;case 4:case 5:case 6:skip(4);break;case 10:case 11:case 12:skip(8);break;case 8:(void)str();break;case 9:{uint32_t t=u32();uint64_t n=u64();if(n>10'000'000)throw std::runtime_error("oversized array");for(uint64_t i=0;i<n;i++)value(t,depth+1);break;}default:throw std::runtime_error("unknown metadata type");}}
};
}
Model inspect(const std::string& path,const Geometry& geometry){Model m;try{
 Reader r(path);m.file_bytes=r.size;char magic[4];r.take(magic,4);if(std::string(magic,4)!="GGUF")throw std::runtime_error("invalid magic");m.version=r.u32();if(m.version!=3)throw std::runtime_error("only GGUF v3 supported");uint64_t nt=r.u64(),nk=r.u64();if(nt>1'000'000||nk>1'000'000)throw std::runtime_error("unreasonable directory counts");
 for(uint64_t i=0;i<nk;i++){auto key=r.str();auto type=r.u32();if(key=="general.architecture" && type==8)m.architecture=r.str();else if(key=="general.alignment" && type==4)m.alignment=r.u32();else r.value(type);}
 if(m.alignment==0 || m.alignment>4096 || (m.alignment&(m.alignment-1)))throw std::runtime_error("invalid alignment");
 std::unordered_set<std::string> seen;m.tensors.reserve(static_cast<size_t>(nt));
 for(uint64_t i=0;i<nt;i++){Tensor t;t.name=r.str();if(t.name.empty()||!seen.insert(t.name).second)throw std::runtime_error("empty or duplicate tensor name");auto nd=r.u32();if(nd==0||nd>8)throw std::runtime_error("invalid tensor rank");for(uint32_t d=0;d<nd;d++){auto v=r.u64();if(!v)throw std::runtime_error("zero tensor dimension");t.dims.push_back(v);}t.type=r.u32();t.offset=r.u64();m.tensors.push_back(std::move(t));}
 uint64_t padded;if(!add(r.pos,m.alignment-1,padded))throw std::runtime_error("alignment overflow");m.data_start=padded&~(m.alignment-1);if(m.data_start>r.size)throw std::runtime_error("data section beyond file");
 std::vector<std::pair<uint64_t,uint64_t>> spans;
 for(auto& t:m.tensors){uint64_t elems=1;for(auto d:t.dims){uint64_t next;if(!mul(elems,d,next))throw std::runtime_error("element count overflow");elems=next;}uint64_t be=0,bb=0;if(!geometry||!geometry(t.type,be,bb)||!be||!bb)throw std::runtime_error("unknown quantization geometry for "+t.name);if(elems%be)throw std::runtime_error("tensor block misalignment: "+t.name);uint64_t blocks=elems/be;if(!mul(blocks,bb,t.bytes))throw std::runtime_error("tensor byte overflow");if(t.offset%m.alignment)throw std::runtime_error("tensor offset misalignment: "+t.name);uint64_t begin,end;if(!add(m.data_start,t.offset,begin)||!add(begin,t.bytes,end)||end>r.size)throw std::runtime_error("tensor exceeds file: "+t.name);spans.emplace_back(begin,end);}
 std::sort(spans.begin(),spans.end());for(size_t i=1;i<spans.size();i++)if(spans[i].first<spans[i-1].second)throw std::runtime_error("overlapping tensor payloads");
 }catch(const std::exception& e){m.errors.emplace_back(e.what());}return m;}
}
