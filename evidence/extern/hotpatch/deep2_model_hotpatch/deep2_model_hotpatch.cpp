#include "deep2_model_hotpatch.hpp"
#include <algorithm>
#include <fstream>
#include <limits>
#include <set>
namespace deep2 {
namespace {
struct Reader {
 std::ifstream f; uint64_t length=0;
 explicit Reader(const std::string& p):f(p,std::ios::binary|std::ios::ate){if(f){length=static_cast<uint64_t>(f.tellg()); f.seekg(0);}}
 bool bytes(void* out,uint64_t n){if(!f || n>length || static_cast<uint64_t>(f.tellg())>length-n)return false;return bool(f.read(static_cast<char*>(out),static_cast<std::streamsize>(n)));}
 bool u32(uint32_t& x){return bytes(&x,4);} bool u64(uint64_t& x){return bytes(&x,8);}
 bool skip(uint64_t n){if(!f || n>length || static_cast<uint64_t>(f.tellg())>length-n)return false;f.seekg(static_cast<std::streamoff>(n),std::ios::cur);return bool(f);}
 bool str(std::string& s){uint64_t n=0;if(!u64(n)||n>1048576)return false;s.resize(static_cast<size_t>(n));return n==0||bytes(&s[0],n);}
};
bool value(Reader& r,uint32_t t,uint64_t& integer,std::string& text,int depth=0){
 if(depth>4)return false;
 switch(t){
 case 0:case 1:case 7: return r.skip(1);
 case 2:case 3: return r.skip(2);
 case 4:case 5:case 6: {uint32_t x;if(!r.u32(x))return false;if(t==4)integer=x;return true;}
 case 8:return r.str(text);
 case 9:{uint32_t inner;uint64_t count;if(!r.u32(inner)||!r.u64(count)||count>10000000)return false;for(uint64_t i=0;i<count;++i){uint64_t ignored=0;std::string tmp;if(!value(r,inner,ignored,tmp,depth+1))return false;}return true;}
 case 10:case 11:case 12:{uint64_t x;if(!r.u64(x))return false;if(t==10)integer=x;return true;}
 default:return false;
 }
}
}
bool inspect_gguf(const std::string& path,ModelSpec& spec,std::string& error){
 Reader r(path); if(!r.f){error="cannot open GGUF";return false;}
 char magic[4];uint32_t version=0;uint64_t tensors=0,metadata=0;
 if(!r.bytes(magic,4)||std::string(magic,4)!="GGUF"||!r.u32(version)||(version!=2&&version!=3)||!r.u64(tensors)||!r.u64(metadata)||tensors>1000000||metadata>1000000){error="invalid/unsupported GGUF header";return false;}
 ModelSpec found;found.path=path;
 for(uint64_t i=0;i<metadata;++i){std::string key,txt;uint32_t type=0;uint64_t num=0;
  if(!r.str(key)||!r.u32(type)||!value(r,type,num,txt)){error="malformed GGUF metadata";return false;}
  if(key=="general.architecture"&&type==8)found.architecture=txt;
  else if(key.size()>12&&key.find(".block_count")!=std::string::npos)found.blocks=num;
  else if(key.find(".embedding_length")!=std::string::npos)found.embedding=num;
  else if(key.find(".expert_count")!=std::string::npos)found.experts=num;
  else if(key.find(".expert_used_count")!=std::string::npos)found.experts_used=num;
 }
 if(found.architecture.empty()){error="GGUF architecture missing";return false;}
 std::set<uint32_t> types;
 for(uint64_t i=0;i<tensors;++i){std::string name;uint32_t dims=0,type=0;uint64_t offset=0;
  if(!r.str(name)||!r.u32(dims)||dims>4){error="malformed tensor descriptor";return false;}
  for(uint32_t d=0;d<dims;++d){uint64_t extent;if(!r.u64(extent)||extent==0){error="invalid tensor dimensions";return false;}}
  if(!r.u32(type)||!r.u64(offset)){error="malformed tensor type/offset";return false;}
  types.insert(type);
 }
 found.tensor_types.assign(types.begin(),types.end());spec=std::move(found);return true;
}
bool Registry::install(Plugin p,std::string& error){
 if(p.contract.abi_version!=1||p.contract.architecture.empty()||p.name.empty()||!p.hooks.execute_token){error="invalid plugin contract or missing executable hook";return false;}
 auto ptr=std::make_shared<const Plugin>(std::move(p));std::lock_guard<std::mutex> guard(mu_);active_[ptr->contract.architecture]=std::move(ptr);return true;
}
SessionBinding Registry::bind(const ModelSpec& spec,const std::vector<std::string>& available_ops,std::string& error)const{
 std::lock_guard<std::mutex> guard(mu_);auto it=active_.find(spec.architecture);
 if(it==active_.end()){error="no native compute plugin for architecture: "+spec.architecture;return {};}
 const auto& c=it->second->contract;
 for(const auto& op:c.required_ops)if(std::find(available_ops.begin(),available_ops.end(),op)==available_ops.end()){error="missing operator: "+op;return {};}
 for(uint32_t t:spec.tensor_types)if(std::find(c.supported_tensor_types.begin(),c.supported_tensor_types.end(),t)==c.supported_tensor_types.end()){error="unsupported tensor type: "+std::to_string(t);return {};}
 return {it->second,spec};
}
bool execute_checked(const SessionBinding& b,void* runtime,uint64_t token,std::string& error){
 if(!b.valid()){error="unbound model execution rejected";return false;}
 if(!b.plugin->hooks.execute_token(runtime,token)){error="native compute execution failed: "+b.plugin->name;return false;}
 return true;
}
}
