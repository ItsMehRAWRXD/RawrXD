#include "Deep2AuthorityGates.hpp"
#include <algorithm>
#include <charconv>
#include <limits>
#include <unordered_map>
#include <unordered_set>
namespace Deep2::Authority {
namespace {
GateResult result(std::vector<std::string> errors) { return {errors.empty(),std::move(errors)}; }
bool digits(const std::string& s, uint32_t& n) { if(s.empty()) return false; auto p=std::from_chars(s.data(),s.data()+s.size(),n); return p.ec==std::errc{} && p.ptr==s.data()+s.size(); }
// Accept exact GGUF packed form blk.<layer>.ffn_{gate,up,down}_exps.weight
// and indexed model.layers.<layer>.experts.<expert>.{w1,w2,w3}.weight.
bool parse(const std::string& name,ExpertBinding& out) {
 auto parts=std::vector<std::string>{}; size_t start=0;
 while(start<=name.size()) { auto pos=name.find('.',start); parts.push_back(name.substr(start,pos==std::string::npos?std::string::npos:pos-start)); if(pos==std::string::npos) break; start=pos+1; }
 if(parts.size()==4 && parts[0]=="blk" && digits(parts[1],out.layer) && parts[3]=="weight") {
  if(parts[2]=="ffn_gate_exps") out.role="gate";
  else if(parts[2]=="ffn_up_exps") out.role="up";
  else if(parts[2]=="ffn_down_exps") out.role="down";
  else return false;
  out.packed=true;out.expert=0;out.tensor=name;return true;
 }
 if(parts.size()==7 && parts[0]=="model" && parts[1]=="layers" && digits(parts[2],out.layer) && parts[3]=="experts" && digits(parts[4],out.expert) && parts[6]=="weight") {
  if(parts[5]=="w1") out.role="gate";
  else if(parts[5]=="w2") out.role="down";
  else if(parts[5]=="w3") out.role="up";
  else return false;
  out.packed=false;out.tensor=name;return true;
 }
 return false;
}
}
Inventory AuthorityGates::discover(const std::vector<GGUFEntry>& entries) {
 Inventory inv; std::unordered_set<std::string> seen;
 for(const auto& e:entries) {
  if(!seen.insert(e.name).second) inv.errors.push_back("duplicate tensor: "+e.name);
  ExpertBinding b;
  if(parse(e.name,b)) inv.experts.push_back(std::move(b));
  else inv.unknown.push_back(e.name);
 }
 std::sort(inv.experts.begin(),inv.experts.end(),[](const auto& a,const auto& b){return a.layer!=b.layer?a.layer<b.layer:(a.expert!=b.expert?a.expert<b.expert:a.role<b.role);});
 return inv;
}
GateResult AuthorityGates::physical(const std::vector<GGUFEntry>& entries,uint64_t file_bytes,uint64_t data_start) {
 std::vector<std::string> errors; std::vector<std::pair<uint64_t,uint64_t>> ranges;
 if(data_start>file_bytes) errors.push_back("data start beyond file");
 for(const auto& e:entries) {
  if(e.name.empty() || e.dimensions.empty() || !e.bytes) errors.push_back("incomplete tensor: "+e.name);
  for(auto d:e.dimensions) if(!d) errors.push_back("zero dimension: "+e.name);
  if(e.offset>std::numeric_limits<uint64_t>::max()-data_start) {errors.push_back("offset overflow: "+e.name);continue;}
  auto begin=data_start+e.offset;
  if(begin>file_bytes || e.bytes>file_bytes-begin) {errors.push_back("out of file: "+e.name);continue;}
  ranges.emplace_back(begin,begin+e.bytes);
 }
 std::sort(ranges.begin(),ranges.end());
 for(size_t i=1;i<ranges.size();++i) if(ranges[i].first<ranges[i-1].second) errors.push_back("overlapping tensor byte ranges");
 return result(std::move(errors));
}
GateResult AuthorityGates::experts(const Inventory& inv,uint32_t expected_experts,uint32_t expected_layers) {
 auto errors=inv.errors; if(!expected_experts || !expected_layers) errors.push_back("missing expert/layer metadata");
 std::unordered_map<uint64_t,uint8_t> roles;std::unordered_map<uint32_t,uint8_t> packed;
 for(const auto& b:inv.experts) {
  if(b.layer>=expected_layers || (!b.packed && b.expert>=expected_experts)) {errors.push_back("expert index out of bounds: "+b.tensor);continue;}
  const uint8_t bit=b.role=="gate"?1:b.role=="up"?2:4;
  uint64_t key=(uint64_t(b.layer)<<32)|b.expert;
  if(roles[key]&bit) errors.push_back("duplicate expert role: "+b.tensor);
  roles[key]|=bit;
  packed[b.layer]|=b.packed?1:2;
 }
 for(const auto& [layer,mode]:packed) if(mode==3) errors.push_back("mixed packed/indexed experts at layer "+std::to_string(layer));
 for(const auto& [key,mask]:roles) if(mask!=7) errors.push_back("incomplete expert triplet at layer "+std::to_string(key>>32));
 if(inv.experts.empty()) errors.push_back("no expert tensors discovered");
 // Packed tensors represent all experts, but physical expert-axis validation requires architecture metadata.
 return result(std::move(errors));
}
GateResult AuthorityGates::graph(const Graph& g,const std::vector<Capability>& caps) {auto r=Validator::validate(g,caps);return result(std::move(r.errors));}
GateResult AuthorityGates::session(const SessionContract& old,const Graph& next,uint32_t abi) {
 std::vector<std::string> errors;
 if(old.plan_fingerprint!=Validator::fingerprint(next)) errors.push_back("graph fingerprint changed; existing state cannot be reused");
 if(old.tokenizer_identity!=next.tokenizer_identity) errors.push_back("tokenizer changed");
 if(old.state_abi!=abi || !abi) errors.push_back("state ABI mismatch");
 if(old.states.size()!=next.states.size()) errors.push_back("state count changed");
 else for(size_t i=0;i<old.states.size();++i) {const auto& a=old.states[i];const auto& b=next.states[i];if(a.id!=b.id||a.kind!=b.kind||a.shape!=b.shape||a.dtype!=b.dtype||a.version!=b.version) errors.push_back("state layout changed: "+a.id);}
 return result(std::move(errors));
}
GateResult AuthorityGates::resources(const MemoryBudget& m,const ResourceLimits& l) {
 std::vector<std::string> errors;
 if(m.host_bytes>l.max_host) errors.push_back("host budget exceeded");
 if(m.device_bytes>l.max_device) errors.push_back("device budget exceeded");
 if(m.state_bytes>l.max_state) errors.push_back("state budget exceeded");
 if(m.scratch_bytes>l.max_scratch) errors.push_back("scratch budget exceeded");
 return result(std::move(errors));
}
GateResult AuthorityGates::quantization(const std::vector<GGUFEntry>& es,const std::vector<uint32_t>& types) {
 std::vector<std::string> errors;
 for(const auto& e:es) if(std::find(types.begin(),types.end(),e.ggml_type)==types.end()) errors.push_back("unsupported ggml type "+std::to_string(e.ggml_type)+": "+e.name);
 return result(std::move(errors));
}
GateResult AuthorityGates::provenance(const Graph& g,const std::string& md,const std::string& td) {
 std::vector<std::string> errors;
 if(md.empty()||g.model_identity!=md) errors.push_back("model digest absent/mismatch");
 if(td.empty()||g.tokenizer_identity!=td) errors.push_back("tokenizer digest absent/mismatch");
 return result(std::move(errors));
}
GateResult AuthorityGates::certificate(const Graph& g,const Certificate& c,uint64_t minimum) {
 std::vector<std::string> errors;
 if(!c.passed || c.reference_identity.empty()) errors.push_back("reference certificate not passed");
 if(c.graph_fingerprint!=Validator::fingerprint(g)) errors.push_back("certificate fingerprint mismatch");
 if(!minimum || c.compared_elements<minimum) errors.push_back("insufficient reference coverage");
 return result(std::move(errors));
}
GateResult AuthorityGates::admission(const Graph& g,const Certificate& c,const std::vector<Capability>& caps,const MemoryBudget& m,const ResourceLimits& l,uint64_t min) {
 std::vector<std::string> errors;
 for(auto r:{graph(g,caps),certificate(g,c,min),resources(m,l)}) errors.insert(errors.end(),r.failures.begin(),r.failures.end());
 return result(std::move(errors));
}
}
