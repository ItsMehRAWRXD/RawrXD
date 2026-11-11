#include "Deep2Authority.hpp"
#include <unordered_set>
#include <cmath>
#include <limits>
#include <utility>

namespace Deep2::Authority {
namespace {
constexpr uint64_t offset=14695981039346656037ull, prime=1099511628211ull;
void byte(uint64_t& h, uint8_t b) { h=(h^b)*prime; }
void number(uint64_t& h, uint64_t n) { for(int i=0;i<8;++i) byte(h, static_cast<uint8_t>(n>>(i*8))); }
void str(uint64_t& h,const std::string& s) { number(h,s.size()); for(unsigned char c:s) byte(h,c); }
void dims(uint64_t& h,const std::vector<uint64_t>& d) { number(h,d.size()); for(auto n:d) number(h,n); }
}
uint64_t Validator::fingerprint(const Graph& g) {
 uint64_t h=offset; str(h,g.model_identity); str(h,g.tokenizer_identity);
 number(h,g.tensors.size());
 for(const auto& t:g.tensors) { str(h,t.name); dims(h,t.shape); number(h,static_cast<uint8_t>(t.dtype)); number(h,t.byte_offset); number(h,t.byte_size); }
 number(h,g.nodes.size());
 for(const auto& n:g.nodes) { str(h,n.id); number(h,static_cast<uint8_t>(n.op)); number(h,n.inputs.size()); for(const auto& x:n.inputs) str(h,x); str(h,n.output); dims(h,n.output_shape); number(h,static_cast<uint8_t>(n.output_dtype)); str(h,n.semantic_id); str(h,n.state_id); }
 number(h,g.states.size());
 for(const auto& s:g.states) { str(h,s.id); number(h,static_cast<uint8_t>(s.kind)); dims(h,s.shape); number(h,static_cast<uint8_t>(s.dtype)); number(h,s.version); }
 return h;
}
Report Validator::validate(const Graph& g,const std::vector<Capability>& caps) {
 Report r; r.fingerprint=fingerprint(g);
 auto fail=[&](const std::string& s){r.errors.push_back(s);};
 if(g.model_identity.empty()) fail("missing model identity");
 if(g.tokenizer_identity.empty()) fail("missing tokenizer identity");
 if(g.nodes.empty()) fail("empty execution graph");
 std::unordered_set<std::string> available, ids, state_ids;
 for(const auto& t:g.tensors) {
  if(t.name.empty() || !available.insert(t.name).second) fail("duplicate/empty tensor name: "+t.name);
  if(t.dtype==DType::Unknown || t.shape.empty() || t.byte_size==0) fail("incomplete tensor descriptor: "+t.name);
  for(auto d:t.shape) if(!d) fail("zero tensor dimension: "+t.name);
  if(t.byte_offset>std::numeric_limits<uint64_t>::max()-t.byte_size) fail("tensor byte range overflow: "+t.name);
 }
 for(const auto& s:g.states) {
  if(s.id.empty() || !state_ids.insert(s.id).second) fail("duplicate/empty state: "+s.id);
  if(s.shape.empty() || s.dtype==DType::Unknown || !s.version) fail("incomplete state: "+s.id);
  for(auto d:s.shape) if(!d) fail("zero state dimension: "+s.id);
 }
 for(const auto& n:g.nodes) {
  if(n.id.empty() || !ids.insert(n.id).second) fail("duplicate/empty node id: "+n.id);
  if(n.semantic_id.empty()) fail("missing semantic authority: "+n.id);
  bool supported=false;
  for(const auto& c:caps) if(c.verified && c.op==n.op && c.dtype==n.output_dtype && c.semantic_id==n.semantic_id) { supported=true; break; }
  if(!supported) fail("no verified kernel/semantics: "+n.id);
  for(const auto& in:n.inputs) if(!available.count(in)) fail("unresolved or forward input: "+n.id+"/"+in);
  if(n.output.empty() || !available.insert(n.output).second) fail("duplicate/empty output: "+n.id);
  if(n.output_shape.empty() || n.output_dtype==DType::Unknown) fail("incomplete output descriptor: "+n.id);
  for(auto d:n.output_shape) if(!d) fail("zero output dimension: "+n.id);
  if((n.op==Op::StateRead || n.op==Op::StateWrite) && !state_ids.count(n.state_id)) fail("unknown state: "+n.id);
  if(n.op!=Op::StateRead && n.op!=Op::StateWrite && !n.state_id.empty()) fail("unexpected state binding: "+n.id);
 }
 r.ok=r.errors.empty(); return r;
}
Certificate Validator::compare(const Graph& g,const std::string& ref,const float* actual,const float* expected,size_t count,double atol,double rtol) {
 Certificate c; c.graph_fingerprint=fingerprint(g); c.reference_identity=ref; c.compared_elements=count;
 if(ref.empty() || !actual || !expected || !count || !std::isfinite(atol) || !std::isfinite(rtol) || atol<0 || rtol<0) return c;
 c.passed=true;
 for(size_t i=0;i<count;++i) {
  if(!std::isfinite(actual[i]) || !std::isfinite(expected[i])) { c.passed=false; c.max_abs_error=std::numeric_limits<double>::infinity(); return c; }
  double a=actual[i], b=expected[i], diff=std::abs(a-b);
  c.max_abs_error=std::max(c.max_abs_error,diff);
  c.max_rel_error=std::max(c.max_rel_error,diff/std::max(std::abs(b),1e-30));
  if(diff>atol+rtol*std::abs(b)) c.passed=false;
 }
 return c;
}
std::shared_ptr<const Plan> PlanAuthority::snapshot() const { std::lock_guard<std::mutex> lock(mu_); return active_; }
bool PlanAuthority::activate(Graph graph,Certificate cert,const std::vector<Capability>& caps,std::string& reason) {
 auto r=Validator::validate(graph,caps);
 if(!r.ok) { reason=r.errors.front(); return false; }
 if(!cert.passed || !cert.compared_elements || cert.reference_identity.empty() || cert.graph_fingerprint!=r.fingerprint) { reason="missing or mismatched numerical certificate"; return false; }
 auto candidate=std::make_shared<Plan>(); candidate->graph=std::move(graph); candidate->certificate=std::move(cert);
 { std::lock_guard<std::mutex> lock(mu_); candidate->generation=next_generation_++; active_=std::move(candidate); }
 reason.clear(); return true;
}
}
