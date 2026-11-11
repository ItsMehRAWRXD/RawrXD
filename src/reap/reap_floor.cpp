// REAP structural floor auditor — standalone C++20, no third-party dependencies.
// Reads a tab-separated tensor inventory: name<TAB>type<TAB>bytes<TAB>expert_count<TAB>family
// expert_count=0 for non-expert; >0 for packed expert tensors.
// Does NOT rewrite models or claim model-quality preservation.
#include <algorithm>
#include <charconv>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

struct Tensor { std::string name,type,family; uint64_t bytes=0,experts=0; };
static bool parseU64(const std::string& s,uint64_t& out){ auto r=std::from_chars(s.data(),s.data()+s.size(),out);return r.ec==std::errc{} && r.ptr==s.data()+s.size(); }
static bool add(uint64_t a,uint64_t b,uint64_t& out){if(b>UINT64_MAX-a)return false;out=a+b;return true;}
static bool mul(uint64_t a,uint64_t b,uint64_t& out){if(a && b>UINT64_MAX/a)return false;out=a*b;return true;}
static std::string esc(const std::string& s){std::string o;for(char c:s){if(c=='"'||c=='\\'){o+='\\';o+=c;}else if(c=='\n')o+="\\n";else o+=c;}return o;}
static int fail(const std::string& s){std::cerr<<"ERROR: "<<s<<'\n';return 2;}
int main(int argc,char** argv){
 if(argc<2||argc>4){std::cerr<<"usage: reap-floor <inventory.tsv> [target_gib=30] [active_experts=8]\n";return 2;}
 uint64_t targetGiB=30,active=8;
 if(argc>=3&&(!parseU64(argv[2],targetGiB)||targetGiB>UINT64_MAX/1073741824ULL))return fail("invalid target GiB");
 if(argc>=4&&(!parseU64(argv[3],active)||active==0))return fail("invalid active expert count");
 uint64_t target=targetGiB*1073741824ULL;
 std::ifstream in(argv[1]);if(!in)return fail("cannot open inventory");
 std::vector<Tensor> tensors;std::set<std::string> names;std::string line;size_t lineno=0;
 uint64_t total=0,dense=0,expertTotal=0,oneExpert=0;std::map<std::string,uint64_t> families;
 while(std::getline(in,line)){
  ++lineno;if(line.empty()||line[0]=='#')continue;
  std::istringstream ss(line);std::string cols[5];for(int i=0;i<5;i++)if(!std::getline(ss,cols[i],'\t'))return fail("expected 5 tab-separated columns on line "+std::to_string(lineno));
  std::string extra;if(std::getline(ss,extra,'\t'))return fail("extra column on line "+std::to_string(lineno));
  Tensor t;t.name=cols[0];t.type=cols[1];t.family=cols[4];
  if(t.name.empty()||t.type.empty()||t.family.empty()||!parseU64(cols[2],t.bytes)||!parseU64(cols[3],t.experts)||!names.insert(t.name).second)return fail("invalid or duplicate tensor on line "+std::to_string(lineno));
  if(t.experts && (t.bytes%t.experts))return fail("non-integral packed expert stride for "+t.name);
  uint64_t tmp;if(!add(total,t.bytes,tmp))return fail("total overflow");total=tmp;
  if(!add(families[t.family],t.bytes,tmp))return fail("family overflow");
  families[t.family]=tmp;
  if(t.experts){if(!add(expertTotal,t.bytes,tmp))return fail("expert overflow");expertTotal=tmp;if(!add(oneExpert,t.bytes/t.experts,tmp))return fail("one expert overflow");oneExpert=tmp;}
  else {if(!add(dense,t.bytes,tmp))return fail("dense overflow");dense=tmp;}
  tensors.push_back(t);
 }
 if(tensors.empty()||expertTotal==0)return fail("inventory empty or no expert tensors");
 uint64_t floorBytes=0;if(!add(dense,oneExpert,floorBytes))return fail("floor overflow");
 std::cout<<"{\n  \"schema\": \"reap.floor.audit.v1\",\n  \"input\": \""<<esc(argv[1])<<"\",\n  \"tensor_count\": "<<tensors.size()<<",\n  \"tensor_bytes\": "<<total<<",\n  \"nonexpert_bytes\": "<<dense<<",\n  \"packed_expert_bytes\": "<<expertTotal<<",\n  \"one_expert_slice_bytes\": "<<oneExpert<<",\n  \"one_expert_tensor_floor_bytes\": "<<floorBytes<<",\n  \"target_bytes\": "<<target<<",\n  \"active_experts_per_token\": "<<active<<",\n  \"metadata_and_alignment_overhead_included\": false,\n  \"quality_preservation_certified\": false,\n  \"rewrite_authorized\": false,\n  \"families\": {";
 bool first=true;for(const auto& [family,bytes]:families){if(!first)std::cout<<',';first=false;std::cout<<"\n    \""<<esc(family)<<"\": "<<bytes;}std::cout<<"\n  },\n  \"scenarios\": [";
 const uint64_t counts[]={1,2,4,8,16,32,64};first=true;
 for(uint64_t n:counts){uint64_t selected=0,scenario=0;bool ok=mul(oneExpert,n,selected)&&add(dense,selected,scenario);if(!first)std::cout<<',';first=false;
  std::cout<<"\n    {\"experts_per_layer\": "<<n<<", \"estimated_tensor_bytes\": ";if(ok)std::cout<<scenario;else std::cout<<"null";
  std::cout<<", \"within_target\": "<<(ok&&scenario<=target?"true":"false")<<", \"topk_feasible\": "<<(n>=active?"true":"false")<<"}";
 }
 std::cout<<"\n  ]\n}\n";return 0;
}
