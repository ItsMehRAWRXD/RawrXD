#include "ExpertAuthority.hpp"
#include <algorithm>
#include <charconv>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <cctype>
namespace deep2 {
namespace {
uint64_t add(uint64_t a,uint64_t b){if(b>std::numeric_limits<uint64_t>::max()-a)throw std::overflow_error("byte sum overflow");return a+b;}
uint64_t number(const std::string& s){uint64_t v=0;auto r=std::from_chars(s.data(),s.data()+s.size(),v);if(r.ec!=std::errc{}||r.ptr!=s.data()+s.size())throw std::runtime_error("invalid integer: "+s);return v;}
std::string quote(const std::string& s){std::string o="\"";for(unsigned char c:s){if(c=='"'||c=='\\'){o+='\\';o+=char(c);}else if(c=='\n')o+="\\n";else if(c<32)throw std::runtime_error("invalid control character");else o+=char(c);}return o+'"';}
std::vector<std::string> split(const std::string& s,char sep){std::vector<std::string> out;size_t p=0;while(true){auto q=s.find(sep,p);out.push_back(s.substr(p,q==std::string::npos?q:q-p));if(q==std::string::npos)break;p=q+1;}return out;}
}
std::vector<TensorRecord> load_tsv(const std::string& path){std::ifstream f(path);if(!f)throw std::runtime_error("cannot open manifest");std::vector<TensorRecord> out;std::set<std::string> names;std::string line;size_t ln=0;while(std::getline(f,line)){++ln;if(!line.empty()&&line.back()=='\r')line.pop_back();if(line.empty()||line[0]=='#')continue;auto c=split(line,'\t');if(c.size()!=6)throw std::runtime_error("expected 6 TSV columns at line "+std::to_string(ln));if(c[0].empty()||c[1].empty()||!names.insert(c[0]).second)throw std::runtime_error("empty or duplicate tensor name at line "+std::to_string(ln));if(c[4]!="0"&&c[4]!="1")throw std::runtime_error("invalid shape flag");if(c[5]!="0"&&c[5]!="1")throw std::runtime_error("invalid name flag");out.push_back({c[0],c[1],number(c[2]),number(c[3]),c[4]=="1",c[5]=="1"});}return out;}
ExpertReport analyze(const std::vector<TensorRecord>& ts,uint64_t declared_total,uint64_t declared_experts){ExpertReport r;std::set<std::string> seen;for(const auto& t:ts){if(!seen.insert(t.name).second)throw std::runtime_error("duplicate tensor name");if(t.dtype.empty()||t.bytes==0)throw std::runtime_error("empty dtype or zero bytes");r.total_bytes=add(r.total_bytes,t.bytes);r.dtype_bytes[t.dtype]=add(r.dtype_bytes[t.dtype],t.bytes);++r.dtype_counts[t.dtype];bool shape=t.shape_candidate || (declared_experts>0&&t.dim0==declared_experts);bool name=t.name_candidate;if(shape){++r.shape_count;r.shape_bytes=add(r.shape_bytes,t.bytes);}if(name){++r.name_count;r.name_bytes=add(r.name_bytes,t.bytes);}if(shape&&name){++r.intersection_count;r.intersection_bytes=add(r.intersection_bytes,t.bytes);}if(shape||name){++r.union_count;r.union_bytes=add(r.union_bytes,t.bytes);}if(shape!=name)r.conflicts.push_back(t.name);}
uint64_t best=0;for(const auto& p:r.dtype_bytes)if(p.second>best){best=p.second;r.dominant_dtype=p.first;}r.complete=(r.total_bytes==declared_total);if(!r.complete)r.conflicts.push_back("INCOMPLETE_HISTOGRAM: tensor bytes "+std::to_string(r.total_bytes)+" != declared "+std::to_string(declared_total));if(r.shape_count!=r.name_count||r.intersection_count!=r.shape_count)r.conflicts.push_back("EXPERT_CLASSIFICATION_DISAGREEMENT");return r;}
std::string to_json(const ExpertReport& r){std::ostringstream s;s<<"{\n  \"complete\": "<<(r.complete?"true":"false")<<",\n  \"total_bytes\": "<<r.total_bytes<<",\n  \"expert_union_bytes\": "<<r.union_bytes<<",\n  \"expert_union_count\": "<<r.union_count<<",\n  \"shape_count\": "<<r.shape_count<<",\n  \"name_count\": "<<r.name_count<<",\n  \"intersection_count\": "<<r.intersection_count<<",\n  \"intersection_bytes\": "<<r.intersection_bytes<<",\n  \"dominant_actual_dtype\": "<<quote(r.dominant_dtype)<<",\n  \"dtype_bytes\": {";bool first=true;for(auto& p:r.dtype_bytes){if(!first)s<<",";first=false;s<<"\n    "<<quote(p.first)<<": "<<p.second;}s<<"\n  },\n  \"conflicts\": [";first=true;for(auto& x:r.conflicts){if(!first)s<<",";first=false;s<<"\n    "<<quote(x);}s<<"\n  ]\n}\n";return s.str();}
}
