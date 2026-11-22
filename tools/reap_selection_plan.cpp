// Native candidate planner. Consumes measured scorer TSV plus producer receipt.
// Group geometry is caller-supplied; this is not checkpoint provenance or parity.
#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using U = uint64_t;
void require(bool ok, const char* why) { if (!ok) throw std::runtime_error(why); }
U integer(const std::string& s) {
    U n=0; auto r=std::from_chars(s.data(),s.data()+s.size(),n);
    require(!s.empty() && r.ec==std::errc{} && r.ptr==s.data()+s.size(),"invalid integer"); return n;
}
U add(U a,U b) { require(b<=UINT64_MAX-a,"count overflow"); return a+b; }
U mul(U a,U b) { require(!a || b<=UINT64_MAX/a,"count overflow"); return a*b; }
double real(const std::string& s) {
    size_t p=0;double x=std::stod(s,&p);
    require(p==s.size() && std::isfinite(x) && x>=0,"invalid score");return x;
}
std::vector<std::string> split(std::string line) {
    if(!line.empty() && line.back()=='\r')line.pop_back();
    std::vector<std::string> fields;size_t p=0;
    for(;;){auto i=line.find('\t',p);fields.push_back(line.substr(p,i==std::string::npos?i:i-p));if(i==std::string::npos)return fields;p=i+1;}
}
struct Receipt { U routes=0, experts=0, top=0; std::string hash; std::set<U> layers; };
Receipt readReceipt(const char* path) {
    std::ifstream in(path);require(bool(in),"receipt unavailable");
    std::map<std::string,std::string> fields;Receipt r;std::string line;
    while(std::getline(in,line)){
        auto f=split(line);require(f.size()==2,"bad receipt row");
        if(f[0]=="expected_layer")require(r.layers.insert(integer(f[1])).second,"duplicate layer");
        else require(fields.emplace(f[0],f[1]).second,"duplicate receipt field");
    }
    require(!in.bad() && fields.size()==8,"incomplete receipt");
    r.routes=integer(fields.at("route_records"));r.experts=integer(fields.at("expert_count"));r.top=integer(fields.at("top_k"));
    r.hash=fields.at("first_shard_sha256");
    require(r.hash.size()==64 && r.hash.find_first_not_of("0123456789abcdefABCDEF")==std::string::npos,"invalid first-shard hash");
    require(fields.at("layer_filter")=="-1" && fields.at("rewrite_authorized")=="0","full unapproved capture required");
    require(r.routes && r.experts && r.experts<=1000000 && r.top && r.top<=r.experts && !r.layers.empty(),"invalid topology");
    require(integer(fields.at("shared_records"))==r.routes && integer(fields.at("routed_records"))==mul(r.routes,r.top),"receipt count mismatch");
    require(*r.layers.rbegin()<UINT32_MAX,"invalid layer index");return r;
}
struct Score { U id, count; double mean; };
using Scores=std::map<U,std::vector<Score>>;
Scores readScores(const char* path,const Receipt& r) {
    std::ifstream in(path);require(bool(in),"scorer TSV unavailable");std::string line;
    require(bool(std::getline(in,line)) && split(line)==std::vector<std::string>{"layer","expert","routes","weighted_norm_sum","mean_weighted_norm"},"wrong scorer schema");
    Scores result;std::set<std::pair<U,U>> seen;U total=0;
    while(std::getline(in,line)){
        auto f=split(line);require(f.size()==5,"bad score row");
        U layer=integer(f[0]),id=integer(f[1]),count=integer(f[2]);double sum=real(f[3]),mean=real(f[4]);
        require(r.layers.count(layer) && id<r.experts && count && seen.emplace(layer,id).second,"invalid or duplicate measured expert");
        const double expected=sum/static_cast<double>(count);
        require(std::abs(expected-mean)<=1e-12*std::max(expected,mean),"inconsistent score mean");
        total=add(total,count);result[layer].push_back({id,count,expected});
    }
    require(!in.bad() && result.size()==r.layers.size() && total==mul(r.routes,r.top),"incomplete score coverage");
    for(const auto& row:result){U n=0;for(auto s:row.second)n=add(n,s.count);require(n%r.top==0,"incomplete layer route count");for(auto s:row.second)require(s.count<=n/r.top,"expert count exceeds layer routes");}
    return result;
}
using Plan=std::map<U,std::vector<U>>;
Plan choose(const Receipt& r,const Scores& scores,U keep,U groups,U used) {
    require(keep>=r.top && keep<=r.experts && groups && groups<=r.experts && used && used<=groups,"invalid retention/group geometry");
    require(r.experts%groups==0 && keep%groups==0 && mul(used,keep/groups)>=r.top,"group capacity cannot satisfy original top-k");
    const U oldWidth=r.experts/groups,newWidth=keep/groups;Plan plan;
    for(const auto& row:scores){
        std::map<U,std::vector<Score>> byGroup;for(auto s:row.second)byGroup[s.id/oldWidth].push_back(s);
        auto& selected=plan[row.first];
        for(U g=0;g<groups;++g){
            auto& bank=byGroup[g];require(bank.size()>=newWidth,"insufficient measured experts in group");
            std::sort(bank.begin(),bank.end(),[](auto a,auto b){return a.mean==b.mean?a.id<b.id:a.mean>b.mean;});
            for(U i=0;i<newWidth;++i)selected.push_back(bank[static_cast<size_t>(i)].id);
        }
        // Preserve contiguous original group identity in the new physical bank.
        std::sort(selected.begin(),selected.end());
    }
    return plan;
}
}
int main(int argc,char** argv){
    try {
        require(argc==6,"usage: reap_selection_plan RECEIPT.tsv SCORES.tsv RETAIN GROUP_COUNT GROUPS_USED");
        const auto r=readReceipt(argv[1]);const auto scores=readScores(argv[2],r);
        const U keep=integer(argv[3]),groups=integer(argv[4]),used=integer(argv[5]);const auto plan=choose(r,scores,keep,groups,used);
        std::cout<<"{\n  \"schema\": \"RAWRXD_REAP_EXPERT_SELECTION_001\",\n  \"rewrite_authorized\": false,\n  \"reference_parity_pass\": false,\n  \"experimental_offline\": false,\n  \"first_shard_sha256\": \""<<r.hash<<"\",\n  \"source_experts\": "<<r.experts<<",\n  \"retained_experts\": "<<keep<<",\n  \"top_k\": "<<r.top<<",\n  \"candidate_group_count\": "<<groups<<",\n  \"candidate_groups_used\": "<<used<<",\n  \"layers\": [\n";
        bool firstLayer=true;for(const auto& row:plan){if(!firstLayer)std::cout<<",\n";firstLayer=false;std::cout<<"    {\"layer\": "<<row.first<<", \"selected\": [";bool first=true;for(auto id:row.second){if(!first)std::cout<<", ";first=false;std::cout<<"{\"expert\": "<<id<<"}";}std::cout<<"]}";}
        std::cout<<"\n  ]\n}\n";
        std::cerr<<"CANDIDATE_PLAN=PASS REWRITE_AUTHORIZED=0 GROUP_GEOMETRY_ATTESTED=0\n";return std::cout.good()?0:2;
    }catch(const std::exception& e){std::cerr<<"INVALID_PLAN: "<<e.what()<<'\n';return 2;}
}
