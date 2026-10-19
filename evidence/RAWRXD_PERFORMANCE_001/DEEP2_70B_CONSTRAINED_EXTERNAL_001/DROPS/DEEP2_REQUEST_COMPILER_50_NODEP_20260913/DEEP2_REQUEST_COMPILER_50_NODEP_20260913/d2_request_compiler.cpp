#include "d2_request_compiler.hpp"
#include <algorithm>
#include <cctype>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace d2rc {

static const char* kMechanisms[50] = {
"Goal Canonicalization",
"Constraint Lifting",
"Requirement Atomization",
"Dependency Compression",
"Transitive-Prerequisite Elimination",
"Critical-Cut Detection",
"Information Bottleneck Search",
"Constraint-Satisfiability Prepass",
"Dominance Pruning",
"Proof-Carrying Nodes",
"Evidence Transitivity",
"Authority Partitioning",
"State Snapshot Hashing",
"Incremental Replanning",
"Failure-Surface Localization",
"Negative-Knowledge Caching",
"Side-Effect Segregation",
"Reversibility Ordering",
"Speculation Budgeting",
"Join-Late Execution",
"Result Normalization",
"Semantic Cache Keys",
"Completion Fixed-Point",
"Minimum-Sufficient Response",
"Complexity Conservation Breaker",
"Subgoal Fusion",
"Dependency Fan-In Hoisting",
"Dependency Fan-Out Sharing",
"Late Binding of Executors",
"Capability Cost Ranking",
"Proof Obligation Minimization",
"Counterexample-First Validation",
"Contradiction Frontier Isolation",
"Monotonic State Advancement",
"Idempotent Action Folding",
"Checkpointed Re-entry",
"Hot-Path Requirement Promotion",
"Cold-Path Deferral",
"Work-Conserving Scheduler",
"Uncertainty-Weighted Priority",
"Cut-Set Retry",
"Failure Memoization",
"Boundary Contract Synthesis",
"Scope Firewalling",
"Progressive Precision",
"Budget-Aware Degradation",
"Output Schema Locking",
"Deterministic Tie-Breaking",
"Plan Hash Sealing",
"Closure Certificate"
};

uint64_t fnv1a64(const void* p, size_t n) {
    const unsigned char* b = static_cast<const unsigned char*>(p);
    uint64_t h = 1469598103934665603ull;
    for (size_t i=0;i<n;i++){ h ^= b[i]; h *= 1099511628211ull; }
    return h;
}
uint64_t fnv1a64(const std::string& s){ return fnv1a64(s.data(), s.size()); }

static std::string trim(const std::string& s) {
    size_t a=0,b=s.size();
    while(a<b && std::isspace((unsigned char)s[a])) ++a;
    while(b>a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a,b-a);
}

std::string canonicalize(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    bool space=false;
    for(char ch: s){
        unsigned char c=(unsigned char)ch;
        if(std::isalnum(c) || ch=='_' || ch=='-' || ch==':' || ch=='/' || ch=='.'){
            if(space && !o.empty()) o.push_back(' ');
            o.push_back((char)std::tolower(c));
            space=false;
        } else if(std::isspace(c) || ch==',' || ch==';' || ch=='|' || ch=='(' || ch==')'){
            space=true;
        }
    }
    return trim(o);
}

std::vector<std::string> split_requirements(const std::string& request) {
    std::vector<std::string> out;
    std::string cur;
    int bracket=0;
    auto flush=[&]{
        std::string t=trim(cur);
        if(!t.empty()) out.push_back(t);
        cur.clear();
    };
    for(size_t i=0;i<request.size();++i){
        char c=request[i];
        if(c=='(' || c=='[' || c=='{') ++bracket;
        if(c==')' || c==']' || c=='}') bracket=std::max(0,bracket-1);
        bool delim = bracket==0 && (c=='\n' || c==';');
        if(delim) flush(); else cur.push_back(c);
    }
    flush();

    // Secondary atomization on explicit conjunction markers only.
    std::vector<std::string> atoms;
    for(const auto& r: out){
        size_t pos=0,last=0;
        bool split=false;
        while((pos=r.find(" && ",last))!=std::string::npos){
            std::string a=trim(r.substr(last,pos-last));
            if(!a.empty()) atoms.push_back(a);
            last=pos+4; split=true;
        }
        if(split){
            std::string a=trim(r.substr(last));
            if(!a.empty()) atoms.push_back(a);
        } else atoms.push_back(r);
    }
    return atoms;
}

static void parse_fields(Node& n) {
    std::istringstream is(n.canonical);
    is >> n.verb;
    std::getline(is,n.object);
    n.object=trim(n.object);
    if(n.verb=="delete" || n.verb=="remove" || n.verb=="overwrite" || n.verb=="drop")
        n.risk=Risk::Destructive;
    else if(n.verb=="write" || n.verb=="edit" || n.verb=="patch" || n.verb=="build" ||
            n.verb=="commit" || n.verb=="push" || n.verb=="run")
        n.risk=Risk::SideEffect;
    else if(n.verb=="test" || n.verb=="verify" || n.verb=="check")
        n.risk=Risk::Reversible;
    else n.risk=Risk::ReadOnly;

    n.completion = "observable:" + n.canonical;
    n.uncertainty = (n.canonical.find("unknown") != std::string::npos ||
                     n.canonical.find("maybe") != std::string::npos ||
                     n.canonical.find("investigate") != std::string::npos) ? 2u : 0u;
}

static void infer_edges(Plan& p) {
    // Deterministic conservative dependency rules:
    // verify/test/check X depends on the nearest earlier build/write/edit/patch/run X.
    // push X depends on earlier commit/build/test touching a shared token.
    // commit X depends on earlier write/edit/patch/build/test touching a shared token.
    auto tokens=[](const std::string& s){
        std::vector<std::string> v; std::istringstream is(s); std::string t;
        while(is>>t) if(t.size()>2) v.push_back(t);
        return v;
    };
    std::vector<std::vector<std::string>> tok(p.nodes.size());
    for(size_t i=0;i<p.nodes.size();++i) tok[i]=tokens(p.nodes[i].canonical);

    auto overlap=[&](size_t a,size_t b){
        size_t n=0;
        for(auto& x:tok[a]) for(auto& y:tok[b]) if(x==y){ ++n; break; }
        return n;
    };

    for(size_t i=0;i<p.nodes.size();++i){
        const auto& vi=p.nodes[i].verb;
        for(size_t j=0;j<i;++j){
            size_t ov=overlap(i,j);
            if(!ov) continue;
            const auto& vj=p.nodes[j].verb;
            bool dep=false;
            if((vi=="verify"||vi=="test"||vi=="check") &&
               (vj=="build"||vj=="write"||vj=="edit"||vj=="patch"||vj=="run")) dep=true;
            if(vi=="commit" && (vj=="write"||vj=="edit"||vj=="patch"||vj=="build"||vj=="test")) dep=true;
            if(vi=="push" && (vj=="commit"||vj=="build"||vj=="test")) dep=true;
            if(dep) p.nodes[i].deps.push_back(p.nodes[j].id);
        }
        std::sort(p.nodes[i].deps.begin(),p.nodes[i].deps.end());
        p.nodes[i].deps.erase(std::unique(p.nodes[i].deps.begin(),p.nodes[i].deps.end()),p.nodes[i].deps.end());
    }
}

static void rebuild_users(Plan& p){
    for(auto& n:p.nodes) n.users.clear();
    std::unordered_map<uint32_t,size_t> ix;
    for(size_t i=0;i<p.nodes.size();++i) ix[p.nodes[i].id]=i;
    for(auto& n:p.nodes) for(uint32_t d:n.deps){
        auto it=ix.find(d); if(it!=ix.end()) p.nodes[it->second].users.push_back(n.id);
    }
}

static void transitive_reduce(Plan& p) {
    std::unordered_map<uint32_t,size_t> ix;
    for(size_t i=0;i<p.nodes.size();++i) ix[p.nodes[i].id]=i;
    auto reachable=[&](uint32_t start,uint32_t target,uint32_t skip_from,uint32_t skip_to){
        std::deque<uint32_t> q; std::unordered_set<uint32_t> seen;
        q.push_back(start); seen.insert(start);
        while(!q.empty()){
            uint32_t cur=q.front(); q.pop_front();
            if(cur==target) return true;
            auto it=ix.find(cur); if(it==ix.end()) continue;
            for(uint32_t d:p.nodes[it->second].deps){
                if(cur==skip_from && d==skip_to) continue;
                if(seen.insert(d).second) q.push_back(d);
            }
        }
        return false;
    };
    for(auto& n:p.nodes){
        std::vector<uint32_t> keep;
        for(uint32_t d:n.deps){
            if(reachable(n.id,d,n.id,d)) ++p.transitive_edges_eliminated;
            else keep.push_back(d);
        }
        n.deps.swap(keep);
    }
}

static void compute_state_hash(Plan& p){
    std::ostringstream os;
    for(auto& n:p.nodes){
        os<<n.id<<'|'<<n.canonical<<'|'<<(int)n.status<<'|';
        for(auto d:n.deps) os<<d<<',';
        os<<';';
    }
    p.state_hash=fnv1a64(os.str());
}

static void compute_ready(Plan& p){
    p.ready.clear(); p.blockers.clear();
    std::unordered_map<uint32_t,Status> st;
    for(auto& n:p.nodes) st[n.id]=n.status;
    for(auto& n:p.nodes){
        if(n.status==Status::Pass || n.status==Status::Skipped) continue;
        bool fail=false, all=true;
        for(auto d:n.deps){
            auto s=st[d];
            if(s==Status::Fail || s==Status::Hold){ fail=true; all=false; break; }
            if(!(s==Status::Pass || s==Status::Skipped)) all=false;
        }
        if(fail) p.blockers.push_back(n.id);
        else if(all) p.ready.push_back(n.id);
    }
    std::stable_sort(p.ready.begin(),p.ready.end(),[&](uint32_t a,uint32_t b){
        auto find=[&](uint32_t id)->const Node*{ for(auto&n:p.nodes) if(n.id==id) return &n; return nullptr; };
        auto A=find(a),B=find(b);
        if(!A||!B) return a<b;
        if(A->risk!=B->risk) return (int)A->risk<(int)B->risk;
        if(A->uncertainty!=B->uncertainty) return A->uncertainty>B->uncertainty;
        if(A->priority!=B->priority) return A->priority>B->priority;
        return A->id<B->id;
    });
}

static void compute_critical_path(Plan& p){
    p.critical_path.clear();
    std::unordered_map<uint32_t,size_t> ix;
    for(size_t i=0;i<p.nodes.size();++i) ix[p.nodes[i].id]=i;
    std::unordered_map<uint32_t,int> memo;
    std::unordered_map<uint32_t,uint32_t> next;
    std::function<int(uint32_t)> depth=[&](uint32_t id)->int{
        auto m=memo.find(id); if(m!=memo.end()) return m->second;
        auto it=ix.find(id); if(it==ix.end()) return 0;
        int best=1; uint32_t bestu=0;
        for(uint32_t u:p.nodes[it->second].users){
            int d=1+depth(u);
            if(d>best){best=d;bestu=u;}
        }
        memo[id]=best; if(bestu) next[id]=bestu; return best;
    };
    int best=0; uint32_t start=0;
    for(auto& n:p.nodes){ int d=depth(n.id); if(d>best){best=d;start=n.id;} }
    for(uint32_t cur=start;cur;){
        p.critical_path.push_back(cur);
        auto it=next.find(cur); if(it==next.end()) break;
        cur=it->second;
    }
}

void recompute(Plan& p){
    rebuild_users(p);
    compute_critical_path(p);
    compute_ready(p);
    compute_state_hash(p);
}

Result compile(const std::string& request, const CompileOptions& opt){
    Result r;
    if(trim(request).empty()){ r.error="empty request"; return r; }
    auto parts=split_requirements(request);
    std::unordered_map<uint64_t,size_t> seen;
    uint32_t id=1;
    for(auto& raw:parts){
        Node n; n.id=id++; n.raw=raw; n.canonical=canonicalize(raw);
        if(n.canonical.empty()) continue;
        n.semantic_hash=fnv1a64(n.canonical);
        parse_fields(n);

        // Mechanisms 22 + 15: semantic keying and failure-surface-friendly atom identity.
        if(opt.deduplicate){
            auto it=seen.find(n.semantic_hash);
            if(it!=seen.end() && r.plan.nodes[it->second].canonical==n.canonical){
                ++r.plan.duplicate_nodes_eliminated;
                continue;
            }
        }
        seen[n.semantic_hash]=r.plan.nodes.size();
        r.plan.nodes.push_back(std::move(n));
    }

    // Mechanisms 8/33: basic contradiction frontier isolation.
    std::unordered_map<std::string,std::set<std::string>> objverbs;
    for(auto& n:r.plan.nodes) if(!n.object.empty()) objverbs[n.object].insert(n.verb);
    for(auto& kv:objverbs){
        auto& s=kv.second;
        if((s.count("delete")||s.count("remove")) && (s.count("preserve")||s.count("keep"))){
            for(auto& n:r.plan.nodes) if(n.object==kv.first) n.uncertainty=std::max(n.uncertainty,3u);
        }
    }

    if(opt.infer_dependencies) infer_edges(r.plan);
    rebuild_users(r.plan);
    if(opt.transitive_reduce) transitive_reduce(r.plan);

    // Mechanisms 9/26/35: exact semantic duplicates are already folded;
    // conservative domination: a 'check' identical target after 'verify' is skipped.
    if(opt.dominance_prune){
        std::unordered_map<std::string,uint32_t> verified;
        for(auto& n:r.plan.nodes){
            if(n.verb=="verify") verified[n.object]=n.id;
            else if(n.verb=="check"){
                auto it=verified.find(n.object);
                if(it!=verified.end()){
                    n.status=Status::Skipped;
                    n.evidence.authority=Authority::Derived;
                    n.evidence.source="dominance-prune";
                    n.evidence.proof="prior verify dominates check";
                    ++r.plan.dominated_nodes_eliminated;
                }
            }
        }
    }

    // Mechanisms 18/37/40: priorities = irreversible-late, uncertain/high-fanout early.
    rebuild_users(r.plan);
    for(auto& n:r.plan.nodes){
        uint32_t fan=(uint32_t)n.users.size();
        n.priority = fan*8u + n.uncertainty*4u + (uint32_t)(3-(int)n.risk);
    }

    recompute(r.plan);
    r.ok=true;
    return r;
}

void mark(Plan& p,uint32_t id,Status st,const Evidence* ev){
    for(auto& n:p.nodes) if(n.id==id){
        n.status=st;
        if(ev) n.evidence=*ev;
        if(n.evidence.state_hash==0) n.evidence.state_hash=p.state_hash;
        break;
    }
    recompute(p);
}

const char* mechanism_name(size_t i){
    return (i>=1 && i<=50)?kMechanisms[i-1]:"";
}
size_t mechanism_count(){ return 50; }

} // namespace d2rc

struct d2rc_plan_handle {
    d2rc::Plan plan;
    std::string error;
};

extern "C" {
d2rc_plan_handle* d2rc_compile(const char* s){
    d2rc_plan_handle* h=new d2rc_plan_handle();
    auto r=d2rc::compile(s?s:"");
    h->plan=std::move(r.plan); h->error=r.error;
    return h;
}
void d2rc_free(d2rc_plan_handle* h){ delete h; }
size_t d2rc_node_count(const d2rc_plan_handle* h){ return h?h->plan.nodes.size():0; }
const char* d2rc_node_canonical(const d2rc_plan_handle* h,size_t i){
    return (h&&i<h->plan.nodes.size())?h->plan.nodes[i].canonical.c_str():"";
}
int d2rc_node_status(const d2rc_plan_handle* h,size_t i){
    return (h&&i<h->plan.nodes.size())?(int)h->plan.nodes[i].status:-1;
}
int d2rc_mark(d2rc_plan_handle* h,uint32_t id,int status){
    if(!h || status<0 || status>5) return 0;
    d2rc::mark(h->plan,id,(d2rc::Status)status,nullptr); return 1;
}
size_t d2rc_ready_count(const d2rc_plan_handle* h){ return h?h->plan.ready.size():0; }
uint32_t d2rc_ready_id(const d2rc_plan_handle* h,size_t i){
    return (h&&i<h->plan.ready.size())?h->plan.ready[i]:0;
}
const char* d2rc_last_error(const d2rc_plan_handle* h){ return h?h->error.c_str():"null handle"; }
size_t d2rc_mechanism_count(){ return d2rc::mechanism_count(); }
const char* d2rc_mechanism_name(size_t i){ return d2rc::mechanism_name(i); }
}
