#include "native_agent_batch.hpp"
#include <algorithm>
#include <fstream>
#include <functional>
#include <iterator>
#include <sstream>
#include <thread>
#include <utility>
namespace RawrXD::NativeBridge {
void AuditLog::record(std::string a, std::string s, std::string d) {
    std::lock_guard<std::mutex> g(mutex_);
    events_.push_back({next_++,std::move(a),std::move(s),std::move(d)});
}
std::vector<AuditEvent> AuditLog::snapshot() const {
    std::lock_guard<std::mutex> g(mutex_); return events_;
}
bool ToolPolicy::allow(std::string n) {
    if(n.empty()) return false;
    std::lock_guard<std::mutex> g(mutex_); denied_.erase(n); return allowed_.insert(std::move(n)).second;
}
bool ToolPolicy::deny(std::string n) {
    if(n.empty()) return false;
    std::lock_guard<std::mutex> g(mutex_); allowed_.erase(n); return denied_.insert(std::move(n)).second;
}
bool ToolPolicy::permitted(const std::string& n) const {
    std::lock_guard<std::mutex> g(mutex_);
    return !denied_.count(n) && allowed_.count(n) != 0;
}
ControlledTools::ControlledTools(const ToolRegistry& t, const ToolPolicy& p, AuditLog& a):tools_(t),policy_(p),audit_(a){}
Result ControlledTools::invoke(const std::string& n,const std::vector<std::string>& a,const std::atomic<bool>& c) const {
    if(!policy_.permitted(n)) { audit_.record("deny",n,"policy"); return {false,{},"tool denied"}; }
    auto r=tools_.execute(n,a,c);
    audit_.record(r.ok?"success":"failure",n,r.ok?"executed":r.error);
    return r;
}
bool Budget::permits(size_t n,size_t bytes) const {return n<=maxTasks && bytes<=maxOutputBytes;}
Result Retry::execute(const std::function<Result()>& fn,unsigned attempts,const std::atomic<bool>& cancel) {
    if(!fn || !attempts) return {false,{},"invalid retry"};
    Result r;
    for(unsigned i=0;i<attempts;++i) {
        if(cancel.load()) return {false,{},"cancelled"};
        try {r=fn();} catch(const std::exception& e){r={false,{},e.what()};}
        catch(...){r={false,{},"unknown exception"};}
        if(r.ok) return r;
    }
    return r;
}
Journal::Journal(std::filesystem::path p):path_(std::move(p)){}
bool Journal::append(const std::string& r,std::string& error) {
    std::lock_guard<std::mutex> g(mutex_);
    if(r.find('\n')!=std::string::npos || r.find('\r')!=std::string::npos) {error="record contains newline";return false;}
    std::ofstream f(path_,std::ios::binary|std::ios::app);
    if(!f || !(f<<r<<'\n') || !f.flush()) {error="journal append failed";return false;}
    return true;
}
std::vector<std::string> Journal::read(std::string& error) const {
    std::lock_guard<std::mutex> g(mutex_);
    std::ifstream f(path_,std::ios::binary);
    if(!f) {error="journal open failed";return {};}
    std::vector<std::string> rows;std::string s;
    while(std::getline(f,s)) rows.push_back(s);
    if(f.bad()) error="journal read failed";
    return rows;
}
void EvidenceLedger::add(std::string id,Result r) {
    std::lock_guard<std::mutex> g(mutex_);entries_.push_back({std::move(id),std::move(r)});
}
std::vector<TaskResult> EvidenceLedger::snapshot() const {
    std::lock_guard<std::mutex> g(mutex_);return entries_;
}
Result DependencyGraph::validate(const std::vector<Task>& tasks) {
    std::set<std::string> ids;
    for(auto& t:tasks) if(t.id.empty()||t.tool.empty()||!ids.insert(t.id).second)
        return {false,{},"empty or duplicate task"};
    for(auto& t:tasks) for(auto& d:t.dependencies)
        if(!ids.count(d)) return {false,{},"missing dependency: "+d};
    std::map<std::string,int> state;
    std::map<std::string,const Task*> index;
    for(auto& t:tasks) index[t.id]=&t;
    std::function<bool(const std::string&)> visit=[&](const std::string& id){
        if(state[id]==1)return false;
        if(state[id]==2)return true;
        state[id]=1;
        for(auto& dep:index.at(id)->dependencies) if(!visit(dep)) return false;
        state[id]=2;return true;
    };
    for(auto& t:tasks) if(!visit(t.id)) return {false,{},"dependency cycle"};
    return {true,"valid",{}};
}
std::vector<std::string> DependencyGraph::order(const std::vector<Task>& tasks,std::string& error) {
    auto v=validate(tasks);if(!v.ok){error=v.error;return {};}
    std::map<std::string,const Task*> index;for(auto& t:tasks)index[t.id]=&t;
    std::set<std::string> visited;std::vector<std::string> order;
    std::function<void(const std::string&)> walk=[&](const std::string& id){
        if(!visited.insert(id).second)return;
        for(auto& dep:index.at(id)->dependencies)walk(dep);
        order.push_back(id);
    };
    for(auto& t:tasks)walk(t.id);
    return order;
}
bool WorkQueue::push(Task t) {
    std::lock_guard<std::mutex> g(mutex_);
    if(t.id.empty()||t.tool.empty()||!ids_.insert(t.id).second)return false;
    tasks_.push_back(std::move(t));return true;
}
std::optional<Task> WorkQueue::pop() {
    std::lock_guard<std::mutex> g(mutex_);
    if(tasks_.empty())return std::nullopt;
    Task t=std::move(tasks_.front());tasks_.pop_front();ids_.erase(t.id);return t;
}
size_t WorkQueue::size() const {std::lock_guard<std::mutex> g(mutex_);return tasks_.size();}
NativeSession::NativeSession(Budget b):budget_(b){}
Result NativeSession::run(const Task& t,const ControlledTools& tools,const std::atomic<bool>& cancel) {
    std::lock_guard<std::mutex> g(mutex_);
    if(!budget_.permits(tasks_+1,0))return {false,{},"task budget exceeded"};
    ++tasks_;
    auto r=tools.invoke(t.tool,t.args,cancel);
    if(r.output.size()>budget_.maxOutputBytes)r={false,{},"output budget exceeded"};
    evidence_.add(t.id,r);return r;
}
static std::optional<std::filesystem::path> pathWithin(const std::filesystem::path& root,const std::string& rel) {
    std::filesystem::path p(rel);
    if(p.empty()||p.is_absolute()||p.has_root_name())return std::nullopt;
    for(auto& part:p)if(part=="..")return std::nullopt;
    std::error_code ec;auto base=std::filesystem::weakly_canonical(root,ec);if(ec)return std::nullopt;
    auto target=std::filesystem::weakly_canonical(base/p,ec);if(ec)return std::nullopt;
    auto b=base.begin(),c=target.begin();
    for(;b!=base.end();++b,++c)if(c==target.end()||*b!=*c)return std::nullopt;
    return target;
}
Result writeFileAtomic(const std::filesystem::path& root,const std::string& rel,const std::string& content) {
    auto p=pathWithin(root,rel);if(!p)return {false,{},"path outside workspace"};
    if(content.size()>16*1024*1024)return {false,{},"write exceeds 16 MiB"};
    std::error_code ec;
    if(!std::filesystem::exists(p->parent_path(),ec))return {false,{},"parent directory missing"};
    // This operation refuses overwrites; no race-free replacement claim is made.
    if(std::filesystem::exists(*p,ec))return {false,{},"destination exists"};
    auto tmp=*p;tmp+=".rawrxd-tmp";
    if(std::filesystem::exists(tmp,ec))return {false,{},"temporary file exists"};
    {std::ofstream f(tmp,std::ios::binary|std::ios::trunc);
     if(!f||!f.write(content.data(),static_cast<std::streamsize>(content.size()))||!f.flush()){
         std::filesystem::remove(tmp,ec);return {false,{},"write failed"};}
    }
    std::filesystem::rename(tmp,*p,ec);
    if(ec){std::filesystem::remove(tmp,ec);return {false,{},"rename failed"};}
    return {true,p->string(),{}};
}
Result compareFile(const std::filesystem::path& root,const std::string& rel,const std::string& expected) {
    auto p=pathWithin(root,rel);if(!p)return {false,{},"path outside workspace"};
    std::ifstream f(*p,std::ios::binary);if(!f)return {false,{},"open failed"};
    std::string got((std::istreambuf_iterator<char>(f)),{});
    if(f.bad())return {false,{},"read failed"};
    return got==expected?Result{true,"equal",{}}:Result{false,{},"content mismatch"};
}
Result searchText(const std::filesystem::path& root,const std::string& rel,const std::string& needle) {
    if(needle.empty())return {false,{},"empty needle"};
    auto p=pathWithin(root,rel);if(!p)return {false,{},"path outside workspace"};
    std::ifstream f(*p,std::ios::binary);if(!f)return {false,{},"open failed"};
    std::ostringstream result;std::string line;size_t row=0,found=0;
    while(std::getline(f,line)){
        ++row;
        if(line.find(needle)!=std::string::npos){result<<row<<':'<<line<<'\n';++found;}
        if(row>1000000||result.tellp()>1048576)return {false,{},"search limit exceeded"};
    }
    if(f.bad())return {false,{},"read failed"};
    return {true,result.str(),{}};
}
Result formatFIM(const std::string& p,const std::string& s,const std::string& mode) {
    if(mode=="fim")return {true,buildFIM(p,s,"<|fim_prefix|>","<|fim_suffix|>","<|fim_middle|>"),{}};
    if(mode=="plain")return {true,p+"\n[INSERT]\n"+s,{}};
    return {false,{},"unknown FIM mode"};
}
Result invokeInference(const Inference& inference,const std::string& prompt,const std::atomic<bool>& cancel) {
    if(cancel.load())return {false,{},"cancelled"};
    if(!inference)return {false,{},"no native inference provider"};
    try{return inference(prompt,cancel);}
    catch(const std::exception& e){return {false,{},e.what()};}
    catch(...){return {false,{},"inference exception"};}
}
}
