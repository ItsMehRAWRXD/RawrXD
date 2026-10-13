#include "native_agent_batch_16_30.hpp"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <system_error>
#include <utility>
namespace RawrXD::NativeBridge {
namespace fs=std::filesystem;
static std::optional<fs::path> confined(const fs::path& root,const std::string& rel) {
    fs::path p(rel);
    if(p.is_absolute()||p.has_root_name())return std::nullopt;
    for(const auto& c:p)if(c=="..")return std::nullopt;
    std::error_code ec;
    auto base=fs::weakly_canonical(root,ec);if(ec||!fs::is_directory(base))return std::nullopt;
    auto dest=fs::weakly_canonical(base/p,ec);if(ec)return std::nullopt;
    auto b=base.begin(),d=dest.begin();
    for(;b!=base.end();++b,++d)if(d==dest.end()||*b!=*d)return std::nullopt;
    return dest;
}
static Result loadText(const fs::path& path,size_t max) {
    std::error_code ec;
    if(!fs::is_regular_file(path,ec))return {false,{},"not a regular file"};
    auto n=fs::file_size(path,ec);
    if(ec||n>max)return {false,{},"read size limit exceeded"};
    std::ifstream f(path,std::ios::binary);
    if(!f)return {false,{},"open failed"};
    std::string data(static_cast<size_t>(n),'\0');
    if(n&&!f.read(data.data(),static_cast<std::streamsize>(n)))return {false,{},"short read"};
    return {true,std::move(data),{}};
}
Result readBounded(const fs::path& root,const std::string& rel,size_t limit) {
    auto p=confined(root,rel);return p?loadText(*p,limit):Result{false,{},"path outside workspace"};
}
Result listDirectory(const fs::path& root,const std::string& rel,size_t limit) {
    auto p=confined(root,rel);if(!p)return {false,{},"path outside workspace"};
    std::error_code ec;if(!fs::is_directory(*p,ec))return {false,{},"not directory"};
    std::vector<std::string> entries;
    for(fs::directory_iterator it(*p,ec),end;!ec&&it!=end;it.increment(ec)){
        if(entries.size()>=limit)return {false,{},"directory limit exceeded"};
        entries.push_back(it->path().filename().string());
    }
    if(ec)return {false,{},"directory iteration failed"};
    std::sort(entries.begin(),entries.end());
    std::ostringstream o;for(const auto& x:entries)o<<x<<'\n';
    return {true,o.str(),{}};
}
static Result rewrite(const fs::path& root,const std::string& rel,const std::string& content) {
    auto p=confined(root,rel);if(!p)return {false,{},"path outside workspace"};
    if(content.size()>16*1024*1024)return {false,{},"write limit exceeded"};
    std::error_code ec;
    if(!fs::is_regular_file(*p,ec)||fs::is_symlink(*p,ec))return {false,{},"not regular file"};
    // Preserve original on failed replacement; do not claim race-free behavior.
    auto temp=*p;temp+=".rawrxd-next";
    auto backup=*p;backup+=".rawrxd-backup";
    if(fs::exists(temp,ec)||fs::exists(backup,ec))return {false,{},"temporary path occupied"};
    {std::ofstream f(temp,std::ios::binary|std::ios::trunc);
     if(!f||!f.write(content.data(),static_cast<std::streamsize>(content.size()))||!f.flush()){
         fs::remove(temp,ec);return {false,{},"temporary write failed"};}
    }
    fs::rename(*p,backup,ec);
    if(ec){fs::remove(temp,ec);return {false,{},"backup rename failed"};}
    fs::rename(temp,*p,ec);
    if(ec){
        std::error_code restore;
        fs::rename(backup,*p,restore);
        fs::remove(temp,restore);
        return {false,{},restore?"replacement and rollback failed":"replacement failed; original restored"};
    }
    fs::remove(backup,ec);
    return ec?Result{false,{},"replacement succeeded; backup removal failed"}:Result{true,"updated",{}};
}
Result replaceExact(const fs::path& root,const std::string& rel,const std::string& before,const std::string& after) {
    if(before.empty())return {false,{},"empty match forbidden"};
    auto r=readBounded(root,rel,16*1024*1024);if(!r.ok)return r;
    auto pos=r.output.find(before);
    if(pos==std::string::npos)return {false,{},"match not found"};
    if(r.output.find(before,pos+before.size())!=std::string::npos)return {false,{},"ambiguous multiple matches"};
    r.output.replace(pos,before.size(),after);
    return rewrite(root,rel,r.output);
}
static std::vector<std::string> linesOf(const std::string& text) {
    std::vector<std::string> lines;std::istringstream in(text);std::string s;
    while(std::getline(in,s))lines.push_back(s);
    return lines;
}
Result insertLine(const fs::path& root,const std::string& rel,size_t lineNumber,const std::string& line) {
    if(line.find('\n')!=std::string::npos||line.find('\r')!=std::string::npos)return {false,{},"multiline insertion rejected"};
    auto r=readBounded(root,rel,16*1024*1024);if(!r.ok)return r;
    auto lines=linesOf(r.output);
    if(lineNumber==0||lineNumber>lines.size()+1)return {false,{},"line out of range"};
    lines.insert(lines.begin()+static_cast<std::ptrdiff_t>(lineNumber-1),line);
    std::string data;for(const auto& x:lines)data+=x+"\n";
    return rewrite(root,rel,data);
}
Result eraseLine(const fs::path& root,const std::string& rel,size_t lineNumber) {
    auto r=readBounded(root,rel,16*1024*1024);if(!r.ok)return r;
    auto lines=linesOf(r.output);
    if(lineNumber==0||lineNumber>lines.size())return {false,{},"line out of range"};
    lines.erase(lines.begin()+static_cast<std::ptrdiff_t>(lineNumber-1));
    std::string data;for(const auto& x:lines)data+=x+"\n";
    return rewrite(root,rel,data);
}
Result diffLines(const std::string& before,const std::string& after,size_t maxLines) {
    auto a=linesOf(before),b=linesOf(after);
    if(a.size()>maxLines||b.size()>maxLines)return {false,{},"diff line limit exceeded"};
    std::ostringstream out;size_t i=0,j=0;
    while(i<a.size()||j<b.size()){
        if(i<a.size()&&j<b.size()&&a[i]==b[j]){++i;++j;continue;}
        if(i<a.size()&&(j==b.size()||(i+1<a.size()&&a[i+1]==b[j]))){out<<"-"<<a[i++]<<"\n";continue;}
        if(j<b.size()&&(i==a.size()||(j+1<b.size()&&a[i]==b[j+1]))){out<<"+"<<b[j++]<<"\n";continue;}
        if(i<a.size())out<<"-"<<a[i++]<<"\n";
        if(j<b.size())out<<"+"<<b[j++]<<"\n";
    }
    return {true,out.str(),{}};
}
std::string fnv1a64(const std::string& data) {
    std::uint64_t hash=14695981039346656037ULL;
    for(unsigned char c:data){hash^=c;hash*=1099511628211ULL;}
    std::ostringstream o;o<<std::hex<<std::setfill('0')<<std::setw(16)<<hash;return o.str();
}
Result fileFingerprint(const fs::path& root,const std::string& rel,size_t limit) {
    auto r=readBounded(root,rel,limit);if(!r.ok)return r;
    return {true,fnv1a64(r.output),{}};
}
std::optional<FileInfo> statFile(const fs::path& root,const std::string& rel) {
    auto p=confined(root,rel);if(!p)return std::nullopt;
    std::error_code ec;bool dir=fs::is_directory(*p,ec);
    if(ec||(!dir&&!fs::is_regular_file(*p,ec)))return std::nullopt;
    std::uintmax_t size=dir?0:fs::file_size(*p,ec);
    if(ec)return std::nullopt;
    return FileInfo{rel,size,dir};
}
Result scanWorkspace(const fs::path& root,const std::string& suffix,size_t limit) {
    auto p=confined(root,".");if(!p)return {false,{},"invalid root"};
    std::vector<std::string> found;std::error_code ec;
    fs::recursive_directory_iterator it(*p,fs::directory_options::skip_permission_denied,ec),end;
    for(;!ec&&it!=end;it.increment(ec)){
        if(it.depth()>32){it.disable_recursion_pending();continue;}
        if(it->is_symlink(ec)){if(it->is_directory(ec))it.disable_recursion_pending();continue;}
        if(!it->is_regular_file(ec))continue;
        auto path=it->path().lexically_relative(*p).generic_string();
        if(suffix.empty()||(path.size()>=suffix.size()&&path.compare(path.size()-suffix.size(),suffix.size(),suffix)==0)){
            if(found.size()>=limit)return {false,{},"scan limit exceeded"};
            found.push_back(path);
        }
    }
    if(ec)return {false,{},"scan failed"};
    std::sort(found.begin(),found.end());
    std::ostringstream o;for(const auto& s:found)o<<s<<'\n';
    return {true,o.str(),{}};
}
Result TaskTracker::load(const std::vector<Task>& tasks) {
    auto valid=DependencyGraph::validate(tasks);if(!valid.ok)return valid;
    tasks_.clear();for(const auto& t:tasks)tasks_.emplace(t.id,ScheduleItem{t});
    return {true,"loaded",{}};
}
std::vector<Task> TaskTracker::ready() const {
    std::vector<Task> out;
    for(const auto& [id,item]:tasks_) {
        if(item.status!=ScheduleItem::Status::Pending)continue;
        bool ok=true;
        for(const auto& dep:item.task.dependencies) {
            auto it=tasks_.find(dep);
            if(it==tasks_.end()||it->second.status!=ScheduleItem::Status::Succeeded){ok=false;break;}
        }
        if(ok)out.push_back(item.task);
    }
    return out;
}
bool TaskTracker::start(const std::string& id) {
    auto it=tasks_.find(id);if(it==tasks_.end()||it->second.status!=ScheduleItem::Status::Pending)return false;
    for(const auto& dep:it->second.task.dependencies)
        if(tasks_.at(dep).status!=ScheduleItem::Status::Succeeded)return false;
    it->second.status=ScheduleItem::Status::Running;return true;
}
bool TaskTracker::finish(const std::string& id,bool success) {
    auto it=tasks_.find(id);if(it==tasks_.end()||it->second.status!=ScheduleItem::Status::Running)return false;
    it->second.status=success?ScheduleItem::Status::Succeeded:ScheduleItem::Status::Failed;
    if(!success) {
        bool changed;
        do {
            changed=false;
            for(auto& [name,item]:tasks_)if(item.status==ScheduleItem::Status::Pending)
                for(const auto& dep:item.task.dependencies)
                    if(tasks_.at(dep).status==ScheduleItem::Status::Failed||
                       tasks_.at(dep).status==ScheduleItem::Status::Skipped){
                        item.status=ScheduleItem::Status::Skipped;changed=true;break;
                    }
        }while(changed);
    }
    return true;
}
std::map<std::string,ScheduleItem::Status> TaskTracker::statuses() const {
    std::map<std::string,ScheduleItem::Status> s;
    for(const auto& [id,item]:tasks_)s[id]=item.status;
    return s;
}
bool TaskTracker::complete() const {
    for(const auto& [id,item]:tasks_)
        if(item.status==ScheduleItem::Status::Pending||item.status==ScheduleItem::Status::Running)return false;
    return true;
}
Result validateWorkspacePath(const fs::path& root,const std::string& rel) {
    auto p=confined(root,rel);
    return p?Result{true,p->string(),{}}:Result{false,{},"path outside workspace"};
}
Result registerWorkspaceTools(ToolRegistry& registry,const fs::path& root) {
    if(!confined(root,"."))return {false,{},"invalid workspace"};
    auto a=registry.registerTool("workspace.read",[root](const auto& args,const auto& cancel)->Result{
        if(cancel.load())return {false,{},"cancelled"};
        if(args.size()!=1)return {false,{},"expected relative path"};
        return readBounded(root,args[0],1024*1024);
    });
    auto b=registry.registerTool("workspace.list",[root](const auto& args,const auto& cancel)->Result{
        if(cancel.load())return {false,{},"cancelled"};
        if(args.size()!=1)return {false,{},"expected relative directory"};
        return listDirectory(root,args[0],10000);
    });
    auto c=registry.registerTool("workspace.search",[root](const auto& args,const auto& cancel)->Result{
        if(cancel.load())return {false,{},"cancelled"};
        if(args.size()!=2)return {false,{},"expected path and search text"};
        return searchText(root,args[0],args[1]);
    });
    return a&&b&&c?Result{true,"registered",{}}
                 :Result{false,{},"one or more tool names already registered"};
}
}
