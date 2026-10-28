#pragma once
// RawrXD native tool host foundation. C++20, standard library + Win32 only.
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
// replace_windows_file() below calls ReplaceFileW; include <windows.h> for its
// declaration (NOMINMAX so the min/max macros do not break <algorithm>).
# ifndef NOMINMAX
#  define NOMINMAX
# endif
# include <windows.h>
#endif
namespace rawrxd::tools {
namespace fs=std::filesystem;
enum class Risk { ReadOnly, Write, Execute, Network, External };
struct Request { std::string name; std::map<std::string,std::string> args; };
struct Result { bool ok=false; std::string output; std::string error; };
struct Tool { std::string name, description; Risk risk; std::vector<std::string> required; std::function<Result(const Request&)> invoke; };
using Approval=std::function<bool(const Tool&,const Request&)>;
class Registry {
  std::map<std::string,Tool> tools_; mutable std::mutex mutex_;
public:
  void add(Tool t) { std::lock_guard<std::mutex> l(mutex_); if(!tools_.emplace(t.name,std::move(t)).second) throw std::runtime_error("duplicate tool"); }
  std::vector<std::string> names() const { std::lock_guard<std::mutex> l(mutex_); std::vector<std::string> out; for(auto& p:tools_)out.push_back(p.first); return out; }
  // Look up a tool descriptor by name. Returns a copy; nullptr-equivalent
  // handling is done by the caller via the bool return.
  bool find(const std::string& name, Tool& out) const {
    std::lock_guard<std::mutex> l(mutex_);
    auto it=tools_.find(name);
    if(it==tools_.end()) return false;
    out=it->second;
    return true;
  }
  Result call(const Request& r, const Approval& approve) const {
   Tool t; {std::lock_guard<std::mutex> l(mutex_);auto it=tools_.find(r.name);if(it==tools_.end())return {false,"","unknown tool"};t=it->second;}
   for(auto& k:t.required) if(!r.args.count(k))return {false,"","missing argument: "+k};
   if(t.risk!=Risk::ReadOnly && (!approve || !approve(t,r)))return {false,"","approval required"};
   try{return t.invoke(r);}catch(const std::exception& e){return {false,"",e.what()};}
  }
};
inline std::string arg(const Request& r,const std::string& k){auto it=r.args.find(k);if(it==r.args.end())throw std::runtime_error("missing "+k);return it->second;}
inline std::string optional_arg(const Request& r,const std::string& k,const std::string& fallback){auto it=r.args.find(k);return it==r.args.end()?fallback:it->second;}
inline size_t optional_limit(const Request& r,const std::string& k,size_t fallback,size_t maximum){
 auto it=r.args.find(k); if(it==r.args.end()||it->second.empty()) return fallback;
 try { size_t used=0; unsigned long long value=std::stoull(it->second,&used); if(used!=it->second.size()||value==0) return fallback; return static_cast<size_t>(std::min<unsigned long long>(value,maximum)); }
 catch(...) { return fallback; }
}
inline fs::path canonical_root(const fs::path& p){return fs::weakly_canonical(fs::absolute(p));}
inline std::string trim_path_argument(std::string value){
 size_t first=0,last=value.size();
 while(first<last&&std::isspace(static_cast<unsigned char>(value[first])))++first;
 while(last>first&&std::isspace(static_cast<unsigned char>(value[last-1])))--last;
 return value.substr(first,last-first);
}
#ifdef _WIN32
// Atomic same-volume file replacement through ReplaceFileW: preserves the
// original file's ACLs, attributes and alternate data streams instead of the
// delete+rename that std::filesystem::rename would perform.
// Declared before write_atomic() which calls it; defined once at the bottom.
inline bool replace_windows_file(const fs::path& target,const fs::path& replacement);
#endif
inline fs::path scoped(const fs::path& root,const std::string& rel){
 const std::string clean=trim_path_argument(rel);
 fs::path r=canonical_root(root),p=fs::weakly_canonical(r/fs::path(clean.empty()?".":clean));
 auto a=r.begin(),b=p.begin();for(;a!=r.end()&&b!=p.end()&&*a==*b;++a,++b){} if(a!=r.end())throw std::runtime_error("path outside workspace");return p;
}
inline std::string read_text(const fs::path& p,size_t max_bytes=2*1024*1024){
 if(!fs::is_regular_file(p))throw std::runtime_error("not a file");
 if(fs::file_size(p)>max_bytes)throw std::runtime_error("file exceeds read limit");
 std::ifstream in(p,std::ios::binary);if(!in)throw std::runtime_error("cannot open file");return {std::istreambuf_iterator<char>(in),{}};
}
inline void write_atomic(const fs::path& p,const std::string& content){
 if(!fs::exists(p.parent_path()))throw std::runtime_error("parent directory missing");
 auto tmp=p;tmp+=".rawrxd_tmp";if(fs::exists(tmp))throw std::runtime_error("temporary path occupied");
 try{std::ofstream o(tmp,std::ios::binary|std::ios::trunc);if(!o)throw std::runtime_error("cannot create temp file");o.write(content.data(),static_cast<std::streamsize>(content.size()));o.close();if(!o)throw std::runtime_error("write failed");
#ifdef _WIN32
  if(fs::exists(p)){ // atomic replacement on same volume
   if(!replace_windows_file(p,tmp))throw std::runtime_error("ReplaceFileW failed");
  }else fs::rename(tmp,p);
#else
  fs::rename(tmp,p);
#endif
 }catch(...){std::error_code ec;fs::remove(tmp,ec);throw;}
}
// Cursor-parity aliases: models / prompts that emit Cursor tool names
// resolve to the same native handlers (fail-closed if unregistered).
inline const char* canonicalize_tool_name(const std::string& name){
  if(name=="Read"||name=="read_file") return "readFile";
  if(name=="Grep"||name=="grep"||name=="search_text") return "textSearch";
  if(name=="Glob"||name=="glob"||name=="find_files") return "fileSearch";
  if(name=="StrReplace"||name=="str_replace"||name=="search_replace") return "editFiles";
  if(name=="Write"||name=="write_file") return "writeFile";
  if(name=="Delete"||name=="delete_file") return "deleteFile";
  if(name=="Shell"||name=="run_terminal_cmd"||name=="bash") return "runInTerminal";
  if(name=="LSDir"||name=="list_dir") return "listDirectory";
  return nullptr; // keep original
}

inline void register_workspace_tools(Registry& reg,fs::path root){
 root=canonical_root(root);
 reg.add({"readFile","Read one bounded workspace file by path",Risk::ReadOnly,{"path"},[root](const Request& r)->Result{return {true,read_text(scoped(root,arg(r,"path"))),""};}});
 reg.add({"listDirectory","List immediate children only; bounded output. Prefer fileSearch/textSearch for repository audits and never enumerate the workspace root recursively",Risk::ReadOnly,{"path"},[root](const Request& r)->Result{
   auto p=scoped(root,arg(r,"path")); if(!fs::is_directory(p)) throw std::runtime_error("not directory");
   const size_t limit=optional_limit(r,"maxEntries",128,256); const size_t maxBytes=48*1024;
   std::vector<std::string> entries; std::error_code ec;
   for(auto& e:fs::directory_iterator(p,fs::directory_options::skip_permission_denied,ec)){
     if(ec) break; entries.push_back(std::string(e.is_directory(ec)?"D ":"F ")+e.path().filename().string());
   }
   std::sort(entries.begin(),entries.end()); const bool countTruncated=entries.size()>limit;
   std::ostringstream out; out<<"DIRECTORY="<<arg(r,"path")<<" ENTRIES="<<entries.size()<<" RETURN_LIMIT="<<limit<<" TRUNCATED="<<(countTruncated?"true":"false")<<'\n';
   size_t returned=0; for(const auto& entry:entries){ if(returned>=limit||out.tellp()>=static_cast<std::streamoff>(maxBytes)) break; out<<entry<<'\n'; ++returned; }
   if(returned<entries.size()) out<<"...[directory output truncated; use a narrower path or fileSearch]...\n";
   return {true,out.str(),""};
 }});
 reg.add({"fileSearch","Find paths by filename substring; optional path and maxResults scope the search",Risk::ReadOnly,{"pattern"},[root](const Request& r)->Result{
   std::ostringstream out; auto pattern=arg(r,"pattern"); const auto start=scoped(root,optional_arg(r,"path",".")); const size_t limit=optional_limit(r,"maxResults",100,250); size_t count=0; std::error_code ec;
   if(!fs::is_directory(start,ec)) throw std::runtime_error("search path is not a directory");
   for(fs::recursive_directory_iterator it(start,fs::directory_options::skip_permission_denied,ec),end;it!=end&&count<limit&&!ec;it.increment(ec)){
     if(it.depth()>24){it.disable_recursion_pending();continue;} if(it->path().filename().string().find(pattern)!=std::string::npos){out<<fs::relative(it->path(),root).string()<<'\n';++count;}
   }
   if(count==limit) out<<"...[file search truncated at maxResults]...\n"; return {true,out.str(),""};
 }});
 reg.add({"textSearch","Search bounded text files; optional path and maxResults scope the search",Risk::ReadOnly,{"needle"},[root](const Request& r)->Result{
   std::ostringstream out; auto needle=arg(r,"needle"); if(needle.empty()) throw std::runtime_error("empty needle"); const auto start=scoped(root,optional_arg(r,"path",".")); const size_t limit=optional_limit(r,"maxResults",100,250); size_t matches=0; std::error_code ec;
   if(!fs::is_directory(start,ec)) throw std::runtime_error("search path is not a directory");
   for(fs::recursive_directory_iterator it(start,fs::directory_options::skip_permission_denied,ec),end;it!=end&&matches<limit&&!ec;it.increment(ec)){
     if(it.depth()>24){it.disable_recursion_pending();continue;} if(!it->is_regular_file(ec)||it->file_size(ec)>1024*1024) continue; std::ifstream f(it->path()); std::string line; size_t ln=0;
     while(std::getline(f,line)&&matches<limit){++ln;if(line.find(needle)!=std::string::npos){out<<fs::relative(it->path(),root).string()<<':'<<ln<<':'<<line.substr(0,240)<<'\n';++matches;}}
   }
   if(matches==limit) out<<"...[text search truncated at maxResults]...\n"; return {true,out.str(),""};
 }});
 reg.add({"createDirectory","Create directory inside workspace",Risk::Write,{"path"},[root](const Request& r)->Result{fs::create_directories(scoped(root,arg(r,"path")));return {true,"created",""};}});
 reg.add({"createFile","Create a new file without overwriting",Risk::Write,{"path","content"},[root](const Request& r)->Result{auto p=scoped(root,arg(r,"path"));if(fs::exists(p))throw std::runtime_error("file already exists");write_atomic(p,arg(r,"content"));return {true,"created",""};}});
 reg.add({"writeFile","Write/overwrite a workspace file",Risk::Write,{"path","content"},[root](const Request& r)->Result{auto p=scoped(root,arg(r,"path"));if(!fs::exists(p.parent_path()))fs::create_directories(p.parent_path());write_atomic(p,arg(r,"content"));return {true,"written",""};}});
 reg.add({"editFiles","Replace exact unique text in a file",Risk::Write,{"path","old","new"},[root](const Request& r)->Result{auto p=scoped(root,arg(r,"path"));auto text=read_text(p);auto old=arg(r,"old");if(old.empty())throw std::runtime_error("empty match");auto pos=text.find(old);if(pos==std::string::npos||text.find(old,pos+old.size())!=std::string::npos)throw std::runtime_error("match must occur exactly once");text.replace(pos,old.size(),arg(r,"new"));write_atomic(p,text);return {true,"edited",""};}});
 reg.add({"deleteFile","Delete a workspace file",Risk::Write,{"path"},[root](const Request& r)->Result{auto p=scoped(root,arg(r,"path"));if(!fs::is_regular_file(p))throw std::runtime_error("not a regular file");std::error_code ec;if(!fs::remove(p,ec)||ec)throw std::runtime_error("delete failed");return {true,"deleted",""};}});
 reg.add({"runInTerminal","Run command with workspace as cwd",Risk::Execute,{"command"},[root](const Request& r)->Result{
   auto cmd=arg(r,"command");
   if(cmd.empty())throw std::runtime_error("empty command");
   if(cmd.size()>8192)throw std::runtime_error("command too long");
#ifdef _WIN32
   std::string full=std::string("cmd.exe /d /c cd /d \"")+root.string()+"\" && "+cmd;
   FILE* pipe=_popen(full.c_str(),"r");
#else
   std::string full=std::string("cd \"")+root.string()+"\" && "+cmd;
   FILE* pipe=popen(full.c_str(),"r");
#endif
   if(!pipe)throw std::runtime_error("failed to start process");
   std::string out;char buf[4096];size_t cap=2*1024*1024;
   while(fgets(buf,sizeof(buf),pipe)){out+=buf;if(out.size()>cap){out+="\n...[truncated]\n";break;}}
#ifdef _WIN32
   int ec=_pclose(pipe);
#else
   int ec=pclose(pipe);
#endif
   if(ec!=0)return {false,out,"exit="+std::to_string(ec)};
   return {true,out,""};
 }});

 auto alias=[&](const char* alias_name,const char* canonical){
   Tool t; if(!reg.find(canonical,t)) return;
   t.name=alias_name;
   reg.add(std::move(t));
 };
 alias("Read","readFile");
 alias("Grep","textSearch");
 alias("Glob","fileSearch");
 alias("StrReplace","editFiles");
 alias("Write","writeFile");
 alias("Delete","deleteFile");
 alias("Shell","runInTerminal");
}

#ifdef _WIN32
// Single inline definition of the Windows atomic-replace primitive.
inline bool replace_windows_file(const fs::path& target,const fs::path& replacement){
 return ReplaceFileW(target.c_str(),replacement.c_str(),nullptr,REPLACEFILE_IGNORE_MERGE_ERRORS,nullptr,nullptr)!=0;
}
#endif

} // namespace rawrxd::tools
