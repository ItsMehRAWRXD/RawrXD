#include <algorithm>
#include <charconv>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>
namespace fs=std::filesystem;
using KVs=std::map<std::string,std::string>;
struct Gate {std::string id,reason; bool pass;};
static std::string quote(const std::string &s){std::string r="\""; for(unsigned char c:s){if(c=='"')r+="\\\"";else if(c=='\\')r+="\\\\";else if(c=='\n')r+="\\n";else if(c=='\r')r+="\\r";else if(c=='\t')r+="\\t";else if(c<32){const char* h="0123456789abcdef";r+="\\u00";r+=h[c>>4];r+=h[c&15];}else r+=char(c);}return r+'"';}
static std::string trim(const std::string &s){auto p=s.find_first_not_of(" \t\r\n");return p==std::string::npos?"":s.substr(p,s.find_last_not_of(" \t\r\n")-p+1);}
static bool read(const fs::path& path,KVs& v,std::string& err){std::ifstream f(path,std::ios::binary); if(!f){err="cannot open evidence";return false;}std::string line;size_t lines=0,total=0;while(std::getline(f,line)){if(++lines>1024||(total+=line.size())>1024*1024||line.size()>8192){err="evidence size limit";return false;}line=trim(line);if(line.empty()||line[0]=='#')continue;auto sep=line.find('=');if(sep==std::string::npos){err="missing = on line "+std::to_string(lines);return false;}auto k=trim(line.substr(0,sep)),val=trim(line.substr(sep+1));if(k.empty()||k.size()>128||!v.emplace(k,val).second){err="invalid/duplicate key on line "+std::to_string(lines);return false;}}if(f.bad()){err="evidence read error";return false;}return true;}
static bool eq(const KVs& v,const std::string &k,const std::string &s){auto it=v.find(k);return it!=v.end()&&it->second==s;}
static bool num(const KVs&v,const std::string &k,double &d){auto it=v.find(k);if(it==v.end()||it->second.empty())return false;try{size_t n;d=std::stod(it->second,&n);return n==it->second.size()&&std::isfinite(d);}catch(...){return false;}}
static bool positive(const KVs&v,const std::string &k){auto it=v.find(k);if(it==v.end()||it->second.empty())return false;unsigned long long x=0;auto r=std::from_chars(it->second.data(),it->second.data()+it->second.size(),x);return r.ec==std::errc{}&&r.ptr==it->second.data()+it->second.size()&&x>0;}
static bool zero(const KVs&v,const std::string &k){return eq(v,k,"0");}
static bool safeRelative(const std::string &s){if(s.empty()||s.size()>240||s.find(':')!=std::string::npos||s.find('\\')!=std::string::npos)return false;fs::path p(s);if(p.is_absolute())return false;for(auto &part:p)if(part==".."||part==".")return false;return true;}
static bool artifact(const fs::path &base,const KVs&v,const std::string &key){auto it=v.find(key);if(it==v.end()||!safeRelative(it->second))return false;std::error_code ec;const auto p=base/it->second;if(fs::is_symlink(p,ec)||!fs::is_regular_file(p,ec))return false;auto size=fs::file_size(p,ec);return !ec&&size>0&&size<=64*1024*1024;}
static std::vector<Gate> eval(const KVs&v,const fs::path&base){std::vector<Gate> g;auto add=[&](const char* id,bool ok,const char* why){g.push_back({id,why,ok});};double tps=0;bool tp=num(v,"decode_tps",tps)&&tps>0;bool generated=eq(v,"generation_completed","PASS")&&positive(v,"generated_tokens")&&artifact(base,v,"generation_log");
add("Q2K_COMPLETE_GENERATION",generated,"completed token generation with nonempty bounded generation log");
add("Q2K_FULL_MODEL_PARITY",eq(v,"full_model_parity","PASS")&&artifact(base,v,"parity_log"),"full-model parity and external log");
add("Q2K_DECODE_TPS",generated&&tp&&artifact(base,v,"timing_log"),"finite positive decode TPS tied to completed generation");
add("Q2K_ACCEPTANCE_150_TPS",generated&&tp&&tps>=150&&artifact(base,v,"timing_log"),"decode TPS >= 150, real generation evidence");
add("GPU_REAL_FORWARD",generated&&positive(v,"gpu_forward_ops")&&positive(v,"gpu_layer_submits")&&zero(v,"strict_gpu_violations")&&artifact(base,v,"gpu_trace"),"nonzero forward/layers, zero violations, trace");
add("GPU_CPU_REFERENCE",eq(v,"gpu_cpu_parity","PASS")&&artifact(base,v,"gpu_cpu_log"),"CPU vs GPU numerical result");
add("GPU_DEVICE_RECOVERY",eq(v,"gpu_recovery","PASS")&&artifact(base,v,"device_recovery_log"),"device loss/recovery exercised");
add("DUAL_GPU_PARITY",eq(v,"dual_gpu_parity","PASS")&&artifact(base,v,"dual_gpu_log"),"real dual GPU parity");
add("WIN32_EDITOR_E2E",eq(v,"editor_save_reopen","PASS")&&artifact(base,v,"editor_log"),"GUI edit save reopen");
add("WIN32_PROBLEMS_NAV",eq(v,"problems_navigation","PASS")&&artifact(base,v,"problems_log"),"error click navigates file and line");
add("WIN32_DEBUGGER_E2E",eq(v,"debugger_step_watch","PASS")&&artifact(base,v,"debugger_log"),"real debugger stepping and watch");
add("WIN32_POWERSHELL_E2E",eq(v,"powershell_cleanup","PASS")&&artifact(base,v,"powershell_log"),"child cleanup and cancellation");
add("WEBVIEW2_EMBED",eq(v,"webview2_embedded","PASS")&&artifact(base,v,"webview_log"),"embedded WebView2 rendered with navigation");
add("GHOSTTEXT_E2E",eq(v,"ghosttext_completion","PASS")&&artifact(base,v,"ghosttext_log"),"visible accept and reject completion");
add("EXTENSION_HOST_E2E",eq(v,"extension_host","PASS")&&artifact(base,v,"extension_log"),"activate and execute extension command");
add("AGENT_EDIT_BUILD_VERIFY",eq(v,"agent_edit_build_verify","PASS")&&artifact(base,v,"agent_log"),"agent file edit build test verify");
add("AGENT_FAILED_TEST_ROLLBACK",eq(v,"agent_rollback","PASS")&&artifact(base,v,"rollback_log"),"failed test causes verified rollback");
add("OLLAMA_DEEP2_CONCURRENT",eq(v,"concurrent_providers","PASS")&&artifact(base,v,"providers_log"),"simultaneous inference with provider provenance");
add("NATIVE_BUILD_RELEASE",eq(v,"native_release","PASS")&&artifact(base,v,"build_log"),"complete native release build");
add("IDE_SOAK",eq(v,"ide_soak","PASS")&&artifact(base,v,"soak_log"),"launch interact and soak receipt");return g;}
static bool publish(const fs::path &out,const std::string& data,std::string&err){std::error_code ec;auto dir=out.parent_path();if(!dir.empty())fs::create_directories(dir,ec);if(ec){err="output directory: "+ec.message();return false;}auto temp=out;temp+=".staging";if(fs::exists(temp,ec)){err="staging exists; refusing overwrite";return false;}{std::ofstream o(temp,std::ios::binary|std::ios::trunc);if(!o){err="cannot stage receipt";return false;}o<<data;o.flush();if(!o){err="cannot flush receipt";o.close();fs::remove(temp,ec);return false;}}if(fs::exists(out,ec)){err="receipt exists; use new output name";fs::remove(temp,ec);return false;}fs::rename(temp,out,ec);if(ec){err="cannot publish: "+ec.message();fs::remove(temp,ec);return false;}return true;}
int main(int argc,char**argv){if(argc!=4||std::string(argv[1])!="evaluate"){std::cerr<<"usage: rawr-runtime-gates evaluate evidence.txt receipt.json\n";return 2;}fs::path in=argv[2],out=argv[3];if(in==out){std::cerr<<"input equals output\n";return 2;}KVs v;std::string err;if(!read(in,v,err)){std::cerr<<err<<'\n';return 2;}auto gates=eval(v,in.parent_path());size_t passed=0;std::string output="{\n  \"schema\": \"RAWRXD_IDE_RUNTIME_014\",\n  \"origin\": "+quote(in.string())+",\n  \"gates\": [\n";for(size_t i=0;i<gates.size();++i){auto &g=gates[i];passed+=g.pass;output+="    {\"id\": "+quote(g.id)+", \"status\": "+quote(g.pass?"PASS":"NOT_CERTIFIED")+", \"requirement\": "+quote(g.reason)+"}"+(i+1<gates.size()?",":"")+"\n";}output+="  ],\n  \"passed\": "+std::to_string(passed)+",\n  \"total\": "+std::to_string(gates.size())+",\n  \"overall\": "+quote(passed==gates.size()?"FULL_PASS":"NOT_CERTIFIED")+"\n}\n";if(!publish(out,output,err)){std::cerr<<err<<'\n';return 2;}std::cout<<passed<<"/"<<gates.size()<<" runtime gates PASS\n";return passed==gates.size()?0:1;}
