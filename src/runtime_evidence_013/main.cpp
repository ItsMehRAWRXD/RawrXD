#include <algorithm>
#include <cmath>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
namespace fs=std::filesystem;
struct Gate {std::string id, state, evidence;};
static std::string json(const std::string& s){std::string o="\"";for(unsigned char c:s){switch(c){case '"':o+="\\\"";break;case '\\':o+="\\\\";break;case '\n':o+="\\n";break;case '\r':o+="\\r";break;case '\t':o+="\\t";break;default:if(c<32){const char*h="0123456789abcdef";o+="\\u00";o+=h[c>>4];o+=h[c&15];}else o+=char(c);}}return o+"\"";}
static bool number(std::string_view s,double& v){try{size_t n=0;v=std::stod(std::string(s),&n);return n==s.size()&&std::isfinite(v);}catch(...){return false;}}
static std::string trim(std::string s){auto a=s.find_first_not_of(" \t\r\n");if(a==std::string::npos)return "";auto b=s.find_last_not_of(" \t\r\n");return s.substr(a,b-a+1);}
static bool load(const fs::path& path,std::map<std::string,std::string>& vals,std::string& error){std::ifstream f(path);if(!f){error="unable to open input";return false;}std::string line;size_t lineno=0;while(std::getline(f,line)){++lineno;if(line.size()>4096){error="line too long";return false;}line=trim(line);if(line.empty()||line[0]=='#')continue;auto p=line.find('=');if(p==std::string::npos||p==0){error="malformed line "+std::to_string(lineno);return false;}std::string k=trim(line.substr(0,p)),v=trim(line.substr(p+1));if(k.empty()||!vals.emplace(k,v).second){error="duplicate or empty key: "+k;return false;}}return true;}
static bool positiveInt(const std::map<std::string,std::string>&v,const std::string&k){auto it=v.find(k);if(it==v.end())return false;unsigned long long x=0;auto r=std::from_chars(it->second.data(),it->second.data()+it->second.size(),x);return r.ec==std::errc{}&&r.ptr==it->second.data()+it->second.size()&&x>0;}
static bool zeroInt(const std::map<std::string,std::string>&v,const std::string&k){auto it=v.find(k);return it!=v.end()&&it->second=="0";}
static bool yes(const std::map<std::string,std::string>&v,const std::string&k){auto it=v.find(k);return it!=v.end()&&it->second=="PASS";}
static std::vector<Gate> evaluate(const std::map<std::string,std::string>&v){std::vector<Gate> g;auto add=[&](std::string id,bool ok,std::string ev){g.push_back({id,ok?"PASS":"NOT_CERTIFIED",std::move(ev)});};
add("Q2K_SHADER_COMPILE",yes(v,"shader_compile"),"shader_compile=PASS");
add("Q2K_REAL_WEIGHT_PARITY",yes(v,"real_weight_parity"),"real_weight_parity=PASS");
add("Q2K_FFN_FINITE",yes(v,"ffn_up_finite")&&yes(v,"ffn_act_finite"),"ffn_up_finite=PASS; ffn_act_finite=PASS");
add("Q2K_GENERATION",positiveInt(v,"generated_tokens")&&yes(v,"generation_completed"),"generated_tokens>0; generation_completed=PASS");
add("Q2K_FULL_MODEL_PARITY",yes(v,"full_model_parity"),"full_model_parity=PASS");
double tps=0;auto it=v.find("decode_tps");add("Q2K_MEASURED_TPS",it!=v.end()&&number(it->second,tps)&&tps>0&&positiveInt(v,"generated_tokens"),"finite decode_tps>0; generated_tokens>0");
add("GPU_FORWARD",positiveInt(v,"gpu_forward_ops")&&positiveInt(v,"gpu_layer_submits")&&zeroInt(v,"strict_gpu_violations"),"gpu_forward_ops>0; gpu_layer_submits>0; strict_gpu_violations=0");
add("WIN32_BUILD",yes(v,"win32_build"),"win32_build=PASS");
add("WIN32_LAUNCH",yes(v,"win32_launch"),"win32_launch=PASS");
add("WIN32_GUI_EDIT",yes(v,"gui_edit_save_reopen"),"gui_edit_save_reopen=PASS");
add("WIN32_DEBUGGER",yes(v,"debugger_step_watch"),"debugger_step_watch=PASS");
add("WIN32_POWERSHELL",yes(v,"powershell_lifecycle"),"powershell_lifecycle=PASS");
add("IDE_AGENT_E2E",yes(v,"agent_edit_build_test_rollback"),"agent_edit_build_test_rollback=PASS");
add("IDE_EXTENSIONS",yes(v,"extension_host_e2e"),"extension_host_e2e=PASS");
add("IDE_DUAL_PROVIDER",yes(v,"ollama_deep2_concurrent"),"ollama_deep2_concurrent=PASS");
add("IDE_SIGNING",yes(v,"sign_verify_deploy"),"sign_verify_deploy=PASS");return g;}
int main(int argc,char**argv){if(argc!=4||std::string(argv[1])!="evaluate"){std::cerr<<"usage: rawr-evidence evaluate measurements.txt receipt.json\n";return 2;}std::map<std::string,std::string> v;std::string error;if(!load(argv[2],v,error)){std::cerr<<error<<'\n';return 2;}auto g=evaluate(v);const fs::path out=argv[3];if(out.has_parent_path())fs::create_directories(out.parent_path());auto temp=out;temp+=".tmp";std::ofstream o(temp,std::ios::binary|std::ios::trunc);if(!o){std::cerr<<"cannot write receipt\n";return 2;}size_t passed=0;o<<"{\n  \"schema\": \"RAWRXD_RUNTIME_EVIDENCE_013\",\n  \"source\": "<<json(argv[2])<<",\n  \"gates\": [\n";for(size_t i=0;i<g.size();++i){const auto&x=g[i];passed+=x.state=="PASS";o<<"    {\"id\": "<<json(x.id)<<", \"status\": "<<json(x.state)<<", \"requirement\": "<<json(x.evidence)<<"}"<<(i+1<g.size()?",":"")<<'\n';}o<<"  ],\n  \"passed\": "<<passed<<",\n  \"total\": "<<g.size()<<",\n  \"overall\": "<<json(passed==g.size()?"FULL_PASS":"NOT_CERTIFIED")<<"\n}\n";o.close();if(!o){fs::remove(temp);return 2;}std::error_code ec;fs::rename(temp,out,ec);if(ec){fs::remove(out,ec);ec.clear();fs::rename(temp,out,ec);if(ec){std::cerr<<"publish failed: "<<ec.message()<<'\n';return 2;}}std::cout<<passed<<"/"<<g.size()<<" gates PASS\n";return passed==g.size()?0:1;}
