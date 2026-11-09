#include "http.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib,"ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#endif
namespace {
using Clock=std::chrono::steady_clock;
struct Probe {std::string name,path;bool ok;int status;std::string error;long long elapsed_ms;};
#ifdef _WIN32
using Sock=SOCKET; constexpr Sock invalid=INVALID_SOCKET;
void close_sock(Sock s){closesocket(s);}
#else
using Sock=int; constexpr Sock invalid=-1;
void close_sock(Sock s){close(s);}
#endif
bool get_http(const std::string& host,unsigned port,const std::string& path,int timeout_ms,rawr::HttpResponse& out){
#ifdef _WIN32
  WSADATA w{};if(WSAStartup(MAKEWORD(2,2),&w)!=0){out.error="WSAStartup failed";return false;}
#endif
  Sock s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(s==invalid){out.error="socket failed";
#ifdef _WIN32
WSACleanup();
#endif
return false;}
#ifdef _WIN32
  DWORD tv=static_cast<DWORD>(timeout_ms);setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&tv),sizeof(tv));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&tv),sizeof(tv));
#else
  timeval tv{timeout_ms/1000,(timeout_ms%1000)*1000};setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
#endif
  sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_port=htons(static_cast<unsigned short>(port));
  if(inet_pton(AF_INET,host.c_str(),&addr.sin_addr)!=1){out.error="only numeric IPv4 loopback is supported";close_sock(s);
#ifdef _WIN32
WSACleanup();
#endif
return false;}
  if((ntohl(addr.sin_addr.s_addr)>>24)!=127){out.error="non-loopback destination refused";close_sock(s);
#ifdef _WIN32
WSACleanup();
#endif
return false;}
  if(connect(s,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))!=0){out.error="connect failed";close_sock(s);
#ifdef _WIN32
WSACleanup();
#endif
return false;}
  std::string request="GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nAccept: application/json\r\nConnection: close\r\n\r\n";
  size_t sent=0;bool ok=true;while(sent<request.size()){int n=send(s,request.data()+sent,static_cast<int>(request.size()-sent),0);if(n<=0){ok=false;out.error="send failed";break;}sent+=static_cast<size_t>(n);}
  std::string wire; char buf[8192];auto deadline=Clock::now()+std::chrono::milliseconds(timeout_ms);
  while(ok && Clock::now()<deadline){int n=recv(s,buf,sizeof(buf),0);if(n==0)break;if(n<0){ok=false;out.error="recv failed or timed out";break;}if(wire.size()+static_cast<size_t>(n)>2*1024*1024){ok=false;out.error="response exceeds 2 MiB";break;}wire.append(buf,n);}
  close_sock(s);
#ifdef _WIN32
  WSACleanup();
#endif
  if(!ok)return false;if(Clock::now()>=deadline){out.error="overall deadline exceeded";return false;}return rawr::parse_response(wire,out);
}
void write_json(const std::filesystem::path& dest,const std::vector<Probe>& probes,bool passed){
  std::filesystem::create_directories(dest.parent_path().empty()?std::filesystem::path("."):dest.parent_path());
  auto tmp=dest;tmp+=".staged";{std::ofstream f(tmp,std::ios::binary|std::ios::trunc);if(!f)throw std::runtime_error("cannot open receipt");
  f<<"{\"schema\":\"rawrxd-runtime-015-v1\",\"result\":\""<<(passed?"PASS":"NOT_CERTIFIED")<<"\",\"checks\":[";
  for(size_t i=0;i<probes.size();++i){auto& q=probes[i];if(i)f<<',';f<<"{\"name\":\""<<rawr::json_escape(q.name)<<"\",\"path\":\""<<rawr::json_escape(q.path)<<"\",\"status\":"<<q.status<<",\"elapsed_ms\":"<<q.elapsed_ms<<",\"passed\":"<<(q.ok?"true":"false")<<",\"error\":\""<<rawr::json_escape(q.error)<<"\"}";}
  f<<"]}\n";f.flush();if(!f)throw std::runtime_error("receipt write failed");}
#ifdef _WIN32
  if(!MoveFileExW(tmp.wstring().c_str(),dest.wstring().c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))throw std::runtime_error("receipt publish failed");
#else
  std::filesystem::rename(tmp,dest);
#endif
}
}
int main(int argc,char**argv){if(argc!=5||std::string(argv[1])!="probe"){std::cerr<<"usage: rawr-runtime probe <127.0.0.1> <port> <receipt.json>\n";return 2;}
  const std::string host=argv[2];unsigned port=0;try{auto s=std::string(argv[3]);size_t idx=0;auto x=std::stoul(s,&idx);if(idx!=s.size()||x==0||x>65535)throw std::invalid_argument("port");port=static_cast<unsigned>(x);}catch(...){std::cerr<<"invalid port\n";return 2;}
  std::vector<Probe> results;bool overall=true;for(const auto& spec:std::vector<std::pair<std::string,std::string>>{{"health","/health"},{"models","/v1/models"},{"capabilities","/api/engine/capabilities"}}){rawr::HttpResponse r;auto before=Clock::now();bool transport=get_http(host,port,spec.second,4000,r);auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-before).count();bool pass=transport&&r.status==200&&rawr::looks_like_json(r.body);std::string err=transport?(r.status!=200?"non-200 response":(!rawr::looks_like_json(r.body)?"not JSON-shaped":"")):r.error;results.push_back({spec.first,spec.second,pass,r.status,err,ms});overall &=pass;}
  try{write_json(argv[4],results,overall);}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 2;}
  std::cout<<(overall?"PASS":"NOT_CERTIFIED")<<" "<<(overall?3:0)<<"/3\n";return overall?0:1;
}
