#pragma once
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <filesystem>
#include <string>
#include <vector>
#include <stdexcept>
// tool_core.hpp owns the single inline definition of replace_windows_file so
// that every translation unit including it agrees on one symbol. Including it
// first here keeps that definition visible to this header's own helpers.
#include "tool_core.hpp"
namespace rawrxd::tools {
struct ProcessResult { DWORD exit_code; std::string output; bool timed_out; };
inline ProcessResult run_process(const std::wstring& command,const std::filesystem::path& cwd,DWORD timeout_ms=120000,size_t max_output=1024*1024){
 SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE rd=nullptr,wr=nullptr;
 if(!CreatePipe(&rd,&wr,&sa,0))throw std::runtime_error("CreatePipe failed");
 SetHandleInformation(rd,HANDLE_FLAG_INHERIT,0);
 STARTUPINFOW si{};si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;si.hStdOutput=wr;si.hStdError=wr;si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
 PROCESS_INFORMATION pi{};std::wstring mutable_cmd=command;
 BOOL ok=CreateProcessW(nullptr,mutable_cmd.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|CREATE_NEW_PROCESS_GROUP,nullptr,cwd.c_str(),&si,&pi);
 CloseHandle(wr);if(!ok){CloseHandle(rd);throw std::runtime_error("CreateProcessW failed");}
 std::string output;bool timed_out=false;DWORD code=0;auto start=GetTickCount64();
 for(;;){DWORD available=0;if(!PeekNamedPipe(rd,nullptr,0,nullptr,&available,nullptr))break;
  if(available){char buf[4096];DWORD got=0;if(!ReadFile(rd,buf,(DWORD)std::min<size_t>(sizeof(buf),available),&got,nullptr))break;if(output.size()<max_output)output.append(buf,std::min<size_t>(got,max_output-output.size()));}
  DWORD state=WaitForSingleObject(pi.hProcess,10);if(state==WAIT_OBJECT_0){while(PeekNamedPipe(rd,nullptr,0,nullptr,&available,nullptr)&&available){char buf[4096];DWORD got=0;if(!ReadFile(rd,buf,(DWORD)std::min<size_t>(sizeof(buf),available),&got,nullptr))break;if(output.size()<max_output)output.append(buf,std::min<size_t>(got,max_output-output.size()));}break;}
  if(GetTickCount64()-start>timeout_ms){timed_out=true;TerminateProcess(pi.hProcess,124);WaitForSingleObject(pi.hProcess,INFINITE);break;}
 }
 GetExitCodeProcess(pi.hProcess,&code);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);CloseHandle(rd);return {code,output,timed_out};
}
}
#endif
