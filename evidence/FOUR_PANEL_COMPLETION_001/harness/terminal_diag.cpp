#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif
typedef VOID* HPCON;
using FnCreatePseudoConsole = HRESULT(WINAPI*)(COORD, HANDLE, HANDLE, DWORD, HPCON*);
using FnClosePseudoConsole = VOID(WINAPI*)(HPCON);
int main() {
  auto create=(FnCreatePseudoConsole)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"CreatePseudoConsole");
  auto close=(FnClosePseudoConsole)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ClosePseudoConsole");
  SECURITY_ATTRIBUTES sa{sizeof(sa),0,TRUE};
  HANDLE inR,inW,outR,outW;
  CreatePipe(&inR,&inW,&sa,0); CreatePipe(&outR,&outW,&sa,0);
  SetHandleInformation(inW,HANDLE_FLAG_INHERIT,0); SetHandleInformation(outR,HANDLE_FLAG_INHERIT,0);
  COORD sz{80,25}; HPCON hPC=nullptr;
  HRESULT hr=create(sz,inR,outW,0,&hPC);
  printf("hr=0x%08lX hPC=%p\n",(unsigned long)hr,(void*)hPC);
  SIZE_T attrBytes=0; InitializeProcThreadAttributeList(nullptr,1,0,&attrBytes);
  auto* attrs=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,attrBytes);
  InitializeProcThreadAttributeList(attrs,1,0,&attrBytes);
  UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,hPC,sizeof(hPC),nullptr,nullptr);
  wchar_t cmd[]=L"cmd.exe /c echo DIAG_MARK_99 && ping -n 2 127.0.0.1 >nul";
  STARTUPINFOEXW si{}; si.StartupInfo.cb=sizeof(si); si.lpAttributeList=attrs;
  si.StartupInfo.dwFlags=STARTF_USESHOWWINDOW; si.StartupInfo.wShowWindow=SW_HIDE;
  PROCESS_INFORMATION pi{};
  BOOL ok=CreateProcessW(nullptr,cmd,nullptr,nullptr,FALSE,EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&si.StartupInfo,&pi);
  printf("CreateProcess=%d err=%lu\n",(int)ok, GetLastError());
  DeleteProcThreadAttributeList(attrs); HeapFree(GetProcessHeap(),0,attrs);
  CloseHandle(inR); CloseHandle(outW);
  WaitForSingleObject(pi.hProcess,10000);
  char buf[1024]; DWORD n=0; BOOL rf=ReadFile(outR,buf,sizeof(buf)-1,&n,nullptr);
  buf[n]=0; printf("ReadFile=%d n=%lu err=%lu\n",(int)rf,(unsigned long)n,GetLastError());
  printf("OUT=%s\n",buf);
  close(hPC); CloseHandle(inW); CloseHandle(outR); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
  return (n>0 && strstr(buf,"DIAG_MARK_99"))?0:1;
}