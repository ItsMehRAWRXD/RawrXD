#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif
typedef VOID* HPCON;
using FnCreatePseudoConsole = HRESULT(WINAPI*)(COORD, HANDLE, HANDLE, DWORD, HPCON*);
using FnClosePseudoConsole = VOID(WINAPI*)(HPCON);
int main(){
  HMODULE k32=GetModuleHandleW(L"kernel32.dll");
  auto create=(FnCreatePseudoConsole)GetProcAddress(k32,"CreatePseudoConsole");
  auto close=(FnClosePseudoConsole)GetProcAddress(k32,"ClosePseudoConsole");
  printf("API_PRESENT=%d\n", create&&close?1:0);
  if(!create||!close){ printf("RUNTIME=FAIL_CLOSED CreatePseudoConsole_absent\nPROMOTE=0\n"); return 2; }
  SECURITY_ATTRIBUTES sa{sizeof(sa),0,TRUE};
  HANDLE inR,inW,outR,outW;
  if(!CreatePipe(&inR,&inW,&sa,0)||!CreatePipe(&outR,&outW,&sa,0)){
    printf("RUNTIME=FAIL_CLOSED create_pipe_failed\nPROMOTE=0\n"); return 3; }
  SetHandleInformation(inW,HANDLE_FLAG_INHERIT,0);
  SetHandleInformation(outR,HANDLE_FLAG_INHERIT,0);
  COORD sz{80,25}; HPCON hPC=nullptr;
  HRESULT hr=create(sz,inR,outW,0,&hPC);
  printf("CreatePseudoConsole hr=0x%08lX hPC=%p\n",(unsigned long)hr,(void*)hPC);
  if(FAILED(hr)||!hPC){ printf("RUNTIME=FAIL_CLOSED CreatePseudoConsole_failed\nPROMOTE=0\n"); return 4; }
  SIZE_T attrBytes=0; InitializeProcThreadAttributeList(nullptr,1,0,&attrBytes);
  auto* attrs=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,attrBytes);
  BOOL okAttr=attrs && InitializeProcThreadAttributeList(attrs,1,0,&attrBytes)
    && UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,hPC,sizeof(hPC),nullptr,nullptr);
  wchar_t cmd[]=L"cmd.exe /c echo CONPTY_OWNER_SMOKE_OK";
  STARTUPINFOEXW si{}; si.StartupInfo.cb=sizeof(si); si.lpAttributeList=attrs;
  PROCESS_INFORMATION pi{};
  BOOL ok=okAttr && CreateProcessW(nullptr,cmd,nullptr,nullptr,FALSE,EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&si.StartupInfo,&pi);
  if(attrs){ DeleteProcThreadAttributeList(attrs); HeapFree(GetProcessHeap(),0,attrs); }
  CloseHandle(inR); CloseHandle(outW);
  if(!ok){ close(hPC); printf("RUNTIME=FAIL_CLOSED CreateProcessW_failed err=%lu\nPROMOTE=0\n",GetLastError()); return 5; }
  WaitForSingleObject(pi.hProcess,10000);
  char buf[256]; DWORD n=0; ReadFile(outR,buf,sizeof(buf)-1,&n,nullptr); buf[n]=0;
  printf("OUT=%s\n",buf);
  printf("RUNTIME_REACHED=1 OWNER_MIRROR=CreatePseudoConsole_attr_list PRODUCT_OWNER=Win32TerminalManager\n");
  printf("NOTE=API_SMOKE_NE_HWND_PRODUCT_PATH\nPROMOTE=0\n");
  close(hPC); CloseHandle(inW); CloseHandle(outR); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
  return 0;
}
