#include "bs_process.h"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
int bs_process_alive(uint32_t pid){HANDLE h=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,(DWORD)pid);DWORD code=0;if(!h)return 0;if(!GetExitCodeProcess(h,&code)){CloseHandle(h);return 0;}CloseHandle(h);return code==STILL_ACTIVE;}
void bs_sleep_ms(uint32_t ms){Sleep(ms);}
#else
#include <signal.h>
#include <unistd.h>
int bs_process_alive(uint32_t pid){return kill((pid_t)pid,0)==0;}
void bs_sleep_ms(uint32_t ms){usleep((useconds_t)ms*1000u);}
#endif
