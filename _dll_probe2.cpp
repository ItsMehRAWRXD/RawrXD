#include <windows.h>
#include <stdio.h>
int main(int argc,char** argv){
  if(argc<2){printf("usage\n");return 1;}
  const char* p=argv[1];
  HMODULE h1=LoadLibraryExA(p,nullptr,DONT_RESOLVE_DLL_REFERENCES);
  printf("map_only=%p err=%lu\n",(void*)h1,GetLastError());
  if(h1) FreeLibrary(h1);
  SetLastError(0);
  HMODULE h2=LoadLibraryA(p);
  printf("full_load=%p err=%lu\n",(void*)h2,GetLastError());
  if(h2) FreeLibrary(h2);
  return 0;
}
