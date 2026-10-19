#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dxgi1_6.h>
#include <cstdio>
#pragma comment(lib,"dxgi.lib")
int main(){
  IDXGIFactory1* f=nullptr;
  if(FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1),(void**)&f))) return 1;
  IDXGIAdapter1* a=nullptr;
  for(UINT i=0; f->EnumAdapters1(i,&a)!=DXGI_ERROR_NOT_FOUND; ++i){
    DXGI_ADAPTER_DESC1 d{}; a->GetDesc1(&d);
    char name[128]{}; WideCharToMultiByte(CP_UTF8,0,d.Description,-1,name,128,0,0);
    printf("ADAPTER[%u] %s ven=%04X dev=%04X flags=0x%X vram=%llu\n", i,name,d.VendorId,d.DeviceId,d.Flags,(unsigned long long)d.DedicatedVideoMemory);
    IDXGIOutput* o=nullptr;
    for(UINT j=0; a->EnumOutputs(j,&o)!=DXGI_ERROR_NOT_FOUND; ++j){
      DXGI_OUTPUT_DESC od{}; o->GetDesc(&od);
      char on[64]{}; WideCharToMultiByte(CP_UTF8,0,od.DeviceName,-1,on,64,0,0);
      printf("  OUTPUT[%u] %s attached=%d desktop=(%ld,%ld)-(%ld,%ld)\n", j,on,(int)od.AttachedToDesktop,
        od.DesktopCoordinates.left,od.DesktopCoordinates.top,od.DesktopCoordinates.right,od.DesktopCoordinates.bottom);
      o->Release();
    }
    a->Release(); a=nullptr;
  }
  f->Release();
  return 0;
}