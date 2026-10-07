#include "HardwareCapabilityProbe.hpp"
#include <chrono>
#include <vector>
#include <windows.h>
#include <dxgi1_6.h>
#include <intrin.h>
#pragma comment(lib,"dxgi.lib")
namespace RawrXD::Governance {
namespace {
uint64_t now_ns(){return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();}
bool xsave(){int r[4]{};__cpuidex(r,1,0);return (r[2]&(1<<27))!=0;}
CpuCapabilities cpup(){CpuCapabilities c; SYSTEM_INFO si{};GetSystemInfo(&si);c.logical_threads=si.dwNumberOfProcessors;int r[4]{};__cpuidex(r,0,0);int maxb=r[0];__cpuidex(r,1,0);c.fma=(r[2]&(1<<12))!=0;c.avx=(r[2]&(1<<28))!=0;if(xsave()){auto x=_xgetbv(0);c.os_avx_state=(x&6)==6;c.os_avx512_state=(x&0xE6)==0xE6;}if(maxb>=7){__cpuidex(r,7,0);c.bmi2=(r[1]&(1<<8))!=0;c.avx2=(r[1]&(1<<5))&&c.os_avx_state;c.avx512f=(r[1]&(1<<16))&&c.os_avx512_state;c.avx512bw=(r[1]&(1<<30))&&c.os_avx512_state;c.avx512vnni=(r[2]&(1<<11))&&c.os_avx512_state;}DWORD len=0;GetLogicalProcessorInformationEx(RelationProcessorCore,nullptr,&len);if(len){std::vector<std::byte>b(len);if(GetLogicalProcessorInformationEx(RelationProcessorCore,(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)b.data(),&len)){DWORD off=0;while(off<len){auto*p=(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(b.data()+off);++c.physical_cores;off+=p->Size;}}}return c;}
}
double HardwareSnapshot::ram_headroom()const noexcept{return total_ram_bytes?(double)available_ram_bytes/total_ram_bytes:0.0;}
double HardwareSnapshot::vram_headroom()const noexcept{return total_vram_bytes?(double)free_vram_bytes/total_vram_bytes:0.0;}
bool HardwareSnapshot::materially_changed_from(const HardwareSnapshot&o)const noexcept{return gpu_count!=o.gpu_count||total_vram_bytes!=o.total_vram_bytes||cpu.avx2!=o.cpu.avx2||cpu.avx512f!=o.cpu.avx512f|| (o.total_ram_bytes && ((double)(total_ram_bytes>o.total_ram_bytes?total_ram_bytes-o.total_ram_bytes:o.total_ram_bytes-total_ram_bytes)/o.total_ram_bytes)>.05);}
HardwareSnapshot HardwareCapabilityProbe::probe()const{HardwareSnapshot s;s.timestamp_ns=now_ns();MEMORYSTATUSEX m{sizeof(m)};if(GlobalMemoryStatusEx(&m)){s.total_ram_bytes=m.ullTotalPhys;s.available_ram_bytes=m.ullAvailPhys;s.total_virtual_bytes=m.ullTotalPageFile;s.available_virtual_bytes=m.ullAvailPageFile;}s.cpu=cpup();IDXGIFactory6*f=nullptr;if(SUCCEEDED(CreateDXGIFactory1(IID_PPV_ARGS(&f)))){for(UINT i=0;;++i){IDXGIAdapter4*a=nullptr;if(f->EnumAdapterByGpuPreference(i,DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE,IID_PPV_ARGS(&a))!=S_OK)break;DXGI_ADAPTER_DESC3 d{};if(SUCCEEDED(a->GetDesc3(&d))&&!(d.Flags&DXGI_ADAPTER_FLAG3_SOFTWARE)){GpuInfo g;int n=WideCharToMultiByte(CP_UTF8,0,d.Description,-1,nullptr,0,nullptr,nullptr);if(n>0){g.name.resize(n-1);WideCharToMultiByte(CP_UTF8,0,d.Description,-1,g.name.data(),n,nullptr,nullptr);}g.dedicated_bytes=d.DedicatedVideoMemory;g.shared_bytes=d.SharedSystemMemory;g.vendor_id=d.VendorId;g.device_id=d.DeviceId;g.discrete=g.dedicated_bytes>0;g.backend=GpuBackend::DX12;s.gpus.emplace_back(std::move(g));}a->Release();}f->Release();}s.gpu_count=(uint32_t)s.gpus.size();for(auto&g:s.gpus)s.total_vram_bytes+=g.dedicated_bytes;s.free_vram_bytes=s.total_vram_bytes;return s;}
}
