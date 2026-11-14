#include <windows.h>
#include <stdio.h>
#include <stdint.h>
typedef int (*hipInit_t)(unsigned);
typedef int (*hipGetDeviceCount_t)(int*);
typedef int (*hipSetDevice_t)(int);
typedef int (*hipMalloc_t)(void**, size_t);
typedef int (*hipFree_t)(void*);
typedef int (*hipMemcpy_t)(void*, const void*, size_t, int);
typedef int (*hipDeviceSynchronize_t)(void);
static HMODULE load_hip(const char** used) {
  const char* names[] = {"amdhip64.dll","amdhip64_6.dll","hiprt64.dll",0};
  for (int i=0; names[i]; ++i) {
    HMODULE h = LoadLibraryA(names[i]);
    if (h) { *used = names[i]; return h; }
  }
  return 0;
}
int main(void) {
  const char* used = 0;
  HMODULE h = load_hip(&used);
  printf("dll=%s load=%d\n", used?used:"NONE", h!=0);
  if (!h) return 1;
  hipInit_t hipInit=(hipInit_t)GetProcAddress(h,"hipInit");
  hipGetDeviceCount_t hipGetDeviceCount=(hipGetDeviceCount_t)GetProcAddress(h,"hipGetDeviceCount");
  hipSetDevice_t hipSetDevice=(hipSetDevice_t)GetProcAddress(h,"hipSetDevice");
  hipMalloc_t hipMalloc=(hipMalloc_t)GetProcAddress(h,"hipMalloc");
  hipFree_t hipFree=(hipFree_t)GetProcAddress(h,"hipFree");
  hipMemcpy_t hipMemcpy=(hipMemcpy_t)GetProcAddress(h,"hipMemcpy");
  hipDeviceSynchronize_t hipSync=(hipDeviceSynchronize_t)GetProcAddress(h,"hipDeviceSynchronize");
  printf("syms init=%d count=%d set=%d malloc=%d free=%d memcpy=%d sync=%d\n",
    !!hipInit,!!hipGetDeviceCount,!!hipSetDevice,!!hipMalloc,!!hipFree,!!hipMemcpy,!!hipSync);
  if (!hipInit||!hipGetDeviceCount||!hipMalloc||!hipMemcpy||!hipFree||!hipSync) return 2;
  int rc=hipInit(0); printf("hipInit_rc=%d\n", rc); if(rc) return 3;
  int n=-1; rc=hipGetDeviceCount(&n); printf("devcount_rc=%d n=%d\n", rc, n); if(rc||n<1) return 4;
  if (hipSetDevice) { rc=hipSetDevice(0); printf("setDevice0_rc=%d\n", rc); }
  const size_t N=1<<20; const size_t bytes=N*sizeof(float);
  float* host=(float*)VirtualAlloc(0,bytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
  float* host2=(float*)VirtualAlloc(0,bytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
  if(!host||!host2) return 5;
  for (size_t i=0;i<N;i++) host[i]=(float)(i&0xffff);
  void* dev=0; rc=hipMalloc(&dev, bytes); printf("malloc_rc=%d ptr=%p\n", rc, dev); if(rc||!dev) return 6;
  LARGE_INTEGER f,s,e; QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&s);
  rc=hipMemcpy(dev, host, bytes, 1); /* H2D */
  hipSync();
  QueryPerformanceCounter(&e);
  double h2d_ms=(double)(e.QuadPart-s.QuadPart)*1000.0/(double)f.QuadPart;
  printf("h2d_rc=%d ms=%.3f\n", rc, h2d_ms);
  QueryPerformanceCounter(&s);
  rc=hipMemcpy(host2, dev, bytes, 2); /* D2H */
  hipSync();
  QueryPerformanceCounter(&e);
  double d2h_ms=(double)(e.QuadPart-s.QuadPart)*1000.0/(double)f.QuadPart;
  printf("d2h_rc=%d ms=%.3f\n", rc, d2h_ms);
  int mism=0; for (size_t i=0;i<N;i++) if (host[i]!=host2[i]) { mism=1; break; }
  printf("verify_ok=%d\n", mism==0);
  hipFree(dev); VirtualFree(host,0,MEM_RELEASE); VirtualFree(host2,0,MEM_RELEASE);
  FreeLibrary(h);
  printf("HIP_MEMCOPY_BENCH=%s\n", mism==0 && rc==0 ? "PASS":"FAIL");
  return mism ? 7 : 0;
}
