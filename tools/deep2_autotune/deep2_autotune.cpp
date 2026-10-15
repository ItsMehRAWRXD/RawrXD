#include "deep2_autotune.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <thread>
#include <tuple>
#include <windows.h>

namespace deep2::tune {
namespace {
constexpr unsigned profile_version = 1;
std::string hexhash(const std::string& s) {
  // Stable cache key, NOT a cryptographic model hash. Runtime must supply a real model fingerprint.
  uint64_t h = 14695981039346656037ull;
  for (unsigned char c : s) { h ^= c; h *= 1099511628211ull; }
  std::ostringstream os; os << std::hex << std::setfill('0') << std::setw(16) << h;
  return os.str();
}
std::string key(const Runtime& r, const Hardware& h) {
  return hexhash(r.model_fingerprint() + "|" + r.implementation_fingerprint() + "|" + h.fingerprint);
}
bool good(const Result& r, uint64_t budget) {
  return r.valid && r.parity_ok && r.stable && r.generated_tokens >= 16 &&
         std::isfinite(r.elapsed_seconds) && r.elapsed_seconds > 0 &&
         std::isfinite(r.prefill_tps) && r.prefill_tps > 0 &&
         r.peak_bytes > 0 && r.peak_bytes <= budget &&
         std::isfinite(r.decode_tps()) && r.decode_tps() > 0;
}
std::string fmt_profile(const std::string& k, const Config& c) {
  std::ostringstream o;
  o << profile_version << ' ' << k << ' ' << c.threads << ' ' << c.batch << ' '
    << c.gpu_layers << ' ' << c.context << ' ' << c.kv_bits << '\n';
  return o.str();
}
std::optional<Config> load(const std::string& path, const std::string& expected) {
  std::ifstream f(path, std::ios::binary);
  unsigned v; std::string k; Config c;
  if (!(f >> v >> k >> c.threads >> c.batch >> c.gpu_layers >> c.context >> c.kv_bits)) return {};
  std::string extra; if (f >> extra) return {};
  if (v != profile_version || k != expected || !c.threads || !c.batch || !c.context ||
      (c.kv_bits != 8 && c.kv_bits != 16)) return {};
  return c;
}
bool save(const std::string& path, const std::string& contents) {
  namespace fs = std::filesystem;
  std::error_code ec;
  fs::path p(path);
  if (!p.parent_path().empty()) fs::create_directories(p.parent_path(), ec);
  if (ec) return false;
  fs::path tmp = p; tmp += ".tmp";
  { std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f || !(f << contents)) return false;
    f.flush(); if (!f) return false;
  }
  if (!MoveFileExW(tmp.c_str(), p.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    fs::remove(tmp, ec); return false;
  }
  return true;
}
std::vector<Config> candidates(const Hardware& h) {
  std::vector<Config> out;
  const uint32_t cpu = (h.logical_cpus > 1) ? h.logical_cpus : 1u;
  for (auto threads : {1u, cpu/2, cpu})
    for (auto batch : {1u, 32u, 128u})
      for (auto layers : {0u, 999u})
        for (auto bits : {16u, 8u})
          out.push_back({threads,batch,layers,4096,bits});
  std::sort(out.begin(),out.end(),[](const Config& a,const Config& b){
    return std::tie(a.threads,a.batch,a.gpu_layers,a.context,a.kv_bits) <
           std::tie(b.threads,b.batch,b.gpu_layers,b.context,b.kv_bits);
  });
  out.erase(std::unique(out.begin(),out.end(),[](const Config& a,const Config& b){
    return std::tie(a.threads,a.batch,a.gpu_layers,a.context,a.kv_bits) ==
           std::tie(b.threads,b.batch,b.gpu_layers,b.context,b.kv_bits);
  }),out.end());
  return out;
}
std::optional<Result> measure(Runtime& runtime, const Config& c, uint64_t budget) {
  std::string why;
  if (!runtime.supports(c,why)) return {};
  std::array<Result,3> r;
  for (uint32_t i=0;i<r.size();++i) {
    try { r[i] = runtime.benchmark(c,i); }
    catch (...) { return {}; }
    if (!good(r[i],budget)) return {};
  }
  std::sort(r.begin(),r.end(),[](const Result& a,const Result& b){return a.decode_tps()<b.decode_tps();});
  if (r[2].decode_tps() > r[0].decode_tps()*1.25) return {}; // unstable timing
  return r[1]; // median
}
}
Hardware discover_hardware() {
  Hardware h;
  SYSTEM_INFO si{}; GetNativeSystemInfo(&si);
  h.logical_cpus = std::max(1u,si.dwNumberOfProcessors);
  MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
  if (GlobalMemoryStatusEx(&ms)) h.ram_bytes = ms.ullTotalPhys;
  // Enumerate display adapters without introducing DXGI/ADL dependencies.
  DISPLAY_DEVICEW d{}; d.cb=sizeof(d);
  for (DWORD i=0; EnumDisplayDevicesW(nullptr,i,&d,0);++i) {
    if (d.StateFlags & DISPLAY_DEVICE_MIRRORING_DRIVER) continue;
    std::wstring ws(d.DeviceString);
    std::string name;
    for (wchar_t ch:ws) name += ch < 128 ? char(ch) : '?';
    h.display_adapters.push_back(name);
    d = {}; d.cb=sizeof(d);
  }
  std::ostringstream o; o << "cpu=" << h.logical_cpus << ";ram=" << h.ram_bytes;
  for (const auto& a:h.display_adapters) o << ";display=" << a;
  h.fingerprint = o.str();
  return h;
}
std::optional<Decision> autotune(Runtime& runtime,const Hardware& hw,const std::string& profile_path,
                                  uint64_t budget,bool force,std::string& diagnostic) {
  if (budget == 0 || runtime.model_fingerprint().empty() || runtime.implementation_fingerprint().empty()) {
    diagnostic="Missing memory budget or runtime fingerprints"; return {};
  }
  const auto k=key(runtime,hw);
  if (!force) if (auto cached=load(profile_path,k)) {
    if (auto measured=measure(runtime,*cached,budget)) {
      std::string error;
      if (runtime.activate(*cached,error)) {
        diagnostic="Cached profile revalidated and activated";
        return Decision{*cached,*measured,true};
      }
    }
  }
  std::optional<Decision> best;
  for (const auto& c:candidates(hw)) {
    auto r=measure(runtime,c,budget);
    if (!r) continue;
    if (!best || r->decode_tps()>best->result.decode_tps()) best=Decision{c,*r,false};
  }
  if (!best) {diagnostic="No candidate passed real inference, parity, stability and memory gates";return {};}
  std::string error;
  if (!runtime.activate(best->config,error)) {
    diagnostic="Winning configuration could not activate: "+error;return {};
  }
  if (!save(profile_path,format(k,best->config))) {
    diagnostic="Configuration activated, but profile persistence failed";
    return best;
  }
  diagnostic="Verified configuration activated and saved";
  return best;
}
}
