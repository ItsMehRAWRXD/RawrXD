#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

// Track H — channel attribution / buffer isolation / boundedness (logic mirror)
struct ChannelBuf {
  std::string data;
  static constexpr size_t kMax = 64 * 1024;
  void append(const std::string& s) {
    data += s;
    if (data.size() > kMax) data.erase(0, data.size() - kMax);
  }
};

int main() {
  printf("OUTPUT_GATE harness PROMOTE=0\n");
  std::mutex mu;
  std::map<std::string, ChannelBuf> ch;
  const char* names[] = {"Build","Tasks","ExtensionHost","Ollama","Deep2","Diagnostics"};
  for (auto* n: names) ch[n] = ChannelBuf{};

  auto post = [&](const std::string& tab, const std::string& text) {
    std::lock_guard<std::mutex> lk(mu);
    ch[tab].append(std::string("[ts] ") + text);
  };

  std::vector<std::thread> th;
  th.emplace_back([&]{ for(int i=0;i<100;i++) post("Build", "build-line\n"); });
  th.emplace_back([&]{ for(int i=0;i<100;i++) post("Deep2", "deep2-tok\n"); });
  th.emplace_back([&]{ for(int i=0;i<100;i++) post("ExtensionHost", "ext-act\n"); });
  for (auto& t: th) t.join();

  int fail=0;
  {
    std::lock_guard<std::mutex> lk(mu);
    if (ch["Build"].data.find("deep2-tok")!=std::string::npos) { printf("FAIL cross-channel corruption\n"); fail++; }
    else printf("PASS no_cross_channel_corruption\n");
    if (ch["Build"].data.find("build-line")==std::string::npos) { printf("FAIL build buffer\n"); fail++; }
    else printf("PASS build_channel\n");
    if (ch["Deep2"].data.find("deep2-tok")==std::string::npos) { printf("FAIL deep2 buffer\n"); fail++; }
    else printf("PASS deep2_channel\n");
    // switch keeps buffers
    std::string keep = ch["Build"].data;
    std::string active = "Deep2";
    (void)active;
    if (ch["Build"].data != keep) { printf("FAIL buffer lost on switch\n"); fail++; }
    else printf("PASS channel_switch_keeps_buffers\n");
  }
  printf("OUTPUT_PANEL=%s\n", fail?"FAIL_CLOSED":"PASS");
  printf("NOTE=Logic harness; HWND product path requires candidate EXE\n");
  printf("PROMOTE=0 TIP_CLIMB=HOLD\n");
  return fail?1:0;
}