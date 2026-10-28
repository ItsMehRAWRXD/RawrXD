#include "GpuPreflight.hpp"
#include <stdio.h>
int main() {
  auto gpus = EnumerateGpuHealth();
  for (const auto& g : gpus) {
    wprintf(L"ENUM name=%s problem=%lu started=%d healthy=%d\n",
            g.friendlyName.c_str(), g.problem, g.started?1:0, g.healthy?1:0);
  }
  fprintf(stderr, "--- preflight (allowCpuOnly=1 so we always continue after report) ---\n");
  bool ok = GpuPreflightCheck(true);
  fprintf(stderr, "GpuPreflightCheck(allowCpuOnly)=%d\n", ok?1:0);
  // Re-enum after
  gpus = EnumerateGpuHealth();
  for (const auto& g : gpus) {
    if (g.friendlyName.find(L"7800") != std::wstring::npos ||
        g.friendlyName.find(L"R9700") != std::wstring::npos)
      wprintf(L"AFTER name=%s problem=%lu started=%d healthy=%d\n",
              g.friendlyName.c_str(), g.problem, g.started?1:0, g.healthy?1:0);
  }
  return 0;
}
