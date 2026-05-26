#pragma once
template <typename... Args> inline bool HasKVApertureProbeFlag(Args&&...) { return false; }
template <typename... Args> inline int RunKVApertureProbe(Args&&...) { return 0; }
