#pragma once
template <typename... Args> inline bool HasGGUFManifoldFlag(Args&&...) { return false; }
template <typename... Args> inline int RunGGUFManifoldProbe(Args&&...) { return 0; }
