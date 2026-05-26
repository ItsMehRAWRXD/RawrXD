#pragma once
template <typename... Args> inline bool HasTextEngineProbeFlag(Args&&...) { return false; }
template <typename... Args> inline int RunTextEngineProbe(Args&&...) { return 0; }
