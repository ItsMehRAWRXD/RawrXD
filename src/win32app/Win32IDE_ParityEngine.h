#pragma once
template <typename... Args> inline bool HasParityEngineFlag(Args&&...) { return false; }
template <typename... Args> inline int RunParityEngineProbe(Args&&...) { return 0; }
