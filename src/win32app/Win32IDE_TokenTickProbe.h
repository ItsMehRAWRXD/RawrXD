#pragma once
template <typename... Args> inline bool HasTokenTickFlag(Args&&...) { return false; }
template <typename... Args> inline int RunTokenTickProbe(Args&&...) { return 0; }
