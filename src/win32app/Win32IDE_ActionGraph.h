#pragma once
template <typename... Args> inline bool HasSovereignActionGraphFlag(Args&&...) { return false; }
template <typename... Args> inline int RunSovereignActionGraph(Args&&...) { return 0; }
