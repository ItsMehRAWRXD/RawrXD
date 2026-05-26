#pragma once
template <typename... Args> inline bool HasTBALinkGraphFlag(Args&&...) { return false; }
template <typename... Args> inline int RunTBALinkGraph(Args&&...) { return 0; }
