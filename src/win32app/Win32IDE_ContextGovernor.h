#pragma once
template <typename... Args> inline bool HasSovereignContextGovernorFlag(Args&&...) { return false; }
template <typename... Args> inline int RunSovereignContextGovernor(Args&&...) { return 0; }
