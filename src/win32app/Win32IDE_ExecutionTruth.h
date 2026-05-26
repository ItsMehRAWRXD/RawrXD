#pragma once
template <typename... Args> inline bool HasExecutionTruthFlag(Args&&...) { return false; }
template <typename... Args> inline int RunExecutionTruth(Args&&...) { return 0; }
