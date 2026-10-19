#pragma once
#include "KimiCostAuthority.hpp"
namespace Deep2 { namespace kcost {
struct SealPolicy { double minCostAdvantagePct; uint64_t minTokens; };
inline bool Seal(const Comparison&c,const SealPolicy&p){
 return c.comparable&&c.deep2.authority&&c.baseline.authority&&
        c.deep2.tokens>=p.minTokens&&c.baseline.tokens>=p.minTokens&&
        c.costAdvantagePct>=p.minCostAdvantagePct&&c.deep2WinsCost;
}
}} 
