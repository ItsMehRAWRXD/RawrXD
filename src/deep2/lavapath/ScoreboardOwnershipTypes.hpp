#pragma once
#include <atomic>
#include <cstdint>
namespace rawrxd::deep2 {
struct LayerEpoch { uint32_t layer=0, generation=0; };
struct LayerEdge { LayerEpoch from{}, to{}; };
enum class IssueOwner:uint8_t { None=0, Scoreboard=1, Sequential=2 };
struct OwnershipDecision { LayerEpoch layer{}; IssueOwner owner=IssueOwner::None; bool runnable=false; };
}
