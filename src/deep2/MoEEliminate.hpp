// MoEEliminate.hpp — blank never-used MoE via process of elimination
#pragma once
#include <cstdint>
#include <cstdio>
#include <vector>

namespace Deep2 {

bool MoEEliminate_Wanted();
void MoEEliminate_Reset();
void MoEEliminate_NoteAcquire(int layer, int expert);
bool MoEEliminate_WasUsed(int layer, int expert);
uint64_t MoEEliminate_UsedCount();
uint64_t MoEEliminate_AcquireOps();
uint64_t MoEEliminate_PrefetchAllowed();
uint64_t MoEEliminate_PrefetchBlanked();
void MoEEliminate_FilterPrefetch(int layer, std::vector<int>& expertIds);
void MoEEliminate_Emit(FILE* f);

} // namespace Deep2
