#pragma once
/* OPEN = meta indexed && storage reachable && working set acquirable. ≤99.
 * Bodies live in ProductOpenStreamable.cpp / _Emit.cpp — single TU beats
 * stale inline COMDATs (tip 6754616E OPEN_SEH after SESSION_EXIT). */
#include "../Deep2Engine.h"
#include <cstdio>

namespace Deep2 {
namespace product_open {

struct Facts {
    int meta_indexed = 0;
    int storage_reachable = 0;
    int working_set_acquirable = 0;
    int acquire_live = 0;
    int mmap_bound = 0;
    int file_backing = 0;
    int tensor_count = 0;
    int open_pass = 0;
};

int AcquireWorkingSet(Deep2Engine& e, const ModelWeights& mw);
Facts Evaluate(Deep2Engine& e, const char* path);
void Emit(FILE* fp, const Facts& f);
bool StreamableOk(Deep2Engine& e, const char* path, FILE* fp);

} /* namespace product_open */
} /* namespace Deep2 */
