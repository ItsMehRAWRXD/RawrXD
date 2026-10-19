#include "deep2_audit_nodep.h"

extern "C" int d2_ssvk_validate(const D2SsVkOps* ops) {
    return (ops && ops->ctx && ops->load_exact && ops->enqueue && ops->collect && ops->reduce) ? 1 : 0;
}
