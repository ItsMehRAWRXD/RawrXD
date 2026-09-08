#pragma once
#include "../../deep2/lavapath/ProductRuntime.hpp"
namespace rawr::product {

inline void CancelGeneration(product_run::ProductRuntime& rt) {
    rt.CancelGeneration();
}

enum { IDC_PRODUCT_CANCEL = 4010 };

} // namespace rawr::product
