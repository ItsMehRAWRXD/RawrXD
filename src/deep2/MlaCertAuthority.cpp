// MlaCertAuthority.cpp — single TU for MLA-CERT-001 witnesses (ODR-safe)
#include "MlaCertAuthority.hpp"

namespace Deep2 {
namespace MlaCertAuthority {

Witness& W() {
    static Witness w;
    return w;
}

} // namespace MlaCertAuthority
} // namespace Deep2
