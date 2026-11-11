// ============================================================================
// MlaCertAuthority.cpp — Single Witness instance for MLA certification.
// ============================================================================

#include "MlaCertAuthority.hpp"

namespace Deep2 {
namespace MlaCertAuthority {

Witness& W() {
    static Witness w;
    return w;
}

} // namespace MlaCertAuthority
} // namespace Deep2
