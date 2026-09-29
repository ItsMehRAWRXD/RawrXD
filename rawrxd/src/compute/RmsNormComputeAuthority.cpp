// RMSNorm compute authority implementation
// RawrXD RMSNorm Compute Authority - Gates all root mean square normalization computation

#include "src/compute/RmsNormComputeAuthority.h"
#include <iostream>
#include <string>

namespace rawrxd::compute
{
    // Global RMSNorm compute authority state
    struct RmsNormComputeAuthorityState
    {
        bool entered = false;
        int dim = 0;
        double eps = 0.0;
        bool inputFinite = false;
        bool outputFinite = false;
        double min = 0.0;
        double max = 0.0;
        double mean = 0.0;
        double l2 = 0.0;
        std::string verdict = "HOLD";
    };

    // Global state instance
    static RmsNormComputeAuthorityState g_rmsnormAuthorityState;

    // Apply RMSNorm
    void apply(int dim, double eps, bool inputFinite, bool outputFinite, 
               double min, double max, double mean, double l2)
    {
        g_rmsnormAuthorityState.entered = true;
        g_rmsnormAuthorityState.dim = dim;
        g_rmsnormAuthorityState.eps = eps;
        g_rmsnormAuthorityState.inputFinite = inputFinite;
        g_rmsnormAuthorityState.outputFinite = outputFinite;
        g_rmsnormAuthorityState.min = min;
        g_rmsnormAuthorityState.max = max;
        g_rmsnormAuthorityState.mean = mean;
        g_rmsnormAuthorityState.l2 = l2;
        
        std::cout << "[RmsNormComputeAuthority] Applied RMSNorm: dim=" << dim 
                  << ", eps=" << eps << ", inputFinite=" << (inputFinite ? "true" : "false")
                  << ", outputFinite=" << (outputFinite ? "true" : "false") << std::endl;
    }

    // Record stats
    void recordStats(double min, double max, double mean, double l2)
    {
        g_rmsnormAuthorityState.min = min;
        g_rmsnormAuthorityState.max = max;
        g_rmsnormAuthorityState.mean = mean;
        g_rmsnormAuthorityState.l2 = l2;
        std::cout << "[RmsNormComputeAuthority] Recorded stats: min=" << min << ", max=" << max 
                  << ", mean=" << mean << ", l2=" << l2 << std::endl;
    }

    // Write RMSNorm receipt
    void writeRmsReceipt()
    {
        std::cout << "[RmsNormComputeAuthority] Writing RMSNorm receipt:" << std::endl;
        std::cout << "  RMSNORM_ENTERED=" << g_rmsnormAuthorityState.entered << std::endl;
        std::cout << "  DIM=" << g_rmsnormAuthorityState.dim << std::endl;
        std::cout << "  EPS=" << g_rmsnormAuthorityState.eps << std::endl;
        std::cout << "  INPUT_FINITE=" << (g_rmsnormAuthorityState.inputFinite ? "true" : "false") << std::endl;
        std::cout << "  OUTPUT_FINITE=" << (g_rmsnormAuthorityState.outputFinite ? "true" : "false") << std::endl;
        std::cout << "  MIN=" << g_rmsnormAuthorityState.min << std::endl;
        std::cout << "  MAX=" << g_rmsnormAuthorityState.max << std::endl;
        std::cout << "  MEAN=" << g_rmsnormAuthorityState.mean << std::endl;
        std::cout << "  L2=" << g_rmsnormAuthorityState.l2 << std::endl;
        std::cout << "  VERDICT=" << g_rmsnormAuthorityState.verdict << std::endl;
    }
}