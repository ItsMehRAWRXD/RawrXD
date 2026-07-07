// ============================================================================
// silu_accuracy_comparison_test.cpp - Compare Taylor vs Exp2-based SiLU
// ============================================================================
// This test compares the accuracy of two SiLU implementations:
//   1. Taylor polynomial (current implementation)
//   2. Exp2-based (using FAST_EXP2 macro)
//
// Expected accuracy:
//   - Taylor: Max error < 2.6e-6 (claimed), but measured 0.229
//   - Exp2: Max error < 1e-5 (target)
// ============================================================================

#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>
#include <limits>

// Reference implementation (ground truth)
float reference_silu(float x) {
    // SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
    return x / (1.0f + std::exp(-x));
}

// Taylor polynomial approximation (current implementation)
// P(x) = 0.5 + 0.25*x - 0.0208*x^3 + 0.00206*x^5 - 0.000196*x^7 + 0.000016*x^9
float taylor_sigmoid(float x) {
    float x2 = x * x;
    float x3 = x2 * x;
    float x5 = x3 * x2;
    float x7 = x5 * x2;
    float x9 = x7 * x2;
    
    return 0.5f + 0.25f * x - 0.0208f * x3 + 0.00206f * x5 - 0.000196f * x7 + 0.000016f * x9;
}

float taylor_silu(float x) {
    // 3-region dispatch
    if (x < -2.0f) {
        return 0.0f;  // sigmoid ≈ 0
    } else if (x > 2.0f) {
        return x;     // sigmoid ≈ 1
    } else {
        return x * taylor_sigmoid(x);
    }
}

// Exp2-based approximation (new implementation)
// sigmoid(x) = 1 / (1 + exp(-x))
// exp(-x) = 2^(-x * log2(e))
float exp2_approx(float x) {
    // FAST_EXP2 approximation (degree-6 polynomial)
    // This is a simplified version for testing
    // The actual MASM implementation uses a degree-6 polynomial
    
    // Range reduction: x = floor(x) + frac(x)
    float floor_x = std::floor(x);
    float frac_x = x - floor_x;
    
    // Polynomial approximation for 2^frac on [0, 1)
    // P(frac) = 1.0 + frac * (p1 + frac * (p2 + frac * (p3 + frac * (p4 + frac * (p5 + frac * p6)))))
    // Degree-6 polynomial coefficients (ultra-high accuracy < 1e-5)
    const float p6 = 0.00015506f;
    const float p5 = 0.00133335f;
    const float p4 = 0.00961813f;
    const float p3 = 0.05550411f;
    const float p2 = 0.24022650f;
    const float p1 = 0.69314718f;
    
    float p = p6 * frac_x + p5;
    p = p * frac_x + p4;
    p = p * frac_x + p3;
    p = p * frac_x + p2;
    p = p * frac_x + p1;
    p = p * frac_x + 1.0f;
    
    // Combine: 2^x = 2^floor * P(frac)
    // Use IEEE 754 bit manipulation for 2^floor
    int exp = (int)floor_x + 127;  // Add bias
    float scale;
    *(int*)&scale = exp << 23;     // Shift into exponent field
    
    return p * scale;
}

float exp2_based_sigmoid(float x) {
    float neg_x = -x;
    float exp_neg_x = exp2_approx(neg_x * 1.44269504f);  // Multiply by log2(e)
    return 1.0f / (1.0f + exp_neg_x);
}

float exp2_based_silu(float x) {
    return x * exp2_based_sigmoid(x);
}

// Test function
void test_accuracy(const char* name, float (*silu_func)(float)) {
    std::cout << "\n" << name << ":\n";
    std::cout << std::string(80, '=') << "\n";
    
    // Test range: -10 to 10
    const float x_min = -10.0f;
    const float x_max = 10.0f;
    const int num_points = 10001;
    const float step = (x_max - x_min) / (num_points - 1);
    
    float max_error = 0.0f;
    float max_error_x = 0.0f;
    float sum_error = 0.0f;
    int count = 0;
    
    for (int i = 0; i < num_points; ++i) {
        float x = x_min + i * step;
        float ref = reference_silu(x);
        float approx = silu_func(x);
        float error = std::abs(ref - approx);
        
        sum_error += error;
        count++;
        
        if (error > max_error) {
            max_error = error;
            max_error_x = x;
        }
    }
    
    float avg_error = sum_error / count;
    
    std::cout << "Max Error:     " << std::scientific << std::setprecision(6) << max_error 
              << " at x = " << std::fixed << std::setprecision(4) << max_error_x << "\n";
    std::cout << "Avg Error:     " << std::scientific << std::setprecision(6) << avg_error << "\n";
    std::cout << "Test Range:    [" << x_min << ", " << x_max << "]\n";
    std::cout << "Test Points:   " << num_points << "\n";
    
    // Check if accuracy meets target
    if (max_error < 1e-5f) {
        std::cout << "Status:        ✅ PASSED (max error < 1e-5)\n";
    } else if (max_error < 1e-4f) {
        std::cout << "Status:        ⚠️  WARNING (max error < 1e-4 but > 1e-5)\n";
    } else {
        std::cout << "Status:        ❌ FAILED (max error > 1e-4)\n";
    }
}

// Test specific regions
void test_regions(float (*silu_func)(float)) {
    std::cout << "\nRegion Analysis:\n";
    std::cout << std::string(80, '-') << "\n";
    
    struct Region {
        const char* name;
        float x_min, x_max;
    };
    
    Region regions[] = {
        {"Region A (x < -2)", -10.0f, -2.0f},
        {"Region B (x > 2)", 2.0f, 10.0f},
        {"Region C (-2 ≤ x ≤ 2)", -2.0f, 2.0f}
    };
    
    for (const auto& region : regions) {
        float max_error = 0.0f;
        float max_error_x = 0.0f;
        
        for (float x = region.x_min; x <= region.x_max; x += 0.01f) {
            float ref = reference_silu(x);
            float approx = silu_func(x);
            float error = std::abs(ref - approx);
            
            if (error > max_error) {
                max_error = error;
                max_error_x = x;
            }
        }
        
        std::cout << region.name << ": max error = " << std::scientific << std::setprecision(6) 
                  << max_error << " at x = " << std::fixed << std::setprecision(4) << max_error_x << "\n";
    }
}

int main() {
    std::cout << "SiLU Accuracy Comparison Test\n";
    std::cout << std::string(80, '=') << "\n";
    
    // Test Taylor polynomial (current implementation)
    test_accuracy("Taylor Polynomial (Current)", taylor_silu);
    test_regions(taylor_silu);
    
    // Test Exp2-based (new implementation)
    test_accuracy("Exp2-Based (New)", exp2_based_silu);
    test_regions(exp2_based_silu);
    
    // Test reference implementation
    test_accuracy("Reference (Ground Truth)", reference_silu);
    
    std::cout << "\n" << std::string(80, '=') << "\n";
    std::cout << "Test Complete\n";
    
    return 0;
}