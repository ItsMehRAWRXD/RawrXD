// Test sigmoid polynomial approximation
#include <iostream>
#include <cmath>
#include <iomanip>

int main() {
    std::cout << "Testing sigmoid polynomial approximation:" << std::endl;
    std::cout << "P(x) = 0.5 + 0.25*x - 0.0208*x^3 + 0.00206*x^5 - 0.000196*x^7 + 0.000016*x^9" << std::endl;
    std::cout << std::endl;
    
    // Test values
    float test_values[] = {-5.0f, -4.0f, -3.0f, -2.5f, -2.0f, -1.5f, -1.0f, -0.5f, 0.0f, 0.5f, 1.0f, 1.5f, 2.0f, 2.5f, 3.0f, 4.0f, 5.0f};
    
    std::cout << "x\t\tSigmoid(x)\tPolynomial(x)\tError" << std::endl;
    std::cout << "----\t\t----------\t-------------\t-----" << std::endl;
    
    for (float x : test_values) {
        // True sigmoid
        float sigmoid_true = 1.0f / (1.0f + std::exp(-x));
        
        // Polynomial approximation
        float x2 = x * x;
        float x3 = x2 * x;
        float x5 = x3 * x2;
        float x7 = x5 * x2;
        float x9 = x7 * x2;
        
        float polynomial = 0.5f + 0.25f*x - 0.0208f*x3 + 0.00206f*x5 - 0.000196f*x7 + 0.000016f*x9;
        
        // SiLU
        float silu_true = x * sigmoid_true;
        float silu_poly = x * polynomial;
        
        float error = std::abs(sigmoid_true - polynomial);
        
        std::cout << std::fixed << std::setprecision(4) << x << "\t\t" 
                  << std::setprecision(6) << sigmoid_true << "\t" 
                  << polynomial << "\t" 
                  << error << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "Testing SiLU (x * sigmoid(x)):" << std::endl;
    std::cout << "x\t\tSiLU_true\tSiLU_poly\tError" << std::endl;
    std::cout << "----\t\t--------\t---------\t-----" << std::endl;
    
    for (float x : test_values) {
        // True sigmoid
        float sigmoid_true = 1.0f / (1.0f + std::exp(-x));
        
        // Polynomial approximation
        float x2 = x * x;
        float x3 = x2 * x;
        float x5 = x3 * x2;
        float x7 = x5 * x2;
        float x9 = x7 * x2;
        
        float polynomial = 0.5f + 0.25f*x - 0.0208f*x3 + 0.00206f*x5 - 0.000196f*x7 + 0.000016f*x9;
        
        // SiLU
        float silu_true = x * sigmoid_true;
        float silu_poly = x * polynomial;
        
        float error = std::abs(silu_true - silu_poly);
        
        std::cout << std::fixed << std::setprecision(4) << x << "\t\t" 
                  << std::setprecision(6) << silu_true << "\t" 
                  << silu_poly << "\t" 
                  << error << std::endl;
    }
    
    return 0;
}