#pragma once
#include <vector>
#include <cmath>
#include <cstddef>
#include <limits>
namespace rawrxd::mla {
using Vector = std::vector<float>;
inline bool finite(const Vector& x) { for (float v : x) if (!std::isfinite(v)) return false; return true; }
inline bool matvec(const Vector& matrix, size_t rows, size_t cols, const Vector& input, Vector& output) {
    if (!rows || !cols || rows > SIZE_MAX / cols || matrix.size() != rows * cols || input.size() != cols) return false;
    Vector result(rows);
    for (size_t r = 0; r < rows; ++r) {
        double sum = 0.0;
        for (size_t c = 0; c < cols; ++c) sum += double(matrix[r * cols + c]) * input[c];
        if (!std::isfinite(sum) || std::abs(sum) > std::numeric_limits<float>::max()) return false;
        result[r] = static_cast<float>(sum);
    }
    output.swap(result); return true;
}
inline bool rmsNorm(const Vector& input, const Vector& weight, float epsilon, Vector& output) {
    if (input.empty() || input.size() != weight.size() || !std::isfinite(epsilon) || epsilon <= 0.0f) return false;
    double sum = 0.0;
    for (float v : input) sum += double(v) * v;
    const double inv = 1.0 / std::sqrt(sum / input.size() + epsilon);
    Vector result(input.size());
    for (size_t i = 0; i < input.size(); ++i) result[i] = float(double(input[i]) * inv * weight[i]);
    if (!finite(result)) return false;
    output.swap(result); return true;
}
inline bool absorbKey(const Vector& wk, size_t keyDim, size_t rank, const Vector& query, Vector& output) {
    if (!keyDim || !rank || keyDim > SIZE_MAX / rank || wk.size() != keyDim * rank || query.size() != keyDim) return false;
    Vector result(rank);
    for (size_t r = 0; r < rank; ++r) {
        double sum = 0.0;
        for (size_t k = 0; k < keyDim; ++k) sum += double(wk[k * rank + r]) * query[k];
        if (!std::isfinite(sum) || std::abs(sum) > std::numeric_limits<float>::max()) return false;
        result[r] = float(sum);
    }
    output.swap(result); return true;
}
inline bool expandValue(const Vector& wv, size_t valueDim, size_t rank, const Vector& latent, Vector& output) {
    return matvec(wv, valueDim, rank, latent, output);
}
}