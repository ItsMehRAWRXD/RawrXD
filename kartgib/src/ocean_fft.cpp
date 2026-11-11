#include "ocean_field.hpp"
#include <cmath>
#include <utility>
#include <vector>

void ifft1d(Cx* data, int n) {
    for (int i = 1, j = 0; i < n; ++i) {
        int bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) std::swap(data[i], data[j]);
    }
    for (int len = 2; len <= n; len <<= 1) {
        float ang = 6.28318530718f / static_cast<float>(len);
        float wlr = std::cos(ang), wli = std::sin(ang);
        for (int i = 0; i < n; i += len) {
            float wr = 1.0f, wi = 0.0f;
            for (int j = 0; j < len / 2; ++j) {
                Cx u = data[i + j];
                Cx v = data[i + j + len / 2];
                float vr = v.r * wr - v.i * wi;
                float vi = v.r * wi + v.i * wr;
                data[i + j] = {u.r + vr, u.i + vi};
                data[i + j + len / 2] = {u.r - vr, u.i - vi};
                float nr = wr * wlr - wi * wli;
                wi = wr * wli + wi * wlr;
                wr = nr;
            }
        }
    }
    for (int i = 0; i < n; ++i) { data[i].r /= static_cast<float>(n); data[i].i /= static_cast<float>(n); }
}

void ifft2d(std::vector<Cx>& data, int n) {
    std::vector<Cx> column(static_cast<size_t>(n));
    for (int y = 0; y < n; ++y) ifft1d(&data[static_cast<size_t>(y * n)], n);
    for (int x = 0; x < n; ++x) {
        for (int y = 0; y < n; ++y) column[static_cast<size_t>(y)] = data[static_cast<size_t>(y * n + x)];
        ifft1d(column.data(), n);
        for (int y = 0; y < n; ++y) data[static_cast<size_t>(y * n + x)] = column[static_cast<size_t>(y)];
    }
}
