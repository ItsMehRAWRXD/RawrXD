#include "RomRotary.hpp"
#include <cstdio>
#include <cmath>
#include <limits>
using deep2::RotaryLayout;
static bool near(float a, double b) { return std::abs(a-b) < 1e-5; }
int main() {
    const double c = std::cos(1.0), s = std::sin(1.0);
    float a[] = {1,0,2,0,7,8};
    if (!deep2::rotateHead(a,6,4,1,10000,1,RotaryLayout::Interleaved) ||
        !near(a[0],c) || !near(a[1],s) ||
        !near(a[2],2*std::cos(0.01)) || !near(a[3],2*std::sin(0.01)) ||
        a[4]!=7 || a[5]!=8) return 1;
    float b[] = {1,2,0,0,7,8};
    if (!deep2::rotateHead(b,6,4,1,10000,1,RotaryLayout::NeoX) ||
        !near(b[0],c) || !near(b[2],s) ||
        !near(b[1],2*std::cos(0.01)) || !near(b[3],2*std::sin(0.01)) ||
        b[4]!=7 || b[5]!=8) return 2;
    float d[] = {1,2,3,4};
    if (!deep2::rotateHead(d,4,4,0,10000,1,RotaryLayout::NeoX) ||
        d[0]!=1 || d[1]!=2 || d[2]!=3 || d[3]!=4) return 3;
    if (deep2::rotateHead(d,4,5,1,10000,1,RotaryLayout::NeoX) ||
        deep2::rotateHead(d,4,3,1,10000,1,RotaryLayout::NeoX) ||
        deep2::rotateHead(d,4,4,1,0,1,RotaryLayout::NeoX) ||
        deep2::rotateHead(nullptr,4,4,1,10000,1,RotaryLayout::NeoX)) return 4;
    float e[] = {3,4};
    if (!deep2::rotateHead(e,2,2,100000,10000,0.5,RotaryLayout::Interleaved) ||
        !near(e[0],3*std::cos(50000.0)-4*std::sin(50000.0)) ||
        !near(e[1],3*std::sin(50000.0)+4*std::cos(50000.0))) return 5;
    std::puts("ROM rotary regression PASS");
    return 0;
}
