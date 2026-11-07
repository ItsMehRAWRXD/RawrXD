#include <concepts>
template<std::integral T> constexpr T add(T a, T b) { return a + b; }
static_assert(add(2, 3) == 5);
int rawrxd_gate_add(int a, int b) { return add(a, b); }
