#pragma once
/* Chamber — stub */
#include <cstdint>
#include <cstddef>
namespace Deep2 {
struct ChamberResult { int status = 0; };
struct FormulaRoute { int route = 0; };
class Chamber {
public:
    ChamberResult evaluate(const float*, size_t) { return {}; }
};
} // namespace Deep2
