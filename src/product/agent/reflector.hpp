#pragma once
#include "confidence.hpp"
#include "failure_class.hpp"
#include <string>
namespace rawr::product {

struct Reflect {
    FailKind fail = FailKind::None;
    std::string note;
    int rollback = 0;
};

inline Reflect ReflectOn(const std::string& log, int compileOk, int testOk) {
    Reflect r;
    r.fail = ClassifyFail(log);
    if (!compileOk && r.fail == FailKind::None) r.fail = FailKind::Compile;
    if (compileOk && !testOk && r.fail == FailKind::None) r.fail = FailKind::Test;
    if (r.fail != FailKind::None) {
        r.rollback = 1;
        r.note = std::string("retry:") + FailName(r.fail);
    } else {
        r.note = "ok";
    }
    return r;
}

} // namespace rawr::product
