#include "reap/ReapAutoFitIR.hpp"
#include <cassert>
#include <iostream>

int main() {
    RawrXD::Reap::AutoFitAggregateIR ir;
    assert(std::string(ir.kSchema) == "rawrxd.reap.autofit.ir.v1");
    RawrXD::Reap::AutoFitTensorIR recurrent;
    recurrent.visitMultiplier = 3;
    recurrent.recurrent = true;
    recurrent.prunable = true;
    assert(recurrent.visitMultiplier == 3 && recurrent.recurrent && recurrent.prunable);
    std::cout << "reap_autofit_ir: PASS\n";
}
