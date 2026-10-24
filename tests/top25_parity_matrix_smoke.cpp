#include "../src/parity/Top25ParityMatrix.hpp"
#include <cassert>
#include <iostream>
int main(){
    using namespace rawrxd::parity;
    Matrix m{};
    assert(kTargets.size()==25 && kCapabilities.size()==20);
    assert(TotalCells()==500 && CertifiedCount(m)==0);
    m[0][0].status=Status::Implemented;
    assert(CertifiedCount(m)==0);
    m[0][0].status=Status::Certified;
    assert(CertifiedCount(m)==1);
    std::cout<<"TOP25_PARITY_MATRIX_SMOKE_PASS\n";
}
