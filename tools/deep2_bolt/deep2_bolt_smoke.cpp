#include "deep2_bolt_pipeline.hpp"
#include <iostream>
int main(){
    try {
        deep2::bolt::ModelDesc empty;
        deep2::bolt::validate_inventory(empty);
        std::cerr << "FAIL: invalid model was admitted\n";
        return 1;
    } catch (const deep2::bolt::Error&) {
        std::cout << "PASS: invalid model fails closed\n";
        return 0;
    }
}
