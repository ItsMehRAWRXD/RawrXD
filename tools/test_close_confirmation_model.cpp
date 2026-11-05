// Portable close-decision model. Not a native MessageBox/Win32IDE test.
#include <iostream>
#include <array>
constexpr int kYes=6, kNo=7, kCancel=2;
struct Decision { bool mayClose; bool invokeSave; };
constexpr Decision decide(int response, bool dirty, bool saveSucceeded) {
    if (!dirty) return {true,false};
    if (response==kNo) return {true,false};
    if (response==kYes) return {saveSucceeded,true};
    return {false,false}; // Cancel, API error (0), or unexpected result
}
struct Case { const char* name; int response; bool dirty; bool saveSucceeded; bool close; bool save; };
int main() {
    constexpr std::array<Case,15> cases = {{
        {"01_clean",0,false,false,true,false},
        {"02_yes_saved",kYes,true,true,true,true},
        {"03_yes_failed",kYes,true,false,false,true},
        {"04_no_discard",kNo,true,false,true,false},
        {"05_cancel",kCancel,true,true,false,false},
        {"06_api_error_zero",0,true,true,false,false},
        {"07_unexpected_negative",-1,true,true,false,false},
        {"08_unexpected_positive",42,true,true,false,false},
        {"09_clean_yes",kYes,false,false,true,false},
        {"10_clean_no",kNo,false,false,true,false},
        {"11_clean_cancel",kCancel,false,false,true,false},
        {"12_yes_failed_again",kYes,true,false,false,true},
        {"13_no_with_success_flag",kNo,true,true,true,false},
        {"14_cancel_with_failed_save",kCancel,true,false,false,false},
        {"15_unexpected_large",65535,true,false,false,false}
    }};
    int passed=0;
    for(const auto& c:cases){
        const auto actual=decide(c.response,c.dirty,c.saveSucceeded);
        const bool ok=actual.mayClose==c.close && actual.invokeSave==c.save;
        passed+=ok;
        std::cout<<c.name<<"="<<(ok?"PASS":"FAIL")<<"\n";
    }
    std::cout<<"CLOSE_DECISION_MODEL="<<passed<<"/"<<cases.size()<<"\n";
    return passed==static_cast<int>(cases.size())?0:1;
}
