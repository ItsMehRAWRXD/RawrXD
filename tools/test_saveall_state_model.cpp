// Standalone Save All state-machine regression; NOT linked to Win32IDE.
#include <iostream>
#include <vector>
struct Doc { bool dirty; bool hasTab; bool saveSucceeds; };
struct Result { bool failed; bool dirty; bool successReported; int attempted; };
static Result simulate(std::vector<Doc> docs, int active) {
    bool failed=false, anySaved=false; int attempted=0;
    for (int i=0;i<static_cast<int>(docs.size());++i) {
        if(i==active || !docs[i].dirty)continue;
        if(!docs[i].hasTab){failed=true;break;}
        ++attempted;
        if(!docs[i].saveSucceeds){failed=true;break;}
        docs[i].dirty=false;anySaved=true;
    }
    if(!failed && active>=0 && active<static_cast<int>(docs.size()) && docs[active].dirty){
        ++attempted;
        if(!docs[active].saveSucceeds)failed=true;
        else {docs[active].dirty=false;anySaved=true;}
    }
    bool dirty=false;
    for(const auto& d:docs)dirty|=d.dirty;
    return {failed,dirty,!failed && anySaved && !dirty,attempted};
}
int main(){
    int passed=0;
    auto test=[&](const char*name,std::vector<Doc>docs,int active,bool failed,bool dirty,bool success,int attempts){
        const auto r=simulate(docs,active);
        const bool ok=r.failed==failed && r.dirty==dirty &&
            r.successReported==success && r.attempted==attempts;
        passed+=ok;
        std::cout<<name<<"="<<(ok?"PASS":"FAIL")<<"\n";
    };
    test("01_clean",{{false,true,true}},0,false,false,false,0);
    test("02_one_saved",{{true,true,true}},0,false,false,true,1);
    test("03_active_fails",{{true,true,false}},0,true,true,false,1);
    test("04_nonactive_saved",{{false,true,true},{true,true,true}},0,false,false,true,1);
    test("05_nonactive_fails",{{false,true,true},{true,true,false}},0,true,true,false,1);
    test("06_missing_tab",{{false,true,true},{true,false,true}},0,true,true,false,0);
    test("07_missing_tab_blocks_later",{{false,true,true},{true,false,true},{true,true,true}},0,true,true,false,0);
    test("08_partial_save_then_missing",{{false,true,true},{true,true,true},{true,false,true}},0,true,true,false,1);
    test("09_active_not_saved_after_failure",{{true,true,true},{true,false,true}},0,true,true,false,0);
    test("10_all_three",{{true,true,true},{true,true,true},{true,true,true}},0,false,false,true,3);
    test("11_second_fails",{{true,true,true},{true,true,false},{true,true,true}},2,true,true,false,2);
    test("12_last_active_fails",{{true,true,false},{true,true,true}},0,true,true,false,2);
    test("13_no_active_clean",{{false,true,true}},-1,false,false,false,0);
    test("14_no_active_modified",{{true,true,true}},-1,false,false,true,1);
    test("15_missing_tab_no_active",{{true,false,true}},-1,true,true,false,0);
    std::cout<<"SAVEALL_MODEL="<<passed<<"/15\n";
    return passed==15?0:1;
}
