#include "Deep2MlaLifecycleAdapter.hpp"
#include <iostream>
#include <vector>

static bool expect(bool v, const char* name) { if(!v) std::cerr << "FAIL " << name << "\n"; return v; }
int main() {
    Deep2::Deep2MlaLifecycleAdapter a; std::string e;
    Deep2::Deep2MlaLifecycleAdapter::Geometry g{2, 3, 4, 2, 2, 2, 2};
    if(!expect(a.Configure(g,e),"configure")) return 1;
    std::vector<float> k(4,1.0f), v(4,2.0f);
    if(!expect(a.BeginToken(0,e),"begin0")) return 1;
    if(!expect(a.WriteLayer(0,k.data(),v.data(),e),"write0")) return 1;
    if(!expect(!a.BeginToken(0,e),"duplicate_position")) return 1;
    if(!expect(a.WriteLayer(1,k.data(),v.data(),e),"write1")) return 1;
    if(!expect(a.CommitToken(e),"commit0")) return 1;
    if(!expect(a.BeginToken(1,e),"begin1")) return 1;
    if(!expect(!a.WriteLayer(9,k.data(),v.data(),e),"bad_layer")) return 1;
    if(!expect(!a.WriteLayer(0,nullptr,v.data(),e),"null_key")) return 1;
    a.CancelRequest();
    if(!expect(a.position()==0 && !a.tokenOpen() && a.cache().currentLength()==0,"cancel_reset")) return 1;
    if(!expect(a.BeginToken(0,e),"begin_after_cancel")) return 1;
    if(!expect(a.WriteLayer(0,k.data(),v.data(),e),"write_after_cancel")) return 1;
    if(!expect(a.CommitToken(e),"commit_after_cancel")) return 1;
    if(!expect(!a.BeginToken(2,e),"skip_position")) return 1;
    if(!expect(a.BeginToken(1,e),"begin1_again")) return 1;
    if(!expect(a.WriteLayer(0,k.data(),v.data(),e),"write1_again")) return 1;
    if(!expect(a.CommitToken(e),"commit1_again")) return 1;
    if(!expect(a.BeginToken(2,e),"begin2")) return 1;
    if(!expect(a.WriteLayer(0,k.data(),v.data(),e),"write2")) return 1;
    if(!expect(a.CommitToken(e),"commit2")) return 1;
    if(!expect(!a.BeginToken(3,e),"context_overflow")) return 1;
    std::cout << "MLA_LIFECYCLE_TEST PASS\n"; return 0;
}
