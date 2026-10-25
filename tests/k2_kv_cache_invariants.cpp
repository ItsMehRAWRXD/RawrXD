// Additional no-dependency KV-cache invariants, independently executable.
#include "K2KVCache.hpp"
#include <cassert>
#include <cstddef>
#include <limits>
#include <stdexcept>
using rawrxd::deep2::K2KVCache;
template<class F> bool fails(F f) { try { f(); } catch (const std::exception&) { return true; } return false; }
int main() {
    const float k[2]={7,11}, v[2]={13,17};
    // 01: default construction is inert.
    K2KVCache c; assert(c.currentLength()==0 && !c.CanAppend());
    // 02: zero geometry fails closed.
    assert(fails([&]{c.Reset(0,1,2);}));
    // 03: dimension overflow fails closed.
    assert(fails([&]{c.Reset(2,2,(std::numeric_limits<std::size_t>::max)());}));
    // 04: successful reset establishes initial bounded allocation.
    c.Reset(2,33,2); assert(c.allocatedPositions()==8);
    // 05: invalid layer fails without mutation.
    assert(fails([&]{c.Write(2,k,v);}) && c.currentLength()==0);
    // 06: null key fails without mutation.
    assert(fails([&]{c.Write(0,nullptr,v);}) && c.currentLength()==0);
    // 07: null value fails without mutation.
    assert(fails([&]{c.Write(0,k,nullptr);}) && c.currentLength()==0);
    // 08: writes are isolated by layer.
    c.Write(1,k,v); assert(c.Key(1,0)[0]==7 && c.Key(0,0)[0]==0);
    // 09: rollback clears speculative key and value.
    c.RollbackPosition(); assert(c.Key(1,0)[0]==0 && c.Value(1,0)[0]==0);
    // 10: commit without writes remains addressable across growth.
    for(std::size_t i=0;i<17;++i)c.CommitPosition();
    assert(c.currentLength()==17 && c.allocatedPositions()>=17 && c.Key(0,16)[0]==0);
    // 11: committed memory accounting excludes unused capacity.
    assert(c.committedBytes()<=c.reservedBytes());
    // 12: speculative write does not alter committed length.
    c.Write(0,k,v); assert(c.currentLength()==17 && c.Key(0,17)[0]==7);
    // 13: truncation clears both speculative and committed suffix.
    c.Truncate(8); assert(c.currentLength()==8 && c.Key(0,17)[0]==0);
    // 14: shrink retains committed prefix and revokes old indexes.
    assert(c.evictColdPages()>0 && c.allocatedPositions()==8);
    assert(fails([&]{(void)c.Key(0,8);}));
    // 15: full capacity no-op truncate is legal.
    c.Reset(1,1,2); c.Write(0,k,v); c.CommitPosition();
    c.Truncate(1); assert(c.currentLength()==1 && c.Key(0,0)[0]==7);
    // 16: exceeding max capacity fails without mutation.
    assert(fails([&]{c.CommitPosition();}) && c.currentLength()==1);
    // 17: reset switches geometry and erases old data.
    c.Reset(3,2,2); assert(c.numLayers()==3 && c.Key(0,0)[0]==0);
    // 18: clear erases committed history and resets length.
    c.Write(2,k,v); c.CommitPosition(); c.Clear();
    assert(c.currentLength()==0 && c.Key(2,0)[0]==0);
    // 19: strict commit rejects an unwritten position.
    c.Reset(2,4,2);
    assert(fails([&]{c.CommitCompletePosition();}) && c.currentLength()==0);
    // 20: one written layer is insufficient.
    c.Write(0,k,v);
    assert(fails([&]{c.CommitCompletePosition();}) && c.currentLength()==0);
    // 21: a complete set commits atomically.
    c.Write(1,k,v); c.CommitCompletePosition();
    assert(c.currentLength()==1 && c.Key(1,0)[0]==7);
    // 22: completion flags reset after commit.
    assert(fails([&]{c.CommitCompletePosition();}));
    // 23: rollback resets partial completion flags.
    c.Write(0,k,v); c.RollbackPosition();
    c.Write(1,k,v);
    assert(fails([&]{c.CommitCompletePosition();}));
    // 24: truncation resets speculative completion flags.
    c.Write(0,k,v); c.Truncate(1);
    assert(fails([&]{c.CommitCompletePosition();}));
    // 25: clear resets completion flags and stored data.
    c.Write(0,k,v); c.Clear();
    assert(fails([&]{c.CommitCompletePosition();}));
    // 26: strict commit works after reset with a different layer count.
    c.Reset(1,1,2); c.Write(0,k,v); c.CommitCompletePosition();
    assert(c.currentLength()==1);
    // 27: Clear revokes partial completion even after a write.
    c.Reset(2,8,2); c.Write(0,k,v); c.Clear();
    c.Write(1,k,v); assert(fails([&]{c.CommitCompletePosition();}));
    // 28: failed Reset preserves an existing complete speculative position.
    c.Write(0,k,v);
    assert(fails([&]{c.Reset(0,8,2);}));
    c.CommitCompletePosition(); assert(c.currentLength()==1);
    // 29: failed overflow Reset preserves committed geometry and content.
    assert(fails([&]{c.Reset(2,8,(std::numeric_limits<std::size_t>::max)());}));
    assert(c.numLayers()==2 && c.currentLength()==1 && c.Key(0,0)[0]==7);
    // 30: successful Reset discards prior completion state.
    c.Write(0,k,v); c.Reset(2,8,2);
    c.Write(1,k,v); assert(fails([&]{c.CommitCompletePosition();}));
    return 0;
}
