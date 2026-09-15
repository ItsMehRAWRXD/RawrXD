#pragma once
#include "KVCache.h"
#include <cstddef>

namespace Deep2 {

class KVSpecTransaction {
public:
    explicit KVSpecTransaction(KVCache& kv)
        :kv_(&kv),base_(kv.checkpoint()){}
    KVSpecTransaction(const KVSpecTransaction&)=delete;
    KVSpecTransaction& operator=(const KVSpecTransaction&)=delete;

    ~KVSpecTransaction() {
        if(kv_&&!committed_)
            (void)kv_->rewind(base_,false);
    }

    size_t base() const noexcept { return base_; }
    size_t current() const noexcept {
        return kv_?kv_->currentLength():base_;
    }

    bool commitAccepted(size_t accepted) {
        if(!kv_) return false;
        const size_t want=base_+accepted;
        if(want>kv_->currentLength()) return false;
        if(!kv_->rewind(want,false)) return false;
        committed_=true;
        return true;
    }

    bool commitAll() {
        if(!kv_) return false;
        committed_=true;
        return true;
    }

    void rollback() {
        if(kv_) (void)kv_->rewind(base_,false);
        committed_=true;
    }

private:
    KVCache* kv_=nullptr;
    size_t base_=0;
    bool committed_=false;
};

} // namespace Deep2
