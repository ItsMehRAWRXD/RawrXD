#include "deep2/ReapDownloadOwnership.hpp"
#include <cstdio>
using Deep2::Submit::DownloadOwnership;
struct Handles { int command=0, fence=0, staging=0; };
int main() {
    DownloadOwnership<Handles> book;
    int pass=0, fail=0, releases=0, last=0;
    auto check=[&](bool yes,const char* label){std::printf("%s %s\n",yes?"PASS":"FAIL",label);yes?++pass:++fail;};
    auto release=[&](Handles& h){++releases;last=h.staging;h={};};
    check(book.Empty(),"initial empty");
    auto a=book.Reserve(7), b=book.Reserve(7);
    if(!a.payload||!b.payload) return 2;
    *a.payload={11,12,13};*b.payload={21,22,23};
    check(a.id!=b.id && book.Find(a.id,7)==a.payload,"unique stable owners");
    check(book.Find(a.id,8)==nullptr,"stale generation lookup rejected");
    check(!book.Complete(a.id,7,0,release),"unsubmitted completion rejected");
    check(book.DiscardUnsubmitted(b.id,7,release)&&releases==1&&last==23,"pre-submit cleanup");
    check(book.MarkAttempt(a.id,7),"mark before submit");
    check(!book.MarkAttempt(a.id,7),"duplicate attempt rejected");
    check(!book.DiscardUnsubmitted(a.id,7,release),"attempted discard blocked");
    check(!book.Complete(a.id,7,2,release),"timeout retains owner");
    check(!book.Complete(a.id,7,-4,release),"device loss retains until teardown");
    check(!book.Complete(a.id,8,0,release),"stale completion rejected");
    check(book.Find(a.id,7)->staging==13&&releases==1,"actual payload retained");
    check(!book.Drain(7,-1,release)&&!book.Empty(),"unknown idle blocks drain");
    check(!book.Drain(8,0,release),"wrong-generation drain blocked");
    check(book.Complete(a.id,7,0,release)&&book.Empty()&&releases==2&&last==13,"completion frees once");
    check(!book.Complete(a.id,7,0,release)&&releases==2,"duplicate completion rejected");
    auto c=book.Reserve(8);if(!c.payload)return 2;*c.payload={31,32,33};
    check(c.id>a.id&&c.id>b.id&&book.MarkAttempt(c.id,8),"identity never recycled after recreation");
    check(book.Drain(8,-4,release)&&book.Empty()&&last==33&&releases==3,"terminal drain");
    check(book.Drain(8,0,release)&&releases==3,"empty drain idempotent");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
