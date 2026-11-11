#include "network/network.hpp"
#include <cassert>
#include <iostream>
using namespace worldforge::net;
int main(){
 Input i{0,1,250,80,0};assert(validate(i));assert(decodeInput(encodeInput(i))->steer==250);auto bad=encodeInput(i);bad.pop_back();assert(!decodeInput(bad));
 State s{0,{{1,0,0,0,0},{2,100,0,0,0}}};auto first=checksum(s);advance(s,{i});assert(s.tick==1&&checksum(s)!=first);assert(decodeSnapshot(encodeSnapshot(snapshot(s)))->checksum==checksum(s));
 auto broken=encodeSnapshot(snapshot(s));broken.back()^=1;assert(!decodeSnapshot(broken));
 Packet p{65535,8,3,encodeInput(i)};auto q=decodePacket(encodePacket(p));assert(q&&q->sequence==65535);assert(!decodePacket({1,2,3}));assert(sequenceNewer(0,65535));
 AckWindow ack;assert(ack.receive(65535));assert(ack.receive(0));assert(ack.acknowledged(65535));assert(!ack.receive(65535));assert(ack.receive(2));assert(ack.receive(1));
 InputBuffer buf;assert(buf.enqueue(i));assert(!buf.enqueue(i));assert(buf.take(0).size()==1);assert(buf.take(0).empty());
 Replay r{{0,{{1,0,0,0,0}}},{i,{1,1,0,80,0}}};assert(checksum(r.play(3))==checksum(r.play(3)));
 Reconciler rec;rec.predicted=r.initial;rec.step({i});rec.step({{1,1,0,80,0}});auto predicted=rec.predicted;Snapshot authoritative=snapshot(r.initial);assert(!rec.reconcile(authoritative));State changed=r.initial;changed.players[0].x=300;auto changedSnap=snapshot(changed);assert(rec.reconcile(changedSnap));assert(rec.predicted.tick==predicted.tick&&rec.predicted.players[0].x!=predicted.players[0].x);
 auto a=snapshot(r.initial);auto b=snapshot(s);auto delta=encodeDelta(a,b);auto applied=applyDelta(a,delta);assert(applied&&applied->checksum==b.checksum);delta.back()^=1;assert(!applyDelta(a,delta));
 assert(interpolate({1,0,0,0,0},{1,100,200,0,0},0.5).x==50);RateLimiter limit{2,10};assert(limit.allow(0)&&limit.allow(0)&&!limit.allow(0)&&limit.allow(10));
 std::cout<<"NETWORK_TESTS_PASS checksum="<<checksum(rec.predicted)<<"\n";
}
