#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <optional>
namespace worldforge::net {
struct Input {uint32_t tick=0, player=0; int16_t steer=0; uint8_t throttle=0,brake=0;};
struct Player {uint32_t id=0; int32_t x=0,z=0,vx=0,vz=0;}; // millimetres and mm/tick
struct State {uint32_t tick=0; std::vector<Player> players;};
struct Packet {uint16_t sequence=0,ack=0; uint32_t ackBits=0; std::vector<uint8_t> payload;};
struct Snapshot {uint32_t tick=0; uint64_t checksum=0; std::vector<Player> players;};
uint64_t checksum(const State&);
bool validate(const Input&);
void advance(State&,const std::vector<Input>&);
std::vector<uint8_t> encodeInput(const Input&);
std::optional<Input> decodeInput(const std::vector<uint8_t>&);
std::vector<uint8_t> encodeSnapshot(const Snapshot&);
std::optional<Snapshot> decodeSnapshot(const std::vector<uint8_t>&);
Snapshot snapshot(const State&);
std::vector<uint8_t> encodePacket(const Packet&);
std::optional<Packet> decodePacket(const std::vector<uint8_t>&);
bool sequenceNewer(uint16_t a,uint16_t b);
struct AckWindow {uint16_t latest=0;uint32_t bits=0;bool initialized=false;bool receive(uint16_t);bool acknowledged(uint16_t seq)const;};
struct InputBuffer {std::map<uint32_t,std::vector<Input>> pending;bool enqueue(Input);std::vector<Input> take(uint32_t tick);};
struct Replay {State initial;std::vector<Input> inputs;State play(uint32_t endTick)const;};
struct Reconciler {State predicted;std::map<uint32_t,State> history;std::map<uint32_t,std::vector<Input>> inputs;void step(const std::vector<Input>&);bool reconcile(const Snapshot&);};
std::vector<uint8_t> encodeDelta(const Snapshot& previous,const Snapshot& current);
std::optional<Snapshot> applyDelta(const Snapshot& previous,const std::vector<uint8_t>&);
struct Interpolated {double x=0,z=0;};
Interpolated interpolate(const Player&,const Player&,double alpha);
struct RateLimiter {uint32_t limit=0,window=60,start=0,count=0;bool allow(uint32_t tick);};
}
