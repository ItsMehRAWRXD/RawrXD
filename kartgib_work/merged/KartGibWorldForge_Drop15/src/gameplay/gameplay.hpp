#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace wf::gameplay {
struct Vec3 {double x=0,y=0,z=0;};
struct Key {double time=0; Vec3 value{};};
struct Track {std::vector<Key> keys; bool loop=false;};
struct Pose {Vec3 position{}, scale{1,1,1}; double yaw=0;};
struct PoseKey {double time=0; Pose pose{};};
struct Clip {std::vector<PoseKey> keys; bool loop=false;};
struct Envelope {double attack=.01,decay=.1,sustain=.6,release=.2;};
struct Note {double hz=440, duration=.5, amplitude=.3;};
struct Instruction {enum Op {Set,Add,Mul,Wait,Emit,JumpIfLess,Stop} op=Stop; int slot=0; double value=0; int target=0;};
struct VM {double registers[16]{}; std::size_t pc=0; double wait=0; bool halted=false; std::vector<int> events;};
double clamp(double v,double lo,double hi);
double lerp(double a,double b,double t);
Vec3 interpolate(const Track& t,double time);
Pose sample(const Clip& clip,double time);
Pose blend(const Pose& a,const Pose& b,double weight);
double envelope(const Envelope& e,double time,double held);
double oscillator(double phase,int waveform);
std::vector<float> synthesize(const Note& note,const Envelope& env,int sampleRate,int waveform);
std::vector<float> mix(const std::vector<std::vector<float>>& tracks);
std::vector<float> lowpass(const std::vector<float>& input,double cutoff,int sampleRate);
std::vector<float> delay(const std::vector<float>& input,int delaySamples,double feedback);
bool writeWav(const std::string& path,const std::vector<float>& samples,int sampleRate);
std::vector<Instruction> compile(const std::string& source);
void execute(VM& vm,const std::vector<Instruction>& code,double dt,int budget=256);
uint64_t fingerprint(const VM& vm);
}
