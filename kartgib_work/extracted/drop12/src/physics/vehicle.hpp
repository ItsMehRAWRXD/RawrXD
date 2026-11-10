#pragma once
#include <cstdint>
#include <vector>
namespace kartgib::physics {
struct Vec3 { double x=0,y=0,z=0; };
struct Input { double throttle=0, brake=0, steer=0; bool boost=false; };
struct Config { double mass=180, wheelbase=1.65, maxSteer=0.58, engineForce=3800, brakeForce=6500, drag=0.48, rolling=18, lateralGrip=7.5, suspensionK=18000, suspensionD=1900, restHeight=0.55, wheelRadius=0.28, boostForce=2800, boostCapacity=3, boostRegen=0.25, maxSpeed=65; };
struct State { Vec3 position{}; double yaw=0, forwardSpeed=0, lateralSpeed=0, verticalSpeed=0, height=0.55, boostEnergy=3; bool grounded=true; uint64_t tick=0; };
struct Surface { double height=0, friction=1; Vec3 normal{0,1,0}; };
struct AABB { Vec3 min{}, max{}; };
struct Contact { bool hit=false; Vec3 normal{}; double penetration=0; };
struct WheelPose { Vec3 position{}; double steerAngle=0, spinAngle=0, compression=0; };
struct Telemetry { double speed=0, acceleration=0, lateralAcceleration=0, suspensionForce=0, boostUsed=0; bool collision=false; };
double clamp(double x,double lo,double hi);
bool valid(const Config& c);
Input sanitize(Input in);
Vec3 forward(double yaw);
Vec3 right(double yaw);
double stoppingDistance(double speed,const Config& c,double friction=1);
double steeringYawRate(double speed,double steer,const Config& c);
double suspensionForce(double compression,double compressionRate,const Config& c);
Contact sphereAabb(Vec3 center,double radius,AABB box);
void resolveContact(State& state,const Contact& contact);
WheelPose wheelPose(const State& s,const Config& c,int wheelIndex);
Telemetry step(State& state,Input input,const Config& config,Surface surface,double dt);
void simulate(State& state,const std::vector<Input>& inputs,const Config& c,Surface surface,double dt);
uint64_t fingerprint(const State& state);
}
