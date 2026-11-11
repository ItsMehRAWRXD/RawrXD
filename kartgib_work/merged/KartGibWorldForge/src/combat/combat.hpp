#pragma once
#include <cstdint>
#include <vector>
namespace kartgib::combat {
struct Vec3 { double x=0,y=0,z=0; };
struct Projectile { uint64_t id=0,owner=0; Vec3 pos{},vel{}; double radius=0.15,life=2.0,damage=100; bool active=true; };
struct Target { uint64_t id=0; Vec3 pos{}; double radius=0.7,health=100; bool alive=true; };
struct Hit { uint64_t projectile=0,target=0; Vec3 point{}; double damage=0; };
struct Particle { Vec3 pos{},vel{}; double life=0,size=0.1; uint32_t color=0xffffffff; };
struct Explosion { Vec3 pos{}; double radius=2,damage=100; };
struct World { std::vector<Projectile> projectiles; std::vector<Target> targets; std::vector<Particle> particles; uint64_t tick=0,nextId=1; };
struct Config { double speed=85,gravity=0,projectileLife=2,hitRadius=0.15,damage=100,range=180; unsigned maxProjectiles=4096,maxParticles=16384; };
double clamp(double x,double a,double b); // 1
Vec3 add(Vec3 a,Vec3 b); // 2
Vec3 scale(Vec3 a,double k); // 3
double dot(Vec3 a,Vec3 b); // 4
double length(Vec3 v); // 5
Vec3 normalize(Vec3 v); // 6
bool valid(const Config& c); // 7
uint64_t hash(uint64_t x); // 8
bool fire(World& w,uint64_t owner,Vec3 origin,Vec3 direction,const Config& c); // 9
bool segmentSphere(Vec3 a,Vec3 b,Vec3 center,double radius,double& t); // 10
std::vector<Hit> advance(World& w,const Config& c,double dt); // 11
std::vector<Hit> explode(World& w,const Explosion& e); // 12
void emitImpact(World& w,Vec3 pos,uint64_t seed,unsigned count); // 13
void updateParticles(World& w,double dt); // 14
uint64_t fingerprint(const World& w); // 15
}
