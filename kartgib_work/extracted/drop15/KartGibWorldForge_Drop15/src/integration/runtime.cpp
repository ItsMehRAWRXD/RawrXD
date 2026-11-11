#include "integration/runtime.hpp"
#include <cmath>
#include <stdexcept>
namespace worldforge::integration {
Runtime::Runtime(){reset();}
void Runtime::reset(){
 vehicle_={};combat_={};scene_={};
 kartNode_=scene_.create("PlayerKart");targetNode_=scene_.create("TargetDummy");
 kartgib::combat::Target target{};target.id=1;target.pos={0,0.55,22};target.radius=1;target.health=100;
 combat_.targets.push_back(target);
 worldforge::editor::Transform t{};t.position={0,0.55,22};
 if(!scene_.setTransform(targetNode_,t))throw std::runtime_error("target transform failed");
}
Frame Runtime::advance(Command command){
 constexpr double dt=1.0/60.0;
 kartgib::physics::step(vehicle_,command.driving,physicsConfig_,{},dt);
 if(command.fire){
  auto f=kartgib::physics::forward(vehicle_.yaw);
  kartgib::combat::fire(combat_,1,{vehicle_.position.x,0.55,vehicle_.position.z},{f.x,0,f.z},combatConfig_);
 }
 const auto hits=kartgib::combat::advance(combat_,combatConfig_,dt);
 kartgib::combat::updateParticles(combat_,dt);
 worldforge::editor::Transform t{};
 t.position={vehicle_.position.x,vehicle_.height,vehicle_.position.z};t.rotation={0,vehicle_.yaw,0};
 if(!scene_.setTransform(kartNode_,t))throw std::runtime_error("kart scene update failed");
 if(!combat_.targets.empty()&&!combat_.targets[0].alive)scene_.setVisible(targetNode_,false);
 return {vehicle_.tick,kartgib::physics::fingerprint(vehicle_),kartgib::combat::fingerprint(combat_),vehicle_.position.x,vehicle_.position.z,hits.size()};
}
std::vector<Frame> Runtime::replay(const std::vector<Command>& commands){
 reset();std::vector<Frame> result;result.reserve(commands.size());
 for(const auto& command:commands)result.push_back(advance(command));
 return result;
}
bool Runtime::exportScene(const std::string& path) const{return scene_.save(path);}
}