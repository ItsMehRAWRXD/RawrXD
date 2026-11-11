#pragma once
#include "physics/vehicle.hpp"
#include "combat/combat.hpp"
#include "editor/scene.hpp"
#include <cstdint>
#include <vector>
#include <string>
namespace worldforge::integration {
struct Command {kartgib::physics::Input driving{}; bool fire=false;};
struct Frame {uint64_t tick=0, vehicleHash=0, combatHash=0; double x=0,z=0; size_t hits=0;};
class Runtime {
public:
 Runtime();
 Frame advance(Command command);
 void reset();
 const kartgib::physics::State& vehicle() const {return vehicle_;}
 const kartgib::combat::World& combat() const {return combat_;}
 const worldforge::editor::Scene& scene() const {return scene_;}
 std::vector<Frame> replay(const std::vector<Command>& commands);
 bool exportScene(const std::string& path) const;
private:
 kartgib::physics::Config physicsConfig_{};
 kartgib::combat::Config combatConfig_{};
 kartgib::physics::State vehicle_{};
 kartgib::combat::World combat_{};
 worldforge::editor::Scene scene_{};
 worldforge::editor::Id kartNode_=0,targetNode_=0;
};
}