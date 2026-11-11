#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <array>
namespace worldforge::editor {
using Id=uint64_t;
struct Vec3 { double x=0,y=0,z=0; };
struct Transform { Vec3 position{},rotation{},scale{1,1,1}; };
struct Node { Id id=0,parent=0; std::string name; Transform local{}; bool visible=true,locked=false; };
struct Ray { Vec3 origin{},direction{0,0,1}; };
struct Camera { Vec3 eye{0,5,-10},target{}; double fov=60; };
struct Hit { Id id=0; double distance=0; };
class Scene {
public:
 Id create(std::string name,Id parent=0); // 1
 bool erase(Id id); // 2 recursive
 bool reparent(Id id,Id parent); // 3 cycle checked
 bool rename(Id id,std::string name); // 4
 bool setTransform(Id id,Transform t); // 5
 bool translate(Id id,Vec3 delta); // 6
 bool setVisible(Id id,bool visible); // 7
 bool setLocked(Id id,bool locked); // 8
 bool select(Id id); // 9
 std::vector<Id> children(Id id) const; // 10
 std::optional<Transform> worldTransform(Id id) const; // 11 (position/rotation additive, scale multiplicative)
 std::optional<Hit> pick(Ray ray,double radius=1) const; // 12
 bool save(const std::string& path) const; // 13
 bool load(const std::string& path); // 14
 bool undo(); bool redo(); // 15
 const std::vector<Node>& nodes() const {return nodes_;}
 Id selection() const{return selected_;}
private:
 struct Snapshot {std::vector<Node> nodes; Id next,selected;};
 std::vector<Node> nodes_{}; Id next_=1,selected_=0;
 std::vector<Snapshot> undo_,redo_;
 Node* find(Id id); const Node* find(Id id) const;
 bool descendant(Id child,Id ancestor) const;
 void checkpoint();
};
Camera orbit(Camera c,double yawRadians,double pitchRadians,double distance);
}