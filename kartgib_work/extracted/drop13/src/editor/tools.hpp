#pragma once
#include "editor/scene.hpp"
#include <array>
#include <optional>
#include <string>
#include <vector>
namespace worldforge::editor::tools {
struct Asset { std::string path,kind; uint64_t bytes=0; };
struct AssetBrowser { std::vector<Asset> items; bool scan(const std::string& root); std::vector<Asset> filter(const std::string& query) const; }; // 1,2
bool safeRelativePath(const std::string& path); // 3
struct Mat4 { std::array<double,16> m{}; };
Mat4 identity(); // 4
Mat4 multiply(const Mat4&,const Mat4&); // 5
Mat4 transformMatrix(Transform); // 6
Vec3 transformPoint(const Mat4&,Vec3); // 7
std::optional<Mat4> inverseAffine(const Mat4&); // 8
struct ScreenRay { Ray ray; bool valid=false; };
ScreenRay viewportRay(double px,double py,double width,double height,const Camera&); // 9
std::optional<double> rayPlane(Ray,Vec3 point,Vec3 normal); // 10
Vec3 snap(Vec3,double increment); // 11
bool applyTranslation(Scene&,Id,Vec3 delta,double snapStep); // 12
bool applyScale(Scene&,Id,Vec3 factor,double snapStep); // 13
bool applyRotation(Scene&,Id,Vec3 radians,double snapStep); // 14
struct Inspector { Id id=0; std::string name; Transform transform{}; bool visible=false,locked=false; };
std::optional<Inspector> inspect(const Scene&,Id); // 15
}
