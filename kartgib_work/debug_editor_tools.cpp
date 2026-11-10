#include "editor/tools.hpp"
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
using namespace worldforge::editor;
using namespace worldforge::editor::tools;
static void require(bool ok,const char* msg){if(!ok){std::cerr<<msg<<'\n';std::exit(1);}}
int main(){
std::cout << "Test 1: safeRelativePath - safe path\n";
require(safeRelativePath("assets/tree.obj"),"safe path");
std::cout << "PASS\n";

std::cout << "Test 2: safeRelativePath - traversal\n";
require(!safeRelativePath("../secret"),"traversal");
std::cout << "PASS\n";

std::cout << "Test 3: safeRelativePath - unix absolute\n";
require(!safeRelativePath("/etc/passwd"),"absolute");
std::cout << "PASS\n";

std::cout << "Test 4: safeRelativePath - drive absolute\n";
require(!safeRelativePath("C:/Windows/System32"),"drive absolute");
std::cout << "PASS\n";

std::cout << "Test 5: safeRelativePath - drive absolute backslash\n";
require(!safeRelativePath("C:\\Windows\\System32"),"drive absolute backslash");
std::cout << "PASS\n";

std::cout << "Test 6: safeRelativePath - UNC\n";
require(!safeRelativePath("\\\\server\\share"),"UNC");
std::cout << "PASS\n";

auto dir=std::filesystem::temp_directory_path()/"worldforge_drop12_test";
std::filesystem::create_directories(dir);
{std::ofstream f(dir/"tree.obj");f<<"v 0 0 0\n";}
AssetBrowser b;
std::cout << "Test 7: AssetBrowser scan\n";
require(b.scan(dir.string()),"scan");
std::cout << "PASS\n";

std::cout << "Test 8: AssetBrowser filter\n";
require(b.filter("mesh").size()==1,"filter");
std::cout << "PASS\n";

std::filesystem::remove_all(dir);
std::cout << "Test 9: identity transform\n";
auto I=identity();
require(transformPoint(I,{1,2,3}).x==1,"identity");
std::cout << "PASS\n";

std::cout << "Test 10: transform matrix\n";
Transform t;t.position={3,4,5};t.scale={2,3,4};
auto M=transformMatrix(t);
auto p=transformPoint(M,{1,1,1});
require(p.x==5&&p.y==7&&p.z==9,"transform");
std::cout << "PASS\n";

std::cout << "Test 11: inverse affine\n";
auto inv=inverseAffine(M);
require(inv.has_value(),"inverse");
auto q=transformPoint(*inv,p);
require(fabs(q.x-1)<1e-9&&fabs(q.y-1)<1e-9,"inverse point");
std::cout << "PASS\n";

std::cout << "Test 12: singular matrix\n";
auto z=transformMatrix({{}, {}, {0,1,1}});
require(!inverseAffine(z),"singular");
std::cout << "PASS\n";

std::cout << "Test 13: multiply\n";
auto mm=multiply(I,M);
require(transformPoint(mm,{1,1,1}).z==9,"multiply");
std::cout << "PASS\n";

std::cout << "Test 14: viewport ray\n";
Camera cam;
auto ray=viewportRay(400,300,800,600,cam);
require(ray.valid,"viewport");
require(!viewportRay(0,0,0,600,cam).valid,"bad viewport");
std::cout << "PASS\n";

std::cout << "Test 15: ray plane\n";
auto hit=rayPlane({{0,1,0},{0,-1,0}},{0,0,0},{0,1,0});
require(hit&&fabs(*hit-1)<1e-9,"plane");
require(!rayPlane({{0,1,0},{1,0,0}},{0,0,0},{0,1,0}),"parallel");
std::cout << "PASS\n";

std::cout << "Test 16: snap\n";
require(snap({1.3,-1.3,0},0.5).x==1.5,"snap");
std::cout << "PASS\n";

std::cout << "Test 17: Scene operations\n";
Scene s;Id id=s.create("Tree");
require(id,"create");
require(applyTranslation(s,id,{1.3,0,0},0.5),"move");
require(inspect(s,id)->transform.position.x==1.5,"inspect");
require(applyRotation(s,id,{0,0.5,0},0.25),"rotate");
require(applyScale(s,id,{2,2,2},0),"scale");
require(!applyScale(s,id,{-1,1,1},0),"negative scale");
require(s.setLocked(id,true),"lock");
require(!applyTranslation(s,id,{1,0,0},0),"locked");
require(s.undo(),"undo");
std::cout << "PASS\n";

std::cout<<"EDITOR_TOOLS_PASS\n";
}
