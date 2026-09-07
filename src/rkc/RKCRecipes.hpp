// RKCRecipes.hpp — deterministic knowledge recipes
#pragma once
#include "RKCTypes.hpp"
#include "RKCWorld.hpp"
#include <vector>

namespace RawrXD {
namespace RKC {

std::vector<Recipe> Deep2RecipePack();

// Apply recipes: if all needKeys are Real/Derived, put Derived producesKey.
void ApplyRecipes(World& world, const std::vector<Recipe>& recipes);

} // namespace RKC
} // namespace RawrXD
