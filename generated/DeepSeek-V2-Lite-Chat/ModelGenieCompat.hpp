//=============================================================================
// ModelGenie compatibility shim for generated headers
//=============================================================================
// The generated headers in RawrXD::Deep2::Generated expect certain ModelGenie
// types to be visible without qualification. This shim bridges that gap.
//=============================================================================

#pragma once

#include "ModelGenome.hpp"

namespace RawrXD {
namespace Deep2 {

// Bring key ModelGenie types into the Deep2 namespace so Generated headers
// can use them without qualification.
using ModelGenie::Architecture;
using ModelGenie::RopeScalingType;
using ModelGenie::WeightTying;
using ModelGenie::TensorRole;
using ModelGenie::GGMLType;
using ModelGenie::Primitive;
using ModelGenie::OpCode;

} // namespace Deep2
} // namespace RawrXD
