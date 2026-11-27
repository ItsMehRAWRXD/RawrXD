#pragma once
// RAWRXD REAP SC01 (consolidation): the authoritative, storage-independent slicing
// core now lives in deep2/ReapExpertSlice.hpp (a superset of the former
// ReapTensorSlice: SliceTensorDesc / ExpertSelection / SliceResult / SliceExperts
// plus ComputeExpertSliceLayout). This header forwards so existing includes and the
// s01/s02/s02p contract tests are unchanged. No duplicate algorithm remains.
#include "deep2/ReapExpertSlice.hpp"