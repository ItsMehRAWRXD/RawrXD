#pragma once
#include <cstdint>
#include <cstddef>

#if defined(_WIN32) || defined(_WIN64)
  #ifdef BUILDING_WEIGHT_PROJECTION_DLL
    #define WP_ABI __declspec(dllexport)
  #else
    #define WP_ABI __declspec(dllimport)
  #endif
#else
  #define WP_ABI __attribute__((visibility("default")))
#endif

extern "C" {

// Target format classification enum (aligns with Classify.asm)
enum WeightFormat : uint16_t {
    WF_ZERO = 0,
    WF_B1   = 1,
    WF_T3   = 3,
    WF_Q3   = 4,
    WF_Q4   = 5,
    WF_RAW  = 255
};

// Pure reference to source weight memory (No device/residency fields)
struct WeightRef {
    const float* data;
    uint32_t     num_elements;
    uint32_t     element_stride_bytes;
};

// Immutable projection view describing structural characteristics
struct WeightView {
    WeightRef    ref;
    WeightFormat format;
    float        density;
    float        peak_to_mean_ratio;
    uint32_t     non_zero_count;
};

// Assembly function interface (Classify.asm)
uint16_t Classify(const float* w, uint32_t n);

// Public C-ABI Functions
WP_ABI int  WeightResolve(const WeightRef* ref, WeightView* out_view);
WP_ABI int  WeightProject(const WeightView* view, void* target_buffer, size_t target_capacity);
WP_ABI void WeightRelease(WeightView* view);

} // extern "C"
