# RAWRXD_DECODE_CARRY — token N pays for N+1 (B015-aware)

## Rule
```
T > 1  → B015 residency ON; DecodeCarry invalidated (prefill phase)
T == 1 → cold: B015 bypass (direct)
         warm: pool hits via pinned carry; miss → direct (no rematerialize)
```

## Files
- src/runtime/memory/DecodeCarry.hpp
- src/runtime/memory/WeightResidencyPool.hpp (for_each_resident)
- src/rawrxd_transformer.h / .cpp (gate + prepare)
- src/rawrxd_transformer_forwardbatch.cpp (invalidate on prefill)
- certs/rawrxd_decode_carry_001.cpp

## Env
RAWRXD_DECODE_CARRY=1 (default on; set 0 to disable)

## Seal
RAWRXD_DECODE_CARRY_001=PASS
