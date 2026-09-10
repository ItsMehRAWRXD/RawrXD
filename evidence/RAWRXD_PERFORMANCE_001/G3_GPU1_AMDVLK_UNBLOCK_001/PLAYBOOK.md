# G3_GPU1_AMDVLK_UNBLOCK_001 — RX 7800 XT Vulkan unblock playbook

Parent: `G3_GPU1_SOLO_CREATE_DISC_001` | `G3_GPU1_VDRIVER_D3D12_001` | `G3_GPU1_AMDVLK_DIRECT_ICD_001`

Authorizing rule: the phase that first yields `SOLO_RX7800XT_A0=PASS` (5/5) AND `vulkaninfo` PASS earns `RX7800XT_POOL_STATUS=INCLUDED` for that `INCLUSION_MODE`.

`PROMOTE=0` through all phases. Pool inclusion ≠ champion promotion.

| Phase | Mode if pass | Mutates system |
|-------|--------------|----------------|
| P0 | witness only | no |
| P1 | NATIVE (ULPS/MPO/HAGS/ASPM) | yes + reboot |
| P2 | WAKE_LEASE | no reboot |
| P3 | NATIVE (driver) | yes |
| P4 | NATIVE (PAL/vBIOS) | maybe |
| P5 | DOZEN_D3D12 | env/ICD |

Verification gate (every phase): `vulkaninfo --summary` exit 0 listing 7800; solo A0 5/5; artifacts under `G3_GPU1_AMDVLK_UNBLOCK_001/<PHASE>/`.
