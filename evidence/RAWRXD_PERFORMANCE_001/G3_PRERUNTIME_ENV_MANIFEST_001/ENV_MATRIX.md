# Pre-runtime environment matrix — deep2_streamer_parity (frozen EXE)

## Phase order
argv → forbidden scan → ImportSpace68 → ArmSpeedEnv → GPU enum → DualStick → FreeToken/FutureConsumer law → MarkGenerateBegin → [RUNTIME] Deep2GenerateStream

## Operator overlays used in G3
| Key | Solo freeze | DualStick reprobe | Harness default if unset |
|-----|-------------|-------------------|--------------------------|
| DEEP2_MARS | 0 | 0 | 1 |
| DEEP2_DUALSTICK_ARM | 0 | 1 | (unset→arm) |
| DEEP2_GPU_POLICY | SOLO | cleared→MULTI via arm | MULTI |
| RAWRXD_GPU_NAME | R9700 | cleared by arm | unset |
| RAWRXD_HOST_DECODE | 0 | 0 | 0 |
| RAWRXD_DEEP2_ALLOW_ELASTIC | 0 | 0 | 1 |
| RAWRXD_ENHANCE_SKIP | min-stack list | min-stack list | unset |
| DEEP2_WEIGHT_BUDGET_MIB | E8B0M | E8B0M | E8B0M |

## Harness always forces
TOKEN_PACING=OFF DECODE_SLEEP=0 DEEP2_LIVE_POLICY=TRAMPOLINE DEEP2_LIVE_MECH=trampoline DEEP2_GEN_ALG=lukewarm + cert/spam logs off

## PE reality vs link line
Linked: winhttp.lib + many system libs
Loaded (PE): KERNEL32, vulkan-1, pdh, dxgi only (/MT static CRT; LTCG drop)
ImportSpace68: FORBIDDEN=0 NETWORK_CAPABLE=0 PASS
