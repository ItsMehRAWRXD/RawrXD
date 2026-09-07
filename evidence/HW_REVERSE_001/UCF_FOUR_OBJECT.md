# UCF collapse — four-object fabric

**Authority (locked):** `src/deep2/rawr_uncoherent_object_fabric.hpp`  
**Not authority:** MASM sandbox drop / `src/deep2/ucf/*` sketches / missing `ml64`

| Object | Role |
|--------|------|
| Tensor | `objectId` + committed `generation` |
| Replica | realization on opaque `DeviceId` + replica `generation` |
| Lease | R / RW + `expectedGen` |
| Device/Node | capabilities + measured topology + backend ops |

**Smoke:** `UCF_BOUNCE_SMOKE=PASS`  
**Integration:** `UCF_NO_STALE_DISPATCH_001=PASS` — stale expected remains illegal even if a replica is resident.

**RW++:** expected N → acquire → execute → commit → N+1. Failed path does not publish.  
**Banked with:** `K2RainbowFoldTable.hpp`
