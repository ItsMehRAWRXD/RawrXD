# RAWRXD_DUALSTICK_PARALLEL_DEVICE_PARTIAL_001

No-dependency C++17 production source drop based on RawrXD seal `9c4213e679`.

Purpose: close the post-reuse kernel-throughput hold without reopening `DUALSTICK_REUSE_MICROFIX_001`.

The standalone core proves orchestration semantics only: concurrent stick workers, exact selected/executed parity, on-device weighted partial contract, at-most-two-vector D2H join, abort-on-worker-failure, and mock/product authority separation.

The RawrXD bind notes deliberately fail closed on the missing live backend primitive: pinned-weight DeviceBuf dispatch plus weighted device accumulation. Until that is wired and measured in the product binary, `PRODUCT_BACKEND_ATTESTED=0`, `TPS_PERFORMANCE_AUTHORITY=0`, `TARGET_35_50_TPS=UNMINTED`, `PROMOTE=0`.
