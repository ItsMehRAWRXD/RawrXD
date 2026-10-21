# Qwen4Exp QSA indexer scoring: device execution evidence

The indexer scores the query against the compressed-key cache through a page
table, and only the visible compressed keys of a sequence take part. The
artifact had been compiled and statically checked and had never been run.

## The result

```
rows=5 index_heads=4 key_dim=8 page_size=4 compress_ratio=2 max_pages=3
max_abs_diff (finite) = 2.823601e-08
mask mismatches        = 0
visible-count mismatch  = 0

RESULT: PASS (the device reproduced the reference)
```

Device: AMD Radeon AI PRO R9700, Vulkan 1.4.357, with the validation layer
on for the whole run.

The masked columns are checked as well as the finite ones. A column outside
the visible window has to be an infinity of the same sign on both sides, and
the visible count per row has to match, because the window arithmetic is the
part of this kernel that a static check cannot speak to.

The inputs exercise the paths that matter: an invalid request, an invalid
page, a request whose visible window is shorter than the key count, and a
row whose position is at zero.

## What the run found

Two defects in the harness, both of which the validation layer named:

- **The barriers had no `sType`.** A `VkBufferMemoryBarrier` that is zeroed
  and not given its structure type is an invalid barrier, and the driver is
  given a structure it cannot interpret.
- **The barrier between the dispatch and the host's read was missing
  entirely.** Without it the read may see what was in the buffer before the
  shader wrote it, and the answer is a stale one. This is not theoretical:
  with the copy in place and the barrier out, the run reported 54 masked
  columns wrong and a largest difference of 1.17, against 2.82e-08 with the
  barrier in.

The release path faulted too, and it is worth recording because it is a
general hazard rather than a quirk of this shader:

**Releasing a host-visible buffer that the device has written to corrupts
the heap on this driver.** The device's cached copy of the buffer is written
back when the buffer is destroyed, and by then the host has been given the
memory back, so the write-back lands outside the allocation. The
`unmap -> destroy buffer -> free memory` sequence, and the destruction of
the device and the instance, both fault. Leaving the device and the instance
to the loader, which releases them when the process ends, is stable: ten
consecutive runs, all clean.

**The same hazard is live in the engine's own teardown**, wherever it frees
host-visible memory that the device has written to. It is worth an audit.

## What this does not establish

- It is not an executor binding. The runtime graph still refuses the QSA
  operator, and the model is still `NOT_CERTIFIED`.
- It covers the indexer scoring only. The compressed-key attention itself,
  the indexer projections and the norms are separate work.

## The gate

`Qwen4Exp_QsaScore_Device` runs the artifact and compares it against the
reference. A machine with no GPU is BLOCKED, never PASS.
