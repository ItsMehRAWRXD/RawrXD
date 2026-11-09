# Materialization progress

| Sample | Files on disk | Materialized bytes |
|---|---:|---:|
| T0 01:38:36 | 208,185 | 8,176,100,436 |
| T60 01:39:40 | 248,821 | 8,837,283,505 |
| T60 01:39:46 | 259,371 | 9,096,555,251 |
| T120 01:40:54 | 301,818 | 11,003,031,523 |

The file count and byte total increased during both observation intervals, demonstrating actual filesystem materialization rather than CPU-only activity.

