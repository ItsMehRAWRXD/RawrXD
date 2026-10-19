# Reference-only model to validate the integer policy concept.
# Not a product dependency.

def matched_share1(cost0, cost1):
    return cost0 / (cost0 + cost1)

for ratio in (2.0, 3.0, 4.0, 5.0):
    s1 = matched_share1(1.0, ratio)
    print(f"GPU1 cost ratio={ratio:0.1f}x -> GPU0/GPU1={100*(1-s1):0.2f}/{100*s1:0.2f}")

# Affine example showing how an apparent 2x per-row slope can still prefer ~80/20
# when GPU1 has additional fixed per-launch/tail cost.
def affine_best(total_rows, c0, c1, f0, f1):
    best = None
    for r1 in range(1, total_rows):
        r0 = total_rows-r1
        t0 = f0 + c0*r0
        t1 = f1 + c1*r1
        crit = max(t0,t1)
        if best is None or crit < best[0]:
            best = (crit,r0,r1,t0,t1)
    return best

print("affine example:", affine_best(1000, 1.0, 2.0, 0.0, 400.0))
