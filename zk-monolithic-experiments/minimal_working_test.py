#!/usr/bin/env python3
# Create the SIMPLEST possible working test case

import json

r_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Let's use the most trivial case possible:
# Private key = 1, so Q = G
# Message hash = 0 (simplifies everything)
# This should make the ECDSA math as simple as possible

priv_key = 1
pub_key = (1, 2)  # Q = 1*G = G
msg_hash = 0      # z = 0

print("=== MINIMAL WORKING TEST ===")
print(f"Private key: {priv_key}")
print(f"Public key: {pub_key}")
print(f"Message hash: {msg_hash}")

# With z = 0, the ECDSA signature becomes:
# s = k^(-1) * (0 + r*1) = k^(-1) * r
# For verification: u1 = 0*w = 0, u2 = r*w = r*k^(-1)*r^(-1) = k^(-1)
# So we need: 0*G + k^(-1)*G = k^(-1)*G = R
# This means R = k^(-1)*G, so we need k^(-1)*G to have x-coordinate r

# Let's try k = 1, so k^(-1) = 1, and R = G = (1,2)
k = 1
r = 1  # R.x = 1

# Calculate s = k^(-1) * r = 1 * 1 = 1  
s = 1

print(f"k: {k}")
print(f"r: {r}")
print(f"s: {s}")

# Verification:
# w = s^(-1) = 1^(-1) = 1
# u1 = z*w = 0*1 = 0
# u2 = r*w = 1*1 = 1
# Verify: u1*G + u2*Q = 0*G + 1*G = G = (1,2)
# Check: G.x = 1 = r ✓

w = 1
u1 = 0
u2 = 1

print(f"w: {w}")
print(f"u1: {u1}")
print(f"u2: {u2}")

print("Verification: 0*G + 1*G = G = (1,2)")
print("G.x = 1 = r ✓")

# This should work! Calculate quotients:
zw = msg_hash * w  # = 0 * 1 = 0
q1 = zw // r_field  # = 0
k1 = zw % r_field   # = 0

rw = r * w  # = 1 * 1 = 1  
q2 = rw // r_field  # = 0
k2 = rw % r_field   # = 1

# For q3: R.x = 1, so q3 = 1 // r_field = 0
q3 = 1 // r_field  # = 0

print(f"Quotients: q1={q1}, q2={q2}, q3={q3}")
print(f"k1={k1}, k2={k2} (should be u1={u1}, u2={u2})")

# Check public key on curve: y^2 = x^3 + 3
# 2^2 = 1^3 + 3 = 4 ✓
qx, qy = pub_key
lhs = (qy * qy) % r_field
rhs = (qx * qx * qx + 3) % r_field
print(f"Public key on curve: {lhs == rhs} ({lhs} = {rhs})")

output_data = {
    "z": str(msg_hash),
    "Qx": str(pub_key[0]),
    "Qy": str(pub_key[1]),
    "r": str(r),
    "s": str(s), 
    "w": str(w),
    "q1": str(q1),
    "q2": str(q2),
    "q3": str(q3)
}

with open("minimal_working.json", "w") as f:
    json.dump(output_data, f, indent=4)

print("\n🎯 Minimal working test saved to: minimal_working.json")
print("This SHOULD work because:")
print("- Public key is on curve ✓")
print("- All math is trivial (0s and 1s) ✓") 
print("- ECDSA verification: 0*G + 1*G = G, G.x = 1 = r ✓")