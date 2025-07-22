#!/usr/bin/env python3
# Corrected minimal test avoiding k=0 in scalar multiplication

import json

r_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def modinv(a):
    return pow(a, -1, r_field)

print("=== CORRECTED MINIMAL TEST ===")

# Use simple values but avoid k=0 in scalar multiplication
# Private key = 1, Q = G  
# Message hash = 1 (not 0)
priv_key = 1
pub_key = (1, 2)  # Q = G
msg_hash = 1      # z = 1 

print(f"Private key: {priv_key}")
print(f"Public key: {pub_key}")  
print(f"Message hash: {msg_hash}")

# Use k = 2 for signature
# R = 2*G, we know 2*G from earlier calculations
# From our previous debug: 2*G = (9576106..., 3762041...)
k = 2
r = 9576106256429682909732802513550057851239909425182015025367964331626916216831  # 2*G x-coordinate

# s = k^(-1) * (z + r*d) = 2^(-1) * (1 + r*1) = (1 + r) / 2
s = (modinv(k) * (msg_hash + r * priv_key)) % r_field

print(f"k: {k}")
print(f"r: {r}")  
print(f"s: {s}")

# Verification:
# w = s^(-1)
# u1 = z*w = 1*w = w
# u2 = r*w
# Verify: u1*G + u2*Q = w*G + r*w*G = w*(1+r)*G = w*s*k*G = k*G = 2*G ✓

w = modinv(s)
u1 = (msg_hash * w) % r_field
u2 = (r * w) % r_field

print(f"w: {w}")
print(f"u1: {u1}")
print(f"u2: {u2}")

print("Expected verification: u1*G + u2*G should equal 2*G")
print(f"u1 + u2 = {(u1 + u2) % r_field} (should equal 2)")

# Calculate quotients
zw = msg_hash * w
q1 = zw // r_field
k1 = zw % r_field

rw = r * w
q2 = rw // r_field
k2 = rw % r_field

# q3: Since we expect R.x = r, and r < r_field, q3 should be 0
q3 = 0

print(f"Quotients: q1={q1}, q2={q2}, q3={q3}")
print(f"Remainders: k1={k1}, k2={k2}")
print(f"Should equal: u1={u1}, u2={u2}")

# Verify remainders match u-values
print(f"k1 == u1: {k1 == u1}")
print(f"k2 == u2: {k2 == u2}")

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

with open("corrected_minimal.json", "w") as f:
    json.dump(output_data, f, indent=4)

print("\n🎯 Corrected minimal test saved to: corrected_minimal.json")
print("Key insight: Avoided k=0 in scalar multiplication!")
print(f"Verification check: u1+u2 = {(u1+u2)%r_field} (since Q=G, this should equal k=2)")