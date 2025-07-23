#!/usr/bin/env python3
"""
ECDSA Test Vector with Different Points

This script creates ECDSA test vectors ensuring that u1*G and u2*Q are different points
to avoid the "PointAdd denominator zero error" that occurs when adding identical points
in elliptic curve arithmetic.

Problem: When u1*G and u2*Q have the same x-coordinate, the point addition in Circom
fails due to division by zero in the slope calculation.

Solution: Use different keys and parameters to ensure distinct intermediate points.
"""

import json

r_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def modinv(a):
    return pow(a, -1, r_field)

def point_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    
    x1, y1 = P1
    x2, y2 = P2
    
    if (x1 % r_field) == (x2 % r_field):
        if (y1 % r_field) == (y2 % r_field):
            s = (3 * x1 * x1 * modinv(2 * y1)) % r_field
        else:
            return None
    else:
        s = ((y2 - y1) * modinv(x2 - x1)) % r_field
    
    x3 = (s * s - x1 - x2) % r_field
    y3 = (s * (x1 - x3) - y1) % r_field
    return (x3, y3)

def scalar_mult(k, P):
    if k == 0: return None
    result = None
    addend = P
    k = k % r_field
    
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    
    return result

print("=== ECDSA WITH DIFFERENT POINTS ===")

G = (1, 2)

# Use different private key and public key to avoid Q = G
priv_key = 2  # d = 2
pub_key = scalar_mult(priv_key, G)  # Q = 2*G

print(f"Private key: {priv_key}")
print(f"Public key: {pub_key}")

# Use simple values 
msg_hash = 1  # z = 1
k = 3         # signature nonce
R = scalar_mult(k, G)  # R = 3*G  
r = R[0] % r_field

print(f"Message hash: {msg_hash}")
print(f"k: {k}, R: {R}")
print(f"r: {r}")

# Calculate s = k^(-1) * (z + r*d)
s = (modinv(k) * (msg_hash + r * priv_key)) % r_field

print(f"s: {s}")

# ECDSA verification
w = modinv(s)
u1 = (msg_hash * w) % r_field  # u1 = z * w
u2 = (r * w) % r_field         # u2 = r * w

print(f"w: {w}")
print(f"u1: {u1}")
print(f"u2: {u2}")

# Now u1*G and u2*Q should be DIFFERENT points
P1 = scalar_mult(u1, G)
P2 = scalar_mult(u2, pub_key)

print(f"P1 = u1*G = {P1}")
print(f"P2 = u2*Q = {P2}")

# Check if they're the same (this would cause the PointAdd error)
if P1 and P2 and P1[0] == P2[0]:
    print("ERROR: P1 and P2 have same x-coordinate!")
    print("This will cause the PointAdd denominator zero error")
else:
    print("GOOD: P1 and P2 have different x-coordinates")

# Verify ECDSA  
R_verify = point_add(P1, P2)
print(f"R_verify = P1 + P2 = {R_verify}")

if R_verify and R_verify[0] % r_field == r:
    print("ECDSA verification SUCCESS!")
    
    # Calculate quotients
    zw = msg_hash * w
    q1 = zw // r_field
    k1 = zw % r_field
    
    rw = r * w
    q2 = rw // r_field  
    k2 = rw % r_field
    
    q3 = R_verify[0] // r_field
    
    print(f"Quotients: q1={q1}, q2={q2}, q3={q3}")
    print(f"Remainders: k1={k1}, k2={k2}")
    
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
    
    with open("different_points.json", "w") as f:
        json.dump(output_data, f, indent=4)
    
    print("Saved working test vector to: different_points.json")
    
else:
    print(f"ECDSA verification FAILED!")
    if R_verify:
        print(f"R_verify.x = {R_verify[0] % r_field}, expected r = {r}")
    else:
        print("R_verify is None")