#!/usr/bin/env python3
# Generate correct BN254 ECDSA data compatible with Circom

import json
import hashlib
import secrets

# BN254 parameters (exact same as Circom uses)
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583  # field modulus
n = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # curve order

def modinv(a, modulus):
    return pow(a, -1, modulus)

def point_add(P1, P2):
    """Point addition on BN254 curve y^2 = x^3 + 3"""
    if P1 is None: return P2
    if P2 is None: return P1
    
    x1, y1 = P1
    x2, y2 = P2
    
    if x1 == x2:
        if y1 == y2:
            # Point doubling
            s = (3 * x1 * x1 * modinv(2 * y1, p)) % p
        else:
            return None  # Point at infinity
    else:
        # Point addition  
        s = ((y2 - y1) * modinv(x2 - x1, p)) % p
    
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k, P):
    """Scalar multiplication using double-and-add"""
    if k == 0: return None
    if k == 1: return P
    
    result = None
    addend = P
    
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)  # double
        k >>= 1
    
    return result

# BN254 generator point
G = (1, 2)

# Verify generator is on curve
gx, gy = G
assert (gy * gy) % p == (gx * gx * gx + 3) % p, "Generator not on curve!"

print("=== GENERATING CORRECT BN254 ECDSA DATA ===")

# Generate private key
priv_key = secrets.randbelow(n)
print(f"Private key: {priv_key}")

# Generate public key: Q = priv_key * G  
pub_key = scalar_mult(priv_key, G)
print(f"Public key: {pub_key}")

# Verify public key is on curve
qx, qy = pub_key
lhs = (qy * qy) % p
rhs = (qx * qx * qx + 3) % p
print(f"Public key on curve: {lhs == rhs}")

# Message hash
msg = b"Test message for BN254 ECDSA"
msg_hash = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % n
print(f"Message hash: {msg_hash}")

# Generate signature
k = secrets.randbelow(n - 1) + 1  # ensure k != 0
R = scalar_mult(k, G)
r = R[0] % n
if r == 0:
    raise ValueError("r is zero, retry")

s = (modinv(k, n) * (msg_hash + r * priv_key)) % n
if s == 0:
    raise ValueError("s is zero, retry")

print(f"Signature: r={r}, s={s}")

# Prepare witness data
w = modinv(s, n)
zw = (msg_hash * w) % (n * n)  # Allow overflow for quotient calculation
q1 = zw // n
k1 = zw % n

rw = (r * w) % (n * n)  # Allow overflow for quotient calculation  
q2 = rw // n
k2 = rw % n

# Verify ECDSA
P1 = scalar_mult(k1, G)
P2 = scalar_mult(k2, pub_key)
R_check = point_add(P1, P2)
q3 = R_check[0] // n
rx_mod = R_check[0] % n

print(f"ECDSA verification: {rx_mod == r}")

# Output data for Circom
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

with open("correct_ecdsa_output.json", "w") as f:
    json.dump(output_data, f, indent=4)

print("✅ Correct BN254 ECDSA data generated!")
print(f"Output saved to: correct_ecdsa_output.json")