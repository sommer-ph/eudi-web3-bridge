#!/usr/bin/env python3
# Generate ECDSA data compatible with Circom's scalar field

import json
import hashlib
import secrets

# CIRCOM USES THE SCALAR FIELD MODULUS, NOT THE BASE FIELD!
circom_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # r (scalar field)
base_field = 21888242871839275222246405745257275088696311157297823662689037894645226208583   # p (base field)

print("=== CIRCOM-COMPATIBLE BN254 ECDSA GENERATOR ===")
print(f"Circom field (r): {circom_field}")
print(f"Base field (p):   {base_field}")
print()

def modinv(a, modulus):
    return pow(a, -1, modulus)

def point_add_circom(P1, P2):
    """Point addition using Circom's scalar field for ALL arithmetic"""
    if P1 is None: return P2
    if P2 is None: return P1
    
    x1, y1 = P1
    x2, y2 = P2
    
    if x1 == x2:
        if y1 == y2:
            # Point doubling - use circom_field for division
            s = (3 * x1 * x1 * modinv(2 * y1, circom_field)) % circom_field
        else:
            return None  # Point at infinity
    else:
        # Point addition - use circom_field for division
        s = ((y2 - y1) * modinv(x2 - x1, circom_field)) % circom_field
    
    # All arithmetic in circom_field
    x3 = (s * s - x1 - x2) % circom_field
    y3 = (s * (x1 - x3) - y1) % circom_field
    return (x3, y3)

def scalar_mult_circom(k, P):
    """Scalar multiplication using Circom's field for all operations"""
    if k == 0: return None
    if k == 1: return P
    
    result = None
    addend = P
    
    while k:
        if k & 1:
            result = point_add_circom(result, addend)
        addend = point_add_circom(addend, addend)  # double
        k >>= 1
    
    return result

# Generator point in Circom's field
G = (1, 2)

# Verify generator is on curve using Circom's field
gx, gy = G
circom_curve_check = (gy * gy) % circom_field == (gx * gx * gx + 3) % circom_field
print(f"Generator on curve (Circom field): {circom_curve_check}")

# Also check with base field for comparison
base_curve_check = (gy * gy) % base_field == (gx * gx * gx + 3) % base_field  
print(f"Generator on curve (Base field):   {base_curve_check}")
print()

# Generate private key (must be in scalar field range)
priv_key = secrets.randbelow(circom_field)
print(f"Private key: {priv_key}")

# Generate public key using Circom's arithmetic
pub_key = scalar_mult_circom(priv_key, G)
print(f"Public key: {pub_key}")

# Verify public key is on curve using Circom's field
if pub_key:
    qx, qy = pub_key
    lhs = (qy * qy) % circom_field
    rhs = (qx * qx * qx + 3) % circom_field
    print(f"Public key on curve (Circom field): {lhs == rhs}")
    print(f"LHS: {lhs}")
    print(f"RHS: {rhs}")

# Message hash (in scalar field range)
msg = b"Circom-compatible BN254 ECDSA test"
msg_hash = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % circom_field
print(f"Message hash: {msg_hash}")

# Generate signature using scalar field
k = secrets.randbelow(circom_field - 1) + 1
R = scalar_mult_circom(k, G)
r = R[0] % circom_field
if r == 0:
    raise ValueError("r is zero, retry")

s = (modinv(k, circom_field) * (msg_hash + r * priv_key)) % circom_field
if s == 0:
    raise ValueError("s is zero, retry")

print(f"Signature: r={r}, s={s}")

# Prepare witness data (all in Circom's scalar field)
w = modinv(s, circom_field)
zw = (msg_hash * w) % (circom_field * circom_field)
q1 = zw // circom_field
k1 = zw % circom_field

rw = (r * w) % (circom_field * circom_field)
q2 = rw // circom_field  
k2 = rw % circom_field

# Verify ECDSA using Circom's field
P1 = scalar_mult_circom(k1, G)
P2 = scalar_mult_circom(k2, pub_key)
R_check = point_add_circom(P1, P2)
q3 = R_check[0] // circom_field
rx_mod = R_check[0] % circom_field

print(f"ECDSA verification: {rx_mod == r}")

# Output for Circom
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

with open("circom_compatible_ecdsa.json", "w") as f:
    json.dump(output_data, f, indent=4)

print("✅ Circom-compatible ECDSA data generated!")
print("Output saved to: circom_compatible_ecdsa.json")