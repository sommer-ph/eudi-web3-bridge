#!/usr/bin/env python3
# Fixed BN254.py that uses ONLY Circom's scalar field

import hashlib
import hmac
import secrets
import json

# CRITICAL: Use only the scalar field that Circom uses!
circom_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # r

# Generator point (same values, but arithmetic in circom_field)
Gx = 1
Gy = 2

print("Using Circom's scalar field for ALL operations:")
print(f"Field modulus: {circom_field}")

def modinv(a, modulus):
    return pow(a, -1, modulus)

def point_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    
    x1, y1 = P1
    x2, y2 = P2
    
    if (x1 % circom_field) == (x2 % circom_field):
        if (y1 % circom_field) == (y2 % circom_field):
            # Point doubling
            s = (3 * x1 * x1 * modinv(2 * y1, circom_field)) % circom_field
        else:
            return None
    else:
        # Point addition
        s = ((y2 - y1) * modinv(x2 - x1, circom_field)) % circom_field
    
    x3 = (s * s - x1 - x2) % circom_field
    y3 = (s * (x1 - x3) - y1) % circom_field
    return (x3, y3)

def scalar_mult(k, P):
    if k == 0: return None
    result = None
    addend = P
    k = k % circom_field
    
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    
    return result

def generate_k(priv_key, msg_hash):
    # Simple deterministic k for testing
    return (priv_key + msg_hash + 12345) % circom_field

def ecdsa_sign(priv_key, msg_hash):
    k = generate_k(priv_key, msg_hash)
    if k == 0: k = 1
    
    R = scalar_mult(k, (Gx, Gy))
    if R is None:
        raise ValueError("R is point at infinity")
        
    r = R[0] % circom_field
    if r == 0:
        raise ValueError("r is zero")
    
    s = (modinv(k, circom_field) * (msg_hash + r * priv_key)) % circom_field
    if s == 0:
        raise ValueError("s is zero")
    
    return (r, s)

def ecdsa_verify(pub_key, msg_hash, sig):
    r, s = sig
    if r >= circom_field or s >= circom_field or r == 0 or s == 0:
        return False
    
    try:
        w = modinv(s, circom_field)
        u1 = (msg_hash * w) % circom_field
        u2 = (r * w) % circom_field
        P1 = scalar_mult(u1, (Gx, Gy))
        P2 = scalar_mult(u2, pub_key)
        P = point_add(P1, P2)
        if P is None:
            return False
        return (P[0] % circom_field) == r
    except:
        return False

# Generate test data
priv_key = 12345678901234567890  # Fixed for reproducibility
pub_key = scalar_mult(priv_key, (Gx, Gy))

msg = b"ECDSA over Circom scalar field"
msg_hash = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % circom_field

print(f"Private key: {priv_key}")
print(f"Public key: {pub_key}")
print(f"Message hash: {msg_hash}")

# Verify public key is on curve (in circom_field)
if pub_key:
    qx, qy = pub_key
    lhs = (qy * qy) % circom_field
    rhs = (qx * qx * qx + 3) % circom_field
    print(f"Public key on curve: {lhs == rhs}")

try:
    # Sign message
    r, s = ecdsa_sign(priv_key, msg_hash)
    print(f"Signature: r={r}, s={s}")
    
    # Prepare witness data
    w = modinv(s, circom_field)
    
    # Calculate quotients (same logic as original)
    zw = msg_hash * w
    q1 = zw // circom_field
    k1 = zw % circom_field
    
    rw = r * w
    q2 = rw // circom_field  
    k2 = rw % circom_field
    
    # Final verification
    P1 = scalar_mult(k1, (Gx, Gy))
    P2 = scalar_mult(k2, pub_key)
    R_final = point_add(P1, P2)
    
    if R_final:
        Rx_full = R_final[0]
        q3 = Rx_full // circom_field
        rx_mod = Rx_full % circom_field
        print(f"Final verification: R.x mod field = {rx_mod}, r = {r}")
        print(f"Match: {rx_mod == r}")
    else:
        q3 = 0
        print("R_final is None!")
    
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
    
    with open("circom_fixed_output.json", "w") as f:
        json.dump(output_data, f, indent=4)
    
    # Verify signature
    valid = ecdsa_verify(pub_key, msg_hash, (r, s))
    print(f"ECDSA verification: {valid}")
    
    print("\n✅ Circom-compatible data generated!")
    print("Output saved to: circom_fixed_output.json")
    
except ValueError as e:
    print(f"Error: {e}")