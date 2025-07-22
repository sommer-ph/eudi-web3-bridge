#!/usr/bin/env python3
# Generate ECDSA data that exactly matches Circom's logic

import json
import hashlib
import secrets

# Circom uses scalar field for ALL arithmetic (this is the key insight!)
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # scalar field (curve order)

print("=== FINAL CIRCOM-COMPATIBLE ECDSA GENERATOR ===")
print(f"Using field modulus (r): {r}")
print()

def modinv(a, modulus):
    return pow(a, -1, modulus)

def point_add(P1, P2):
    """Point addition - exactly like Circom's PointAdd template"""
    if P1 is None: return P2
    if P2 is None: return P1
    
    x1, y1 = P1
    x2, y2 = P2
    
    # Handle point doubling
    if (x1 % r) == (x2 % r):
        if (y1 % r) == (y2 % r):
            # Point doubling: lambda = (3*x^2) / (2*y)
            numerator = (3 * x1 * x1) % r
            denominator = (2 * y1) % r
            if denominator == 0:
                return None  # Point at infinity
            lambda_val = (numerator * modinv(denominator, r)) % r
        else:
            return None  # Point at infinity
    else:
        # Point addition: lambda = (y2-y1) / (x2-x1)
        numerator = (y2 - y1) % r
        denominator = (x2 - x1) % r
        if denominator == 0:
            return None  # Should not happen if x1 != x2
        lambda_val = (numerator * modinv(denominator, r)) % r
    
    # Calculate result: x3 = lambda^2 - x1 - x2, y3 = lambda*(x1-x3) - y1
    lambda_sq = (lambda_val * lambda_val) % r
    x3 = (lambda_sq - x1 - x2) % r
    y3 = (lambda_val * (x1 - x3) - y1) % r
    
    return (x3, y3)

def scalar_mult(k, P):
    """Scalar multiplication using double-and-add"""
    if k == 0: return None
    if k == 1: return P
    
    # Ensure k is in field range
    k = k % r
    if k == 0: return None
    
    result = None
    addend = P
    
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    
    return result

# Generator point
G = (1, 2)

# Verify generator is on curve: y^2 = x^3 + 3 (in scalar field)
gx, gy = G
lhs = (gy * gy) % r
rhs = (gx * gx * gx + 3) % r
print(f"Generator on curve check: {lhs == rhs} (LHS: {lhs}, RHS: {rhs})")

# Generate a simple private key
priv_key = 123456789  # Use fixed value for reproducible testing
print(f"Private key: {priv_key}")

# Generate public key
pub_key = scalar_mult(priv_key, G)
print(f"Public key: {pub_key}")

if pub_key:
    qx, qy = pub_key
    # Verify public key is on curve
    lhs = (qy * qy) % r
    rhs = (qx * qx * qx + 3) % r
    print(f"Public key on curve: {lhs == rhs}")

# Simple message hash
msg_hash = 987654321
print(f"Message hash: {msg_hash}")

# Generate signature
k = 111111111  # Fixed nonce for reproducible testing
R = scalar_mult(k, G)
if R is None:
    raise ValueError("R is point at infinity")

r_val = R[0] % r
if r_val == 0:
    raise ValueError("r is zero")

# s = k^(-1) * (hash + r * priv_key) mod r
s_val = (modinv(k, r) * (msg_hash + r_val * priv_key)) % r
if s_val == 0:
    raise ValueError("s is zero")

print(f"Signature: r={r_val}, s={s_val}")

# ECDSA verification (to ensure our signature is correct)
# u1 = hash * s^(-1) mod r
# u2 = r * s^(-1) mod r  
# R = u1*G + u2*Q
w = modinv(s_val, r)
u1 = (msg_hash * w) % r
u2 = (r_val * w) % r

P1 = scalar_mult(u1, G)
P2 = scalar_mult(u2, pub_key)
R_verify = point_add(P1, P2)

verification_ok = R_verify is not None and (R_verify[0] % r) == r_val
print(f"ECDSA verification in Python: {verification_ok}")

if not verification_ok:
    print(f"DEBUG: R_verify = {R_verify}")
    if R_verify:
        print(f"DEBUG: R_verify[0] % r = {R_verify[0] % r}")
        print(f"DEBUG: r_val = {r_val}")

# Prepare witness data for Circom (quotients for big number arithmetic)
# u1 = z * w mod n (but we need quotient q1 for z*w/n)
zw = msg_hash * w
q1 = zw // r  # quotient
k1 = zw % r   # remainder (should equal u1)

# u2 = r * w mod n (but we need quotient q2 for r*w/n)  
rw = r_val * w
q2 = rw // r  # quotient
k2 = rw % r   # remainder (should equal u2)

# For final verification: R.x mod n (quotient q3 for R.x/n)
if R_verify:
    rx_full = R_verify[0]
    q3 = rx_full // r
    rx_mod = rx_full % r
else:
    q3 = 0
    rx_mod = 0

print(f"Quotients: q1={q1}, q2={q2}, q3={q3}")
print(f"u1={u1}, k1={k1} (should be equal: {u1 == k1})")
print(f"u2={u2}, k2={k2} (should be equal: {u2 == k2})")

# Final output for Circom
output_data = {
    "z": str(msg_hash),
    "Qx": str(pub_key[0]),
    "Qy": str(pub_key[1]),
    "r": str(r_val),
    "s": str(s_val),
    "w": str(w),
    "q1": str(q1),
    "q2": str(q2),
    "q3": str(q3)
}

with open("final_ecdsa_data.json", "w") as f:
    json.dump(output_data, f, indent=4)

print("\n✅ Final ECDSA data generated!")
print("Output saved to: final_ecdsa_data.json")