#!/usr/bin/env python3
# FINAL working BN254.py that matches Circom exactly

import hashlib
import hmac
import secrets
import json

# CORRECT BN254 parameters that match Circom exactly  
r_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # scalar field = curve order
p_field = 21888242871839275222246405745257275088696311157297823662689037894645226208583  # base field

# CRITICAL: For Circom compatibility, use scalar field for ALL arithmetic
group_order = r_field
field_modulus = r_field  # This is the key fix!

# Generator point
G = (1, 2)

print(f"Using field modulus: {field_modulus}")
print(f"Using group order: {group_order}")
print(f"Generator: {G}")

def modinv(a, modulus):
    return pow(a, -1, modulus)

def point_add(P1, P2):
    """Point addition exactly as Circom does it"""
    if P1 is None: return P2
    if P2 is None: return P1
    
    x1, y1 = P1
    x2, y2 = P2
    
    # Check for point doubling case
    if (x1 % field_modulus) == (x2 % field_modulus):
        if (y1 % field_modulus) == (y2 % field_modulus):
            # Point doubling
            numerator = (3 * x1 * x1) % field_modulus
            denominator = (2 * y1) % field_modulus
            if denominator == 0:
                return None  # Point at infinity
            s = (numerator * modinv(denominator, field_modulus)) % field_modulus
        else:
            return None  # Point at infinity
    else:
        # Point addition
        numerator = (y2 - y1) % field_modulus
        denominator = (x2 - x1) % field_modulus
        s = (numerator * modinv(denominator, field_modulus)) % field_modulus
    
    # Calculate result
    x3 = (s * s - x1 - x2) % field_modulus
    y3 = (s * (x1 - x3) - y1) % field_modulus
    return (x3, y3)

def scalar_mult(k, P):
    """Scalar multiplication using double-and-add"""
    if k == 0: return None
    result = None
    addend = P
    k = k % group_order
    
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    
    return result

def generate_k(priv_key, msg_hash):
    """Simple deterministic k generation"""
    return ((priv_key + msg_hash + 12345) % group_order) + 1  # Ensure k > 0

def ecdsa_sign(priv_key, msg_hash):
    """ECDSA signature generation"""
    k = generate_k(priv_key, msg_hash)
    
    R = scalar_mult(k, G)
    if R is None:
        raise ValueError("R is point at infinity")
        
    r = R[0] % group_order
    if r == 0:
        raise ValueError("r is zero")
    
    s = (modinv(k, group_order) * (msg_hash + r * priv_key)) % group_order
    if s == 0:
        raise ValueError("s is zero")
    
    return (r, s)

def ecdsa_verify(pub_key, msg_hash, sig):
    """ECDSA verification"""
    r, s = sig
    if r >= group_order or s >= group_order or r == 0 or s == 0:
        return False
    
    try:
        w = modinv(s, group_order)
        u1 = (msg_hash * w) % group_order
        u2 = (r * w) % group_order
        P1 = scalar_mult(u1, G)
        P2 = scalar_mult(u2, pub_key)
        P = point_add(P1, P2)
        if P is None:
            return False
        return (P[0] % group_order) == r
    except:
        return False

# Generate example with known working values
priv_key = 1337  # Use a different private key to avoid edge cases
pub_key = scalar_mult(priv_key, G)

msg = b"Final BN254 ECDSA test for Circom"
msg_hash = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % group_order

print(f"Private key: {priv_key}")
print(f"Public key: {pub_key}")
print(f"Message hash: {msg_hash}")

# Verify public key is on curve
if pub_key:
    qx, qy = pub_key
    lhs = (qy * qy) % field_modulus
    rhs = (qx * qx * qx + 3) % field_modulus
    print(f"Public key on curve: {lhs == rhs}")

try:
    # Generate signature
    r, s = ecdsa_sign(priv_key, msg_hash)
    print(f"Signature: r={r}, s={s}")
    
    # Prepare witness data exactly as original script
    w = modinv(s, group_order)
    
    # Calculate quotients for big number arithmetic
    zw = msg_hash * w
    q1 = zw // group_order
    k1 = zw - q1 * group_order
    
    rw = r * w
    q2 = rw // group_order
    k2 = rw - q2 * group_order
    
    # Verification step to get q3
    P1 = scalar_mult(k1, G)
    P2 = scalar_mult(k2, pub_key)
    R_circ = point_add(P1, P2)
    
    if R_circ:
        Rx_full = R_circ[0]
        q3 = Rx_full // group_order
        rx_mod = Rx_full - q3 * group_order
        verification_result = (rx_mod == r)
        print(f"ECDSA verification: {verification_result}")
        print(f"rx_mod={rx_mod}, r={r}")
    else:
        q3 = 0
        verification_result = False
        print("R_circ is None - verification failed")
    
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
    
    # Save to file
    with open("final_bn254_output.json", "w") as f:
        json.dump(output_data, f, indent=4)
    
    # Also verify with standard ECDSA function
    standard_verify = ecdsa_verify(pub_key, msg_hash, (r, s))
    print(f"Standard ECDSA verification: {standard_verify}")
    
    print("\n✅ Final BN254 data generated!")
    print("Output saved to: final_bn254_output.json")
    
    if verification_result:
        print("🎯 This should work with Circom!")
    else:
        print("⚠️ Verification failed - may not work with Circom")

except ValueError as e:
    print(f"Error: {e}")