#!/usr/bin/env python3
"""
Generate mathematically correct ECDSA test vectors for BN254 curve
that work with Circom's field arithmetic.

The key insight is that for BN254 curve, the base field p and scalar field r
are the same value, but we need to be careful about which operations use which field.
"""

import json
import hashlib
import secrets

# BN254 curve parameters
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # Scalar field (order)
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583  # Base field

# Generator point G = (1, 2) - this is on the curve y^2 = x^3 + 3 (mod p)
G = (1, 2)

print(f"BN254 Curve Parameters:")
print(f"Scalar field r: {r}")
print(f"Base field p:   {p}")
print(f"Generator G:    {G}")

# Verify generator is on curve
def is_on_curve(point, field_mod):
    if point is None:
        return True  # Point at infinity
    x, y = point
    return (y * y) % field_mod == (x * x * x + 3) % field_mod

print(f"G on curve (mod p): {is_on_curve(G, p)}")

def modinv(a, modulus):
    """Modular inverse using extended Euclidean algorithm"""
    return pow(a, -1, modulus)

def point_add_bn254(P1, P2):
    """
    Add two points on BN254 curve y^2 = x^3 + 3
    Operations done in base field p
    """
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    
    x1, y1 = P1
    x2, y2 = P2
    
    # Check if points are the same or inverses
    if x1 == x2:
        if y1 == y2:
            # Point doubling
            if y1 == 0:
                return None  # Point at infinity
            s = (3 * x1 * x1 * modinv(2 * y1, p)) % p
        else:
            # Points are inverses
            return None  # Point at infinity
    else:
        # Point addition
        s = ((y2 - y1) * modinv((x2 - x1) % p, p)) % p
    
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    
    return (x3, y3)

def scalar_mult_bn254(k, P):
    """
    Scalar multiplication k * P on BN254 curve
    k is taken modulo r (scalar field)
    Point operations are in base field p
    """
    if k == 0:
        return None
    
    k = k % r
    if k == 0:
        return None
    
    result = None
    addend = P
    
    while k:
        if k & 1:
            result = point_add_bn254(result, addend)
        addend = point_add_bn254(addend, addend)
        k >>= 1
    
    return result

def ecdsa_sign_bn254(private_key, message_hash, k=None):
    """
    ECDSA signature generation for BN254
    """
    private_key = private_key % r
    message_hash = message_hash % r
    
    if k is None:
        # Generate random k
        k = secrets.randbelow(r - 1) + 1
    else:
        k = k % r
        if k == 0:
            k = 1
    
    # Calculate R = k * G
    R = scalar_mult_bn254(k, G)
    if R is None:
        raise ValueError("R is point at infinity")
    
    # r = R.x mod r (note: mod r, not mod p!)
    r_sig = R[0] % r
    if r_sig == 0:
        raise ValueError("r component is zero")
    
    # s = k^(-1) * (hash + r * private_key) mod r
    k_inv = modinv(k, r)
    s = (k_inv * (message_hash + r_sig * private_key)) % r
    if s == 0:
        raise ValueError("s component is zero")
    
    return (r_sig, s), R

def ecdsa_verify_bn254(public_key, message_hash, signature):
    """
    ECDSA signature verification for BN254
    """
    r_sig, s = signature
    
    # Check signature components are valid
    if not (1 <= r_sig < r and 1 <= s < r):
        return False
    
    # Verification steps
    try:
        w = modinv(s, r)
        u1 = (message_hash * w) % r
        u2 = (r_sig * w) % r
        
        # Calculate R' = u1*G + u2*Q
        P1 = scalar_mult_bn254(u1, G)
        P2 = scalar_mult_bn254(u2, public_key)
        R_prime = point_add_bn254(P1, P2)
        
        if R_prime is None:
            return False
        
        # Check if R'.x ≡ r (mod r)
        return (R_prime[0] % r) == r_sig
        
    except:
        return False

# Generate test vectors
print("\n=== Generating ECDSA Test Vectors ===")

# Test case 1: Simple values
private_key = 12345
public_key = scalar_mult_bn254(private_key, G)
message = b"Hello BN254 ECDSA"
message_hash = int.from_bytes(hashlib.sha256(message).digest(), 'big') % r

print(f"\nTest Vector 1:")
print(f"Private key d: {private_key}")
print(f"Public key Q: {public_key}")
print(f"Message hash z: {message_hash}")
print(f"Q on curve: {is_on_curve(public_key, p)}")

# Generate signature with fixed k for reproducibility
k = 54321
try:
    (r_sig, s), R = ecdsa_sign_bn254(private_key, message_hash, k)
    
    print(f"k: {k}")
    print(f"R point: {R}")
    print(f"Signature r: {r_sig}")
    print(f"Signature s: {s}")
    
    # Verify the signature
    is_valid = ecdsa_verify_bn254(public_key, message_hash, (r_sig, s))
    print(f"Signature valid: {is_valid}")
    
    if is_valid:
        # Calculate verification components for Circom
        w = modinv(s, r)
        u1 = (message_hash * w) % r
        u2 = (r_sig * w) % r
        
        # Calculate quotients for Circom witness
        zw = message_hash * w
        q1 = zw // r
        k1 = zw % r
        
        rw = r_sig * w  
        q2 = rw // r
        k2 = rw % r
        
        # Verify u1 = k1 and u2 = k2
        print(f"\nVerification components:")
        print(f"w = s^(-1) mod r: {w}")
        print(f"u1 = z*w mod r: {u1} (should equal k1: {k1})")
        print(f"u2 = r*w mod r: {u2} (should equal k2: {k2})")
        
        # Calculate final R point
        P1 = scalar_mult_bn254(u1, G)
        P2 = scalar_mult_bn254(u2, public_key)
        R_verify = point_add_bn254(P1, P2)
        
        print(f"\nFinal verification:")
        print(f"u1*G: {P1}")
        print(f"u2*Q: {P2}")
        print(f"R_verify: {R_verify}")
        
        if R_verify:
            rx_verify = R_verify[0] % r
            print(f"R_verify.x mod r: {rx_verify}")
            print(f"Original r: {r_sig}")
            print(f"Match: {rx_verify == r_sig}")
            
            # q3 for R.x quotient
            q3 = R_verify[0] // r
            
            # Create test vector output
            test_vector = {
                "description": "BN254 ECDSA test vector with verification",
                "curve": "BN254 (alt_bn128)",
                "generator": {"x": str(G[0]), "y": str(G[1])},
                "scalar_field_r": str(r),
                "base_field_p": str(p),
                "private_key_d": str(private_key),
                "public_key_Q": {"x": str(public_key[0]), "y": str(public_key[1])},
                "message": message.decode(),
                "message_hash_z": str(message_hash),
                "signature": {"r": str(r_sig), "s": str(s)},
                "verification": {
                    "w": str(w),
                    "u1": str(u1),
                    "u2": str(u2),
                    "R_verify": {"x": str(R_verify[0]), "y": str(R_verify[1])},
                    "verification_passes": rx_verify == r_sig
                },
                "circom_witness": {
                    "z": str(message_hash),
                    "Qx": str(public_key[0]),
                    "Qy": str(public_key[1]),
                    "r": str(r_sig),
                    "s": str(s),
                    "w": str(w),
                    "q1": str(q1),
                    "q2": str(q2), 
                    "q3": str(q3)
                }
            }
            
            # Save to file
            with open("bn254_ecdsa_test_vectors.json", "w") as f:
                json.dump(test_vector, f, indent=4)
            
            print(f"\n✅ Valid ECDSA test vector generated!")
            print("Saved to: bn254_ecdsa_test_vectors.json")
            
        else:
            print("❌ R_verify is None")
    else:
        print("❌ Signature verification failed")

except Exception as e:
    print(f"❌ Error generating signature: {e}")

# Test case 2: Edge case with minimal values
print(f"\n=== Test Vector 2: Minimal Values ===")
private_key_2 = 1
public_key_2 = scalar_mult_bn254(private_key_2, G)  # Should be G itself
message_hash_2 = 1

print(f"Private key: {private_key_2}")
print(f"Public key: {public_key_2}")
print(f"Message hash: {message_hash_2}")

k2 = 2
try:
    (r_sig_2, s_2), R_2 = ecdsa_sign_bn254(private_key_2, message_hash_2, k2)
    is_valid_2 = ecdsa_verify_bn254(public_key_2, message_hash_2, (r_sig_2, s_2))
    
    print(f"k: {k2}")
    print(f"R: {R_2}")
    print(f"Signature: r={r_sig_2}, s={s_2}")
    print(f"Valid: {is_valid_2}")
    
    if is_valid_2:
        print("✅ Minimal value test vector also works!")
        
        # Save minimal test vector too
        w_2 = modinv(s_2, r)
        test_vector_2 = {
            "description": "BN254 ECDSA minimal test vector",
            "private_key_d": str(private_key_2),
            "public_key_Q": {"x": str(public_key_2[0]), "y": str(public_key_2[1])},
            "message_hash_z": str(message_hash_2),
            "signature": {"r": str(r_sig_2), "s": str(s_2)},
            "circom_witness": {
                "z": str(message_hash_2),
                "Qx": str(public_key_2[0]),
                "Qy": str(public_key_2[1]),
                "r": str(r_sig_2),
                "s": str(s_2),
                "w": str(w_2),
                "q1": str((message_hash_2 * w_2) // r),
                "q2": str((r_sig_2 * w_2) // r),
                "q3": "0"  # Assuming R.x < r for this case
            }
        }
        
        with open("bn254_ecdsa_minimal_vectors.json", "w") as f:
            json.dump(test_vector_2, f, indent=4)
        
        print("Saved minimal vectors to: bn254_ecdsa_minimal_vectors.json")
    
except Exception as e:
    print(f"❌ Error with minimal values: {e}")