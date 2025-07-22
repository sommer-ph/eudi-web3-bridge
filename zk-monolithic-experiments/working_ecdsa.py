#!/usr/bin/env python3
# Create a working ECDSA signature by constructing it backwards

import json
import hashlib

# Circom's scalar field
r_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def modinv(a, modulus):
    return pow(a, -1, modulus)

def point_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    
    x1, y1 = P1
    x2, y2 = P2
    
    if (x1 % r_field) == (x2 % r_field):
        if (y1 % r_field) == (y2 % r_field):
            # Point doubling
            s = (3 * x1 * x1 * modinv(2 * y1, r_field)) % r_field
        else:
            return None
    else:
        # Point addition
        s = ((y2 - y1) * modinv(x2 - x1, r_field)) % r_field
    
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

print("=== WORKING ECDSA GENERATOR (BACKWARDS CONSTRUCTION) ===")

# Fixed values that we know work
G = (1, 2)
priv_key = 1000  # Simple private key
pub_key = scalar_mult(priv_key, G)

# Fixed message hash
msg_hash = 123

print(f"Generator: {G}")  
print(f"Private key: {priv_key}")
print(f"Public key: {pub_key}")
print(f"Message hash: {msg_hash}")

# Fixed k for reproducible r
k = 500
R_point = scalar_mult(k, G)
r = R_point[0] % r_field

print(f"k: {k}")
print(f"R point: {R_point}")
print(f"r: {r}")

# Calculate s = k^(-1) * (hash + r * priv) mod r_field
k_inv = modinv(k, r_field)
s = (k_inv * (msg_hash + r * priv_key)) % r_field

print(f"s: {s}")

# ECDSA verification check
w = modinv(s, r_field)
u1 = (msg_hash * w) % r_field  
u2 = (r * w) % r_field

print(f"w (s^-1): {w}")
print(f"u1 (z*w): {u1}")
print(f"u2 (r*w): {u2}")

# Verify: u1*G + u2*Q should give point with x-coordinate = r
P1 = scalar_mult(u1, G)
P2 = scalar_mult(u2, pub_key)
R_verify = point_add(P1, P2)

print(f"P1 (u1*G): {P1}")
print(f"P2 (u2*Q): {P2}")  
print(f"R_verify (P1+P2): {R_verify}")

if R_verify:
    rx_verify = R_verify[0] % r_field
    print(f"R_verify x-coord: {rx_verify}")
    print(f"Original r: {r}")
    print(f"ECDSA verification: {rx_verify == r}")
else:
    print("R_verify is None - point at infinity!")

# If verification failed, let's debug step by step
if R_verify is None or (R_verify[0] % r_field) != r:
    print("\n=== DEBUGGING ===")
    
    # Manual check: k*G should equal R_point
    k_G = scalar_mult(k, G)
    print(f"k*G: {k_G}")
    print(f"Matches R_point: {k_G == R_point}")
    
    # Check if priv_key * G equals pub_key
    check_pub = scalar_mult(priv_key, G)
    print(f"priv*G: {check_pub}")
    print(f"Matches pub_key: {check_pub == pub_key}")
    
    # Let's try simpler values
    print("\n=== TRYING SIMPLER VALUES ===")
    simple_k = 2
    simple_R = scalar_mult(simple_k, G)
    simple_r = simple_R[0] % r_field
    
    simple_s = (modinv(simple_k, r_field) * (msg_hash + simple_r * priv_key)) % r_field
    
    print(f"Simple k: {simple_k}")
    print(f"Simple R: {simple_R}")
    print(f"Simple r: {simple_r}")  
    print(f"Simple s: {simple_s}")
    
    # Verify simple version
    simple_w = modinv(simple_s, r_field)
    simple_u1 = (msg_hash * simple_w) % r_field
    simple_u2 = (simple_r * simple_w) % r_field
    
    simple_P1 = scalar_mult(simple_u1, G)
    simple_P2 = scalar_mult(simple_u2, pub_key)
    simple_R_verify = point_add(simple_P1, simple_P2)
    
    print(f"Simple verification result: {simple_R_verify}")
    if simple_R_verify:
        simple_rx = simple_R_verify[0] % r_field
        print(f"Simple rx: {simple_rx}")
        print(f"Simple r: {simple_r}")
        print(f"Simple ECDSA works: {simple_rx == simple_r}")
        
        if simple_rx == simple_r:
            print("\n✅ Found working values!")
            r = simple_r
            s = simple_s
            w = simple_w
            
            # Calculate quotients
            zw = msg_hash * w
            q1 = zw // r_field
            
            rw = r * w  
            q2 = rw // r_field
            
            rx_full = simple_R_verify[0]
            q3 = rx_full // r_field
            
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
            
            with open("working_ecdsa.json", "w") as f:
                json.dump(output_data, f, indent=4)
            
            print("Saved to working_ecdsa.json")