#!/usr/bin/env python3
# Create perfect test vector by working backwards from Circom

import json

# Circom's field
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

print("=== CREATING PERFECT CIRCOM TEST VECTOR ===")

G = (1, 2)

# Use very simple values
priv_key = 2  # Private key = 2
pub_key = scalar_mult(priv_key, G)  # Q = 2*G

msg_hash = 1  # z = 1

print(f"Private key d: {priv_key}")
print(f"Public key Q: {pub_key}")
print(f"Message hash z: {msg_hash}")

# Let's use k = 3 for signature generation
k = 3
R_point = scalar_mult(k, G)  # R = 3*G
r = R_point[0] % r_field

print(f"k: {k}")
print(f"R point: {R_point}")
print(f"r: {r}")

# Calculate s = k^(-1) * (z + r*d) mod r_field
s = (modinv(k) * (msg_hash + r * priv_key)) % r_field

print(f"s: {s}")

# Verification check
w = modinv(s)
u1 = (msg_hash * w) % r_field  # u1 = z * s^(-1)
u2 = (r * w) % r_field         # u2 = r * s^(-1)

print(f"w (s^-1): {w}")
print(f"u1 (z*w): {u1}")
print(f"u2 (r*w): {u2}")

# Verify: u1*G + u2*Q should give R
P1 = scalar_mult(u1, G)
P2 = scalar_mult(u2, pub_key)
R_verify = point_add(P1, P2)

print(f"P1 (u1*G): {P1}")
print(f"P2 (u2*Q): {P2}")
print(f"R_verify: {R_verify}")

if R_verify:
    rx_verify = R_verify[0] % r_field
    print(f"R_verify.x: {rx_verify}")
    print(f"Original r: {r}")
    print(f"Verification: {rx_verify == r}")
    
    if rx_verify == r:
        print("\n✅ PERFECT! Creating test vector...")
        
        # Calculate quotients
        zw = msg_hash * w
        q1 = zw // r_field
        k1 = zw % r_field
        
        rw = r * w
        q2 = rw // r_field  
        k2 = rw % r_field
        
        rx_full = R_verify[0]
        q3 = rx_full // r_field
        
        print(f"Debug - zw: {zw}")
        print(f"Debug - rw: {rw}")
        print(f"Debug - rx_full: {rx_full}")
        print(f"Quotients: q1={q1}, q2={q2}, q3={q3}")
        print(f"Remainders: k1={k1}, k2={k2}")
        print(f"Should match: u1={u1}, u2={u2}")
        
        # Verify public key is on curve
        qx, qy = pub_key
        lhs = (qy * qy) % r_field
        rhs = (qx * qx * qx + 3) % r_field
        print(f"Public key on curve: {lhs == rhs}")
        
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
        
        with open("perfect_test_vector.json", "w") as f:
            json.dump(output_data, f, indent=4)
        
        print("\n🎯 PERFECT test vector saved to: perfect_test_vector.json")
    else:
        print(f"\n❌ Verification failed: {rx_verify} ≠ {r}")
        # Let's see what went wrong
        print(f"Difference: {rx_verify - r}")
else:
    print("\n❌ R_verify is None")