#!/usr/bin/env python3
# Debugging script to test BN254 parameters without py_ecc

# Standard BN254 parameters (from EIP-196)
field_modulus = 21888242871839275222246405745257275088696311157297823662689037894645226208583  # p
curve_order = 21888242871839275222246405745257275088548364400416034343698204186575808495617    # n

# Generator point
Gx = 1
Gy = 2

# Test data from ecdsa_output.json
Qx = 771952510784686338371105103952085307171761135211179360017669456556751830174
Qy = 11450033698498394626944063293282180303917624860478735314946199646092515329384

print("=== BN254 PARAMETER ANALYSE ===")
print(f"Field Modulus (p): {field_modulus}")
print(f"Curve Order (n):   {curve_order}")
print(f"Generator: ({Gx}, {Gy})")
print()

print("=== POINT ON CURVE TEST ===")
print(f"Test Point: ({Qx}, {Qy})")
print()

# Test mit Field Modulus (korrekt für Kurven-Arithmetik)
lhs = (Qy * Qy) % field_modulus
x_sq = (Qx * Qx) % field_modulus  
x_cu = (x_sq * Qx) % field_modulus
rhs = (x_cu + 3) % field_modulus

print(f"Mit Field Modulus p = {field_modulus}:")
print(f"LHS (y^2 mod p) = {lhs}")
print(f"RHS (x^3+3 mod p) = {rhs}")
print(f"Point on curve: {lhs == rhs}")
print()

# Test mit Curve Order (falsch für Kurven-Arithmetik)
lhs2 = (Qy * Qy) % curve_order
x_sq2 = (Qx * Qx) % curve_order  
x_cu2 = (x_sq2 * Qx) % curve_order
rhs2 = (x_cu2 + 3) % curve_order

print(f"Mit Curve Order n = {curve_order}:")
print(f"LHS (y^2 mod n) = {lhs2}")
print(f"RHS (x^3+3 mod n) = {rhs2}")
print(f"Point on curve: {lhs2 == rhs2}")
print()

# Test Generator point
print("=== GENERATOR TEST ===")
gen_lhs = (Gy * Gy) % field_modulus
gen_rhs = (Gx * Gx * Gx + 3) % field_modulus
print(f"Generator ({Gx}, {Gy}) on curve: {gen_lhs == gen_rhs}")
print(f"Gen LHS: {gen_lhs}, Gen RHS: {gen_rhs}")