#!/usr/bin/env python3
"""
Field Arithmetic Verification Script

This simple script verifies field arithmetic operations by comparing manual calculations
with Circom witness results. It helps debug discrepancies between expected mathematical
results and actual circuit computations.

Used for debugging specific field arithmetic issues where Circom produces unexpected results.
"""

y = 11827799447777774141591265572096038483897818415107791647687835362639865667176
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583

print("=== FIELD ARITHMETIC VERIFICATION ===")
print("y:", y)
print("p:", p)
print()

# Manual calculation
y_sq_manual = (y * y) % p
print("Manual y^2 mod p:", y_sq_manual)

# Circom result
y_sq_circom = 16094894196505648382334086725086297715380092971732205191514441731520248777946
print("Circom y^2:      ", y_sq_circom)

print("Equal:", y_sq_manual == y_sq_circom)
print()

if y_sq_manual != y_sq_circom:
    raw_y_sq = y * y
    print("Raw y^2 (no mod):", raw_y_sq)
    print("Difference:", y_sq_manual - y_sq_circom)
    print("Ratio:", y_sq_manual / y_sq_circom)