#!/usr/bin/env python3
"""
Field Modulus Analysis: Circom vs Standard BN254

This script demonstrates that Circom uses the BN254 scalar field modulus 
(curve order) instead of the BN254 base field modulus for its arithmetic operations.
"""

# BN254 curve parameters
BN254_BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583  # p (base field)
BN254_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # r (scalar field/curve order)

# Test value from your example
y = 11827799447777774141591265572096038483897818415107791647687835362639865667176
circom_result = 16094894196505648382334086725086297715380092971732205191514441731520248777946

print("=== BN254 Field Modulus Analysis ===")
print(f"Input y: {y}")
print()
print("BN254 Parameters:")
print(f"Base Field (p):   {BN254_BASE_FIELD}")  
print(f"Scalar Field (r): {BN254_SCALAR_FIELD}")
print(f"Difference:       {BN254_BASE_FIELD - BN254_SCALAR_FIELD}")
print()

# Calculate y^2 with different moduli
raw_y_squared = y * y
base_field_result = raw_y_squared % BN254_BASE_FIELD
scalar_field_result = raw_y_squared % BN254_SCALAR_FIELD

print("Field Arithmetic Results:")
print(f"Raw y^2:                     {raw_y_squared}")
print(f"y^2 mod p (base field):      {base_field_result}")
print(f"y^2 mod r (scalar field):    {scalar_field_result}")
print(f"Circom witness result:       {circom_result}")
print()

print("Verification:")
print(f"Circom uses base field:      {base_field_result == circom_result}")
print(f"Circom uses scalar field:    {scalar_field_result == circom_result}")
print()

if scalar_field_result == circom_result:
    print("✓ CONCLUSION: Circom uses BN254 scalar field modulus (curve order)")
    print("  This is the 'r' parameter, not the base field 'p' parameter")
elif base_field_result == circom_result:
    print("✓ CONCLUSION: Circom uses BN254 base field modulus")
else:
    print("✗ ERROR: Circom result doesn't match either expected modulus")

print()
print("Technical Details:")
print("- BN254 base field (p): Used for elliptic curve point coordinates")
print("- BN254 scalar field (r): Used for private keys, signatures, and circuit arithmetic")
print("- Circom operates in the scalar field Fr, not the base field Fp")
print("- This is why your standard BN254 calculations differ from Circom results")