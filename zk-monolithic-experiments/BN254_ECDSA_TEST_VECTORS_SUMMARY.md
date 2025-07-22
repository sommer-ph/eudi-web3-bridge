# BN254 ECDSA Test Vectors for Circom

## Overview

This document provides mathematically verified ECDSA test vectors for the BN254 curve (also known as alt_bn128) that are compatible with Circom's field arithmetic. All operations are performed modulo the scalar field `r` as required by Circom.

## Curve Parameters

- **Curve**: BN254 (alt_bn128)
- **Equation**: y² = x³ + 3 (over base field F_p)
- **Generator Point**: G = (1, 2)
- **Scalar Field Order**: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
- **Base Field**: p = 21888242871839275222246405745257275088696311157297823662689037894645226208583

## ECDSA Verification Equation

The ECDSA verification follows this process:
1. Calculate w = s^(-1) mod r
2. Calculate u₁ = z·w mod r  
3. Calculate u₂ = r·w mod r
4. Calculate R = u₁·G + u₂·Q (point addition on the curve)
5. Verify that R.x mod r = r (signature component)

## Test Vector 1: Standard Case

### Input Parameters
- **Private key d**: 12345
- **Public key Q**: (11404940445424363337823423808411232433223590477377068719858726746225925918890, 2424505913866680143139332783087422983475325405994502385033744924144562639386)
- **Message**: "Hello BN254 ECDSA"  
- **Message hash z**: 14704903728378246326577305547205377309195090619437662134766942637023702156464

### Signature Components
- **r**: 17880725275155766350342155997254961499094219132684969381835561082485285850094
- **s**: 5140509993908080801810402776881632225478701790495886092804925721036955096958

### Verification Values
- **w**: 18293108965943053975522689012567745931074397079307445870241405948310854615429
- **u₁**: 4588367797399022731811872583211663090747292297518211107956547701533651407564
- **u₂**: 20441066318480162415111138109719555515008776498995459030975183436154796475870

### Circom Witness Data
```json
{
    "z": "14704903728378246326577305547205377309195090619437662134766942637023702156464",
    "Qx": "11404940445424363337823423808411232433223590477377068719858726746225925918890",
    "Qy": "2424505913866680143139332783087422983475325405994502385033744924144562639386",
    "r": "17880725275155766350342155997254961499094219132684969381835561082485285850094",
    "s": "5140509993908080801810402776881632225478701790495886092804925721036955096958",
    "w": "18293108965943053975522689012567745931074397079307445870241405948310854615429",
    "q1": "12289629999629181232651457933784638601003723948965937848909464609863322995876",
    "q2": "14943824306214431386142158111809366755749094524505252209800678297020046842568", 
    "q3": "0"
}
```

**Verification Status**: ✅ PASSED

## Test Vector 2: Minimal Case

### Input Parameters  
- **Private key d**: 1
- **Public key Q**: (1, 2) [same as generator G since 1·G = G]
- **Message hash z**: 1

### Signature Components
- **r**: 1368015179489954701390400359078579693043519447331113978918064868415326638035
- **s**: 684007589744977350695200179539289846521759723665556989459032434207663319018

### Verification Values
- **w**: 2716263033819408570346102102002109115718789838339501423857726865089489556260
- **u₁**: 2716263033819408570346102102002109115718789838339501423857726865089489556260
- **u₂**: 19171979838019866651900303643255165972829574562076532919840477321486318939359

### Circom Witness Data
```json
{
    "z": "1",
    "Qx": "1", 
    "Qy": "2",
    "r": "1368015179489954701390400359078579693043519447331113978918064868415326638035",
    "s": "684007589744977350695200179539289846521759723665556989459032434207663319018",
    "w": "2716263033819408570346102102002109115718789838339501423857726865089489556260",
    "q1": "0",
    "q2": "169766439613713035646631381375131819733571848242199567878510996923391604173",
    "q3": "0"
}
```

**Verification Status**: ✅ PASSED

## Quotient Explanation

The quotients (q1, q2, q3) are used in Circom to handle the fact that intermediate calculations may exceed the field size:

- **q1**: Quotient when z·w is divided by r, i.e., q1 = ⌊(z·w)/r⌋
- **q2**: Quotient when r·w is divided by r, i.e., q2 = ⌊(r·w)/r⌋  
- **q3**: Quotient when R.x is divided by r, i.e., q3 = ⌊R.x/r⌋

These quotients allow Circom to verify the modular arithmetic constraints:
- z·w = q1·r + u₁
- r·w = q2·r + u₂  
- R.x = q3·r + (R.x mod r)

## Mathematical Verification

Both test vectors have been mathematically verified to satisfy:

1. **Public key is on curve**: Q satisfies y² = x³ + 3 (mod p)
2. **Signature components are valid**: 1 ≤ r,s < r (scalar field order)
3. **ECDSA verification equation**: R.x mod r = r, where R = u₁·G + u₂·Q
4. **Quotient relationships**: All quotient calculations are correct
5. **Field arithmetic**: All operations use appropriate field moduli

## Usage with Circom

These test vectors can be directly used as witness inputs for BN254 ECDSA verification circuits in Circom. The values are provided in decimal format as strings to maintain precision.

## Files Generated

- `bn254_ecdsa_test_vectors.json`: Complete test vector with verification details
- `bn254_ecdsa_minimal_vectors.json`: Minimal test vector for simple testing
- `generate_bn254_ecdsa_vectors.py`: Python script to generate these vectors  
- `verify_bn254_vectors.py`: Verification script to validate the vectors

All test vectors have been confirmed to work with Circom's field arithmetic requirements for the BN254 curve.