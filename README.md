# EUDI-Web3 zk-SNARKs Implementation

This project contains the implementation described in the master's thesis about bridging EUDI and Web3 using zk-SNARKs. It integrates a Java-based backend system for data management with a modular CLI-based proof generation workflow using Circom and SnarkJS.

---

## Project Structure

- **`zk-backend/`**  
  Spring Boot backend responsible for:

  - Creation and management of EUDI and blockchain wallets
  - Preparation of data required for zk-SNARKs

- **`zk-monolithic/`**  
  CLI application for generating and verifying the monolithic zk-SNARK as described in the thesis. Proofs are constructed using Circom, compiled via SnarkJS or RapidSnark, and executed through a Bash script.

- **`zk-recursive/`**  
  CLI application for generating and verifying the recursive zk-SNARK as described in the thesis. Proofs are constructed using Rust with Nova and executed through a Bash script.

- **`circom_libs/`**  
  External Circom libraries, integrated via Git submodules.

- **`ptau/`**  
  Central directory for Powers-of-Tau setup files (`.ptau`) shared across all zk-proof-related projects within this repository.

---

## zk-backend

This is a Spring Boot application.

### Getting Started

```bash
cd zk-backend
./mvnw spring-boot:run
```

The application will start on:  
http://localhost:8080

The OpenAPI specification is accessible at:  
http://localhost:8080/swagger-ui.html  
It can be downloaded and imported into Postman.

### Extending the Proof Preparation System

To add new high-level constraints (e.g., eudi key derivation, blockchain key derivation, etc.):

- For each constraint, a corresponding JSON data structure must be added to `zk-backend/data/proof-preparation/`.  
  The naming format is:

  ```
  <userId>-<constraintType>.json
  ```

  Examples:

  - `philipp-eudi-credential-verification.json`
  - `philipp-blockchain-master-key-derivation.json`

- Create a new Java model class in the `model` package.
- Register the new model in:
  - `ProofPreparationRegistry.java`
  - `ProofPreparationService.java`
  - `ProofPreparationController.java`

This structure ensures that every proof has its corresponding input data managed and prepared correctly by the backend.

---

## zk-monolithic

This CLI-based system handles compilation, proof generation, and verification.

### Launch the CLI

```bash
cd zk-monolithic
./scripts/proof.sh
```

### Workflow

After starting the CLI, the following steps are performed:

1. Selection of the user id. 
2. Synchronization of input data from the backend.
3. The system automatically executes:
   - Circuit compilation
   - Witness generation
   - Groth16 trusted setup
   - Verification key export
   - Proof generation and verification
   - Output storage

### Output Files

All generated artifacts (proofs, verification keys, public inputs, etc.) are written to:

```
zk-monolithic/build/
```

---

## Setup: Git Submodules and PTAU

### Git Submodules

After cloning this repository, run the following command to initialize submodules:

```bash
git submodule update --init --recursive
```

If the submodule for `circom-pairing` fails due to SSH issues, adjust the `.gitmodules` entry or run:

```bash
git config -f .gitmodules submodule.circom_libs/circom-ecdsa-p256/circuits/circom-pairing.url https://github.com/yi-sun/circom-pairing.git
git submodule sync --recursive
```

### Submodules Used

- [`circom-ecdsa-p256`](https://github.com/sommer-ph/circom-ecdsa-p256)  
  _Forked from [privacy-scaling-explorations/circom-ecdsa-p256](https://github.com/privacy-scaling-explorations/circom-ecdsa-p256)._  
  This fork updates the internal `.gitmodules` file to replace the SSH-based submodule URL for `circom-pairing` with an HTTPS URL. This change resolves potential SSH permission issues during submodule initialization and simplifies cloning and setup in typical development environments.
- [`circom-pairing`](https://github.com/yi-sun/circom-pairing)  
  Required as a nested submodule inside `circom-ecdsa-p256`, providing pairing-friendly elliptic curve arithmetic and bigint operations.
- [`circom-ecdsa`](https://github.com/sommer-ph/circom-ecdsa)  
  _Forked from [0xPARC/circom-ecdsa](https://github.com/0xPARC/circom-ecdsa)._  
  This fork adds a prefix `K1_` to every template, function, and signal name in order to avoid naming conflicts with `circom-ecdsa-p256`. Since `circom-ecdsa-p256` was originally derived from `circom-ecdsa`, many identifiers overlapped. As Circom currently does not support namespacing, this adaptation was necessary to allow both secp256k1 and secp256r1 cryptographic operations to coexist within a single unified proof circuit.

### PTAU File Handling

All trusted setup `.ptau` files are stored in the root-level `ptau/` directory.  
Example:

```
ptau/powersOfTau28_hez_final_22.ptau  # Suitable for up to 2^22 constraints
```

These files were downloaded from the official [SnarkJS reference setup](https://github.com/iden3/snarkjs#7-ptau-setup) and may be replaced or extended with other sizes as needed.

They are referenced in scripts via:

```bash
POT_NAME="powersOfTau28_hez_final_22.ptau"
POT_FILE="${ROOT_DIR}/../ptau/${POT_NAME}"
```

---

## zk-recursive

Tbw...

---

## Author

Philipp Sommer  
Last updated: June 2025
