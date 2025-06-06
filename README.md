# EUDI-Web3 zk-SNARKs Implementation

This project contains the implementation described in the master's thesis about bridging EUDI and Web3 using zk-SNARKs. It integrates a Java-based backend system for data management with a modular CLI-based proof generation workflow using Circom and SnarkJS.

---

## Project Structure

- **`zk-backend/`**  
  Spring Boot backend responsible for:

  - Creation and management of EUDI and blockchain wallets
  - Preparation of data required for zk-SNARKs

- **`zk-proof/`**  
  CLI application for generating and verifying the zk-SNARKs as described in the thesis. Proofs are constructed using Circom, compiled via SnarkJS, and executed through modular Bash scripts.

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

## zk-proof

This CLI-based system handles compilation, proof generation, and verification.

### Launch the CLI

```bash
cd zk-proof
./scripts/1-main.sh
```

### Workflow

After starting the CLI, the following steps are performed:

1. Selection of the proof composition or sub-proof mode.
2. Input of further parameters depending on the selected mode.
3. Synchronization of input data from the backend.
4. Preparation of the proof input using dedicated JS preprocessors.
5. The system automatically executes:
   - Circuit compilation
   - Groth16 trusted setup
   - Witness generation
   - Proof generation and verification
   - Output storage

### Output Files

All generated artifacts (proofs, verification keys, public inputs, etc.) are written to:

```
zk-proof/build/
```

Files that are specific to a user or a single proof will have the user ID and proof identifier encoded in their filenames.

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
  This fork updates the internal `.gitmodules` file to replace the SSH-based submodule URL for `circom-pairing` with an HTTPS URL. This change avoids SSH-related permission errors during submodule initialization and makes the repository easier to clone and set up in typical development environments.
- [`circom-pairing`](https://github.com/yi-sun/circom-pairing)  
  Required as a nested submodule inside `circom-ecdsa-p256`, used for pairing-based cryptographic operations.

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

## Extending the zk-proof System

To add a new circuit/proof flow:

### 1. Circom Circuit

- Place the `.circom` file under `zk-proof/circuits/<subdirectory>/`.
- Choose a clear naming convention (e.g., `verify-key-derivation.circom`).

### 2. Bash CLI Integration

- **Update `scripts/1-main.sh`:**  
  Add the new option to the interactive menu, following the structure for existing constraints.
- **Add JavaScript preprocessor:**  
  Create a new `prepare-<proof-type>-<constraint>-<impl>.js` file in `scripts/input/`.  
  This file must take the copied JSON and output a valid `input.json` for the Circom circuit.

- **Update `scripts/3-prepare-input.sh`:**  
  Map the `(constraint + impl)` selection to the correct JS preprocessor file.

- **Update `scripts/4-compile-and-prove.sh`:**  
  Extend the proof configuration matrix to include the new circuit, providing:
  - CIRCUIT_NAME
  - CIRCUIT_PATH
  - INPUT_FILE
  - OUTPUT_PREFIX (naming pattern)

Refer to how `verify-p256-signature` is handled as an example.

### Naming Conventions

- Inputs: `input/prepared/<user>-<constraint>.json`
- Circuits: `verify-<constraint>.circom`
- Proof Outputs: `build/<user>_<proof-id>_proof.json`, etc.
- Prepare Scripts: `prepare-<proof-type>-<constraint>-<impl>.js`

---

## Author

Philipp Sommer  
Last updated: June 2025
