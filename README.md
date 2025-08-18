# EUDI-Web3 Bridge: zk-SNARKs Identity Integration

> Academic research implementation bridging European Digital Identity (EUDI) wallets with Web3 blockchain systems using zk-SNARKs.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Rust](https://img.shields.io/badge/Rust-1.70+-red.svg)](https://www.rust-lang.org/)
[![Circom](https://img.shields.io/badge/Circom-2.2.0-green.svg)](https://docs.circom.io/)

## Overview

The EUDI-Web3 Bridge enables privacy-preserving integration between European Digital Identity wallets and blockchain-based Web3 wallets through zk-SNARKs. This implementation demonstrates how users can prove possession of valid EUDI credentials without revealing sensitive personal information, while simultaneously binding their identity to blockchain wallet addresses.

### Key Features

- **Privacy-Preserving Identity Verification**: Prove credential validity without revealing personal data
- **Cross-Platform Integration**: Bridge EUDI wallets with Web3 blockchain systems
- **Multiple zk-SNARK Backends**: Monolithic (Groth16), Recursive (Nova), and Recursive (Plonky2) implementations
- **Research-Grade Implementation**: Comprehensive experimental framework for cryptographic comparisons

## System Architecture

The system consists of five main components working together to provide end-to-end zk-SNARK-based identity verification:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   EUDI Wallet   │    │   zk-backend     │    │   Blockchain        │
│                 │    │                  │    │   (Web3 Wallet)     │
│ • Credentials   │────│ • Data Prep      │────│ • Address           │
│ • Private Keys  │    │ • Key Management │    │ • Transaction       │
│ • Signatures    │    │ • REST API       │    │                     │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
         ┌──────────▼──┐ ┌──────▼─────┐ ┌───▼─────────────┐
         │zk-monolithic│ │zk-recursive│ │zk-monolithic-   │
         │             │ │  -nova     │ │  experiments    │
         │ • Circom    │ │ • Nova     │ │ • EdDSA         │
         │ • Groth16   │ │ • Rust     │ │ • Comparisons   │
         │ • SnarkJS   │ │            │ │ • SNARK-friendly│
         └─────────────┘ └────────────┘ └─────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │   zk-recursive-       │
                    │     plonky2           │
                    │   • Plonky2           │
                    │   • Multi-step        │
                    │   • Rust              │
                    └───────────────────────┘
```

### Component Overview

- **`zk-backend/`**: Spring Boot REST API for data preparation, wallet management, and zk-SNARK input generation
- **`zk-monolithic/`**: Circom-based implementation using Groth16 proofs with SnarkJS/RapidSnark
- **`zk-monolithic-experiments/`**: Research playground for EdDSA comparisons and SNARK-friendly implementations
- **`zk-recursive-nova/`**: Rust implementation using Nova recursive proofs for scalability
- **`zk-recursive-plonky2/`**: Advanced Plonky2-based recursive implementation with additional multi-step workflows
- **`circom_libs/`**: External cryptographic libraries (ECDSA implementations, pairing-friendly curves)

## Quick Start

### Prerequisites

Ensure you have the following installed:

- **Java 21+** (OpenJDK recommended)
- **Maven 3.8+**
- **Node.js 18+** and **npm**
- **Rust 1.70+** with Cargo
- **Circom 2.2.0+**
- **SnarkJS** globally installed: `npm install -g snarkjs`
- **Git** with submodule support

### Installation

1. **Clone the repository with submodules:**

   ```bash
   git clone --recursive https://github.com/sommer-ph/eudi-web3-bridge.git
   cd eudi-web3-bridge
   ```

2. **Initialize submodules (if not cloned recursively):**

   ```bash
   git submodule update --init --recursive
   ```

3. **Install Node.js dependencies:**
   ```bash
   cd zk-monolithic && npm install && cd ..
   cd zk-monolithic-experiments && npm install && cd ..
   ```

### 5-Minute Demo

1. **Start the backend:**

   ```bash
   cd zk-backend
   ./mvnw spring-boot:run
   ```

   Access Swagger UI at: http://localhost:8080/swagger-ui.html. Choose a user Id and use endpoints to create wallets, credentials, and to prepare the data for proof generation.

2. **Generate a monolithic proof:**

   ```bash
   cd zk-monolithic
   ./scripts/proof.sh
   # Enter user ID when prompted (reference data for id "philipp" already exists; you can also use your id specified in step 1)
   ```

3. **Try recursive proof with plonky2:**
   ```bash
   cd zk-recursive-plonky2
   ./inputs/tools/proof.sh
   # Enter user ID when prompted (reference data for id "philipp" already exists; you can also use your id specified in step 1)
   ```

## Prerequisites & Installation

### System Requirements

- **OS**: Linux (Ubuntu 20.04+), macOS (10.15+), Windows (WSL2 recommended)
- **RAM**: 16GB recommended
- **Storage**: 5GB+ for build artifacts
- **CPU**: Modern multi-core processor (proof generation is CPU-intensive)

### Detailed Setup

#### Java Backend Setup

```bash
cd zk-backend
./mvnw clean install
./mvnw spring-boot:run
```

#### Circom Environment Setup

```bash
# Install Circom
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
source ~/.cargo/env
git clone https://github.com/iden3/circom.git
cd circom && cargo build --release
cargo install --path circom
```

#### RapidSnark (Optional, for fast monolithic proving)

```bash
git clone https://github.com/iden3/rapidsnark.git
cd rapidsnark
git submodule init && git submodule update
./build_gmp.sh host
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
```

#### Powers-of-Tau Setup

The repository does not include pre-downloaded ptau files. For monolithic proof generation a file with at least power of 2\*\*22 is needed. The file can be downloaded from:

```bash
https://github.com/iden3/snarkjs/
```

> [!Important]
> **Download and Setup Instructions**
> 
> It is also possible to download from another source. To avoid compile issues, create a folder named "ptau" on root level of the repository and place the downloaded ptau-file in it. Also ensure the ptau-file is named "powersOfTau28_hez_final_22.ptau" as the monolithic shell-scripts use file references.

## zk-SNARK Proof Systems

### Monolithic Proofs (Circom + Groth16)

**Location**: `zk-monolithic/`

Implements a single, comprehensive circuit that proves:

- EUDI wallet key derivation (P-256)
- Credential public key validation
- Issuer signature verification (optimized static key)
- Blockchain wallet key derivation (secp256k1)

**Circuit Structure:**

```circom
template CredentialWalletBinding() {
    // C1: EudiWalletKeyDerivation (pk_c = KeyDer(sk_c))
    // C2: CredentialPKCheck (pk_c === pk_c_extracted)
    // C3: CredentialSignatureVerification (VerifySig(pk_I, msg, r, s))
    // C4: BlockchainWalletKeyDerivation (pk_0 = KeyDer(sk_0))
}
```

**Usage:**

```bash
cd zk-monolithic
./scripts/proof.sh
```

### Recursive Proofs (Plonky2)

**Location**: `zk-recursive-plonky2/`

Advanced implementation using Plonky2's fast recursive proofs:

- Multi-step recursive workflows (C1→C2→C3→C4→C5)
- Configurable signature modes (static/dynamic)
- Hybrid derivation modes (SHA512/Poseidon)

**Usage:**

```bash
cd zk-recursive-plonky2
./inputs/tools/proof.sh
```

### Experimental Implementations

**Location**: `zk-monolithic-experiments/`

Research-focused implementations for comparative analysis. All experimental implementations can be executed using the provided shell scripts:

#### Circuit Components & Combinations

```bash
cd zk-monolithic-experiments

# Individual circuit components
./scripts/cred-bind/proof-eudi-wallet-key-derivation.sh
./scripts/cred-bind/proof-credential-signature-verification-optimized.sh
./scripts/cred-bind/proof-blockchain-wallet-key-derivation.sh

# Complete circuit binding (EUDI + Blockchain)
./scripts/cred-bind/proof-cred-bind.sh

# EUDI-only binding
./scripts/cred-bind-eudi-only/proof-cred-bind-eudi-only.sh

# Nova preparation wrapper
./scripts/nova-cred-bind-wrapper/proof-nova-cred-bind-wrapper.sh
```

#### SNARK-Friendly Signature Analysis

```bash
cd zk-monolithic-experiments

# EdDSA (Baby Jubjub) implementations
./scripts/snark-friendly/eddsa/proof-eddsa-keyDer.sh      # Key derivation
./scripts/snark-friendly/eddsa/proof-eddsa-sigVerify.sh   # Signature verification

# ECDSA native verification
./scripts/snark-friendly/ecdsa/proof-ecdsa-native.sh
```

### Recursive Proofs (Nova)

**Location**: `zk-recursive-nova/`

Uses Nova's folding scheme for recursive proof composition with a monolithic circuit wrapper.

**Prerequisites:**
1. Generate required circuit files using the wrapper script in `zk-monolithic-experiments/`:
   ```bash
   cd zk-monolithic-experiments
   ./scripts/nova-cred-bind-wrapper/proof-nova-cred-bind-wrapper.sh
   ```

**Usage:**
```bash
cd zk-recursive-nova
cargo run --release
# Or with custom paths:
# cargo run --release -- build_monolithic/nova-cred-bind-wrapper.r1cs build_monolithic/nova-cred-bind-wrapper.wtns
```

## Security Considerations

**Academic Research Implementation**

This codebase is an academic research implementation developed as part of a master's thesis. It has **not been audited** by professional security firms and should **not be used in production environments** without thorough security review.

### Known Limitations

1. **No Formal Security Audit**: Implementation has not undergone professional cryptographic audit
2. **Research-Grade Code**: Focus on functionality and research exploration over production hardening
3. **Trusted Setup Dependency**: Groth16 implementation relies on trusted ceremony parameters
4. **Key Management**: Simplified key handling suitable for research but not production deployment

## Research & Publications

This implementation was developed as part of a master's thesis research project exploring the integration of European Digital Identity (EUDI) systems with Web3 blockchain technologies through zero-knowledge proofs.

### Academic Context

**Thesis Title**: Bridging EUDI Wallets and Web3 via zk-SNARKs 
**Institution**: Technical University of Darmstadt - Chair of Applied Cryptography
**Author**: Philipp Sommer  

_For questions, issues, or research collaborations, please use the GitHub issue tracker or contact the maintainers directly._