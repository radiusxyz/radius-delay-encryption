# Cryptographic Modules

This project provides `pvde` and `skde` modules, which facilitate secure cryptographic operations, including time-lock puzzle generation, proof generation and verification, symmetric key encryption and decryption, and more. These modules leverage WebAssembly (Wasm) for efficient cryptographic computations.

## Table of Contents

- [Installation](#installation)
- [Initialization](#initialization)
- [Usage](#usage)
  - [Time-Lock Puzzle Operations (pvde)](#time-lock-puzzle-operations-pvde)
  - [Encryption Operations (pvde)](#encryption-operations-pvde)
  - [SKDE Encryption and Decryption](#skde-encryption-and-decryption)
- [Dependencies](#dependencies)
- [License](#license)

## Installation

To use these modules, ensure you have installed all dependencies and the required WebAssembly files. Clone the repository and install necessary packages:

```bash
git clone https://github.com/radiusxyz/radius-delay-encryption.git
cd radius-delay-encryption
npm install
```

## Initialization

Before using the functions in either `pvde` or `skde`, initialize the modules to load the WebAssembly components properly.

```javascript
import { pvde, skde } from "./radius-delay-encryption";

await pvde.ensureInitialized();
await skde.ensureInitialized();
```

## Usage

### Time-Lock Puzzle Operations (pvde)

The `pvde` module provides functionality for creating and verifying time-lock puzzles, allowing for time-delayed decryption of messages.

#### Generating Time-Lock Puzzle Parameters

Generate parameters for creating a time-lock puzzle:

```javascript
const params = await pvde.generateTimeLockPuzzleParam();
```

#### Creating a Time-Lock Puzzle

With generated parameters, create a time-lock puzzle:

```javascript
const puzzle = await pvde.generateTimeLockPuzzle(params);
```

#### Generating a Time-Lock Puzzle Proof

Create a Zero-Knowledge Proof (ZKP) for a time-lock puzzle:

```javascript
const proof = await pvde.generateTimeLockPuzzleProof(
  zkpParam,
  provingKey,
  publicInput,
  secretInput,
  params
);
```

#### Verifying a Time-Lock Puzzle Proof

Verify the ZKP for the time-lock puzzle to ensure validity:

```javascript
const isValid = await pvde.verifyTimeLockPuzzleProof(
  zkpParam,
  verifyingKey,
  publicInput,
  params,
  proof
);
```

#### Solving a Time-Lock Puzzle

After verification, solve the puzzle to retrieve the symmetric key:

```javascript
const symmetricKey = await pvde.solveTimeLockPuzzle(publicInput, params);
```

### Encryption Operations (pvde)

The modules also support encryption and decryption operations using symmetric keys and zero-knowledge proof (ZKP) generation for encrypted messages.

#### Encrypting a Message

Encrypt a message using a provided encryption key:

```javascript
const encryptedMessage = await pvde.encryptMessage(message, encryptionKey);
```

#### Generating an Encryption Proof

Create a ZKP to validate the encryption of a message:

```javascript
const encryptionProof = await pvde.generateEncryptionProof(
  zkpParam,
  provingKey,
  publicInput,
  secretInput
);
```

#### Verifying an Encryption Proof

Verify the ZKP for an encrypted message:

```javascript
const isValidEncryptionProof = await pvde.verifyEncryptionProof(
  zkpParam,
  verifyingKey,
  publicInput,
  encryptionProof
);
```

#### Decrypting a Message

Decrypt an encrypted message using the symmetric key:

```javascript
const decryptedMessage = await pvde.decryptCipher(cipher, symmetricKey);
```

### SKDE Encryption and Decryption

The `skde` module provides lightweight symmetric key encryption and decryption functions, useful for secure message handling.

#### Encrypting a Message (skde)

Encrypt a message with the `skde` module using provided encryption parameters and key:

```javascript
const skdeParams = {
  /* parameters specific to skde */
};
const encryptedMessage = await skde.encryptMessage(
  skdeParams,
  message,
  encryptionKey
);
```

#### Decrypting a Message (skde)

Decrypt an encrypted message with `skde` using the appropriate parameters and secret key:

```javascript
const decryptedMessage = await skde.decryptCipher(
  skdeParams,
  cipherText,
  secretKey
);
```

## Dependencies

This project relies on the following:

- WebAssembly (Wasm) modules for cryptographic operations.
- Fetch API for downloading cryptographic parameters and keys.

Ensure that the necessary parameter and key files are available at the correct URLs or local paths specified in the code:

- `time_lock_puzzle_zkp_param.data`
- `time_lock_puzzle_zkp_proving_key.data`
- `time_lock_puzzle_zkp_verifying_key.data`
- `encryption_zkp_param.data`
- `encryption_zkp_proving_key.data`
- `encryption_zkp_verifying_key.data`
---
