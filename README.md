Here's a README for your `pvde.js` module:

---

# PVDE.js

This module provides functions to generate, prove, verify, and solve time-lock puzzles, as well as perform symmetric key encryption and decryption. It leverages WebAssembly (Wasm) modules to enhance the cryptographic operations.

## Table of Contents
- [Installation](#installation)
- [Initialization](#initialization)
- [Usage](#usage)
  - [Time-Lock Puzzle](#time-lock-puzzle)
    - [Generating Parameters](#generating-time-lock-puzzle-parameters)
    - [Creating a Puzzle](#generating-time-lock-puzzle)
    - [Proof Generation](#generating-time-lock-puzzle-proof)
    - [Proof Verification](#verifying-time-lock-puzzle-proof)
    - [Solving the Puzzle](#solving-time-lock-puzzle)
  - [Encryption](#encryption)
    - [Message Encryption](#encrypting-message)
    - [Proof Generation](#generating-encryption-proof)
    - [Proof Verification](#verifying-encryption-proof)
    - [Decryption](#decrypting-message)
- [Dependencies](#dependencies)
- [License](#license)

## Installation

To use the `pvde.js` module, ensure you have installed all dependencies and WebAssembly modules. Clone the repository and install any required packages:

```bash
git clone https://github.com/radiusxyz/pvde.js.git
cd pvde.js
npm install
```

## Initialization

The module must be initialized before using its functions. This ensures that the WebAssembly module is loaded correctly.

```javascript
import { ensureInitialized } from './pvde.js';

await ensureInitialized();
```

## Usage

### Time-Lock Puzzle

#### Generating Time-Lock Puzzle Parameters
Generate parameters for creating a time-lock puzzle:
```javascript
const params = await generateTimeLockPuzzleParam();
```

#### Generating Time-Lock Puzzle
Create a time-lock puzzle using the generated parameters:
```javascript
const puzzle = await generateTimeLockPuzzle(params);
```

#### Generating Time-Lock Puzzle Proof
Generate a Zero-Knowledge Proof (ZKP) for the time-lock puzzle:
```javascript
const proof = await generateTimeLockPuzzleProof(
  zkpParam,
  provingKey,
  publicInput,
  secretInput,
  params
);
```

#### Verifying Time-Lock Puzzle Proof
Verify the generated proof for the time-lock puzzle:
```javascript
const isValid = await verifyTimeLockPuzzleProof(
  zkpParam,
  verifyingKey,
  publicInput,
  params,
  proof
);
```

#### Solving Time-Lock Puzzle
Solve the time-lock puzzle to reveal the symmetric key:
```javascript
const symmetricKey = await solveTimeLockPuzzle(publicInput, params);
```

### Encryption

#### Encrypting Message
Encrypt a message using a symmetric key:
```javascript
const encryptedMessage = await encryptMessage(message, encryptionKey);
```

#### Generating Encryption Proof
Generate a ZKP for the encrypted message:
```javascript
const encryptionProof = await generateEncryptionProof(
  zkpParam,
  provingKey,
  publicInput,
  secretInput
);
```

#### Verifying Encryption Proof
Verify the proof for the encrypted message:
```javascript
const isValidEncryptionProof = await verifyEncryptionProof(
  zkpParam,
  verifyingKey,
  publicInput,
  encryptionProof
);
```

#### Decrypting Message
Decrypt a message using the symmetric key:
```javascript
const decryptedMessage = await decryptCipher(cipher, symmetricKey);
```

## Dependencies

The module depends on the following:
- WebAssembly (Wasm) modules for cryptographic operations
- Fetch API for downloading puzzle and encryption keys

Make sure that you have the necessary keys and data files available at the paths specified in the code:
- `time_lock_puzzle_zkp_param.data`
- `time_lock_puzzle_zkp_proving_key.data`
- `time_lock_puzzle_zkp_verifying_key.data`
- `encryption_zkp_param.data`
- `encryption_zkp_proving_key.data`
- `encryption_zkp_verifying_key.data`

