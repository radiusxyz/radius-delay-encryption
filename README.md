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
---

## Usage

### PVDE

### Initial Setup

Before performing any time-lock puzzle or encryption operations, you need to fetch the Zero-Knowledge Proof (ZKP) parameters and keys. These are essential for generating and verifying proofs in both the time-lock puzzle and encryption processes.

#### Fetching Required Parameters and Keys

```javascript
// Fetch Time-Lock Puzzle ZKP parameters and keys
const timeLockPuzzleZkpParam = await pvde.fetchTimeLockPuzzleZkpParam();
const timeLockPuzzleZkpProvingKey = await pvde.fetchTimeLockPuzzleProvingKey();
const timeLockPuzzleZkpVerifyingKey = await pvde.fetchTimeLockPuzzleVerifyingKey();

// Fetch Encryption ZKP parameters and keys
const encryptionZkpParam = await pvde.fetchEncryptionZkpParam();
const encryptionProvingKey = await pvde.fetchEncryptionProvingKey();
const encryptionVerifyingKey = await pvde.fetchEncryptionVerifyingKey();
```

- **Purpose**: These parameters and keys are required for generating and verifying ZKPs.
  - **Time-Lock Puzzle**:
    - `timeLockPuzzleZkpParam`: ZKP parameter data for time-lock puzzles.
    - `timeLockPuzzleZkpProvingKey`: Proving key for generating proofs.
    - `timeLockPuzzleZkpVerifyingKey`: Verifying key for proof verification.
  - **Encryption**:
    - `encryptionZkpParam`: ZKP parameter data for encryption.
    - `encryptionProvingKey`: Proving key for generating encryption proofs.
    - `encryptionVerifyingKey`: Verifying key for proof verification.

### Time-Lock Puzzle Operations

The `pvde` module provides functionality for creating, proving, and verifying time-lock puzzles, enabling time-delayed decryption of messages with Zero-Knowledge Proof (ZKP) for security.

#### Generating Time-Lock Puzzle Parameters

To create a time-lock puzzle, start by generating the required cryptographic parameters:

```javascript
const timeLockPuzzleParam = await pvde.generateTimeLockPuzzleParam();
```

- **Output**: An object containing fields like `g`, `n`, `t`, `y`, and `yTwo`, where each field represents specific cryptographic values and configurations required for the time-lock puzzle.

#### Creating a Time-Lock Puzzle

Use the generated parameters to create a time-lock puzzle. This step generates a puzzle alongside public and secret inputs for use in proof generation and verification:

```javascript
const [timeLockPuzzleSecretInput, timeLockPuzzlePublicInput] = await pvde.generateTimeLockPuzzle(timeLockPuzzleParam);
```

- **Inputs**: `timeLockPuzzleParam` — Object containing values like `g`, `n`, `t`, `y`, and `yTwo`.
- **Outputs**: An array with:
  - `timeLockPuzzleSecretInput` — Contains `k`, a cryptographic key in array format.
  - `timeLockPuzzlePublicInput` — Contains arrays for `kHashValue`, `kTwo`, `o`, `r1`, `r2`, and `z`, used in proof verification.

#### Generating a Time-Lock Puzzle Proof

Generate a Zero-Knowledge Proof (ZKP) to validate the time-lock puzzle. This proof ensures the puzzle was created correctly, without revealing the underlying secret key:

```javascript
const timeLockPuzzleProof = await pvde.generateTimeLockPuzzleProof(
  timeLockPuzzleZkpParam,     // Uint8Array containing ZKP parameters
  timeLockPuzzleZkpProvingKey, // Uint8Array containing ZKP proving key
  timeLockPuzzlePublicInput,   // Public inputs for the puzzle
  timeLockPuzzleSecretInput,   // Secret inputs for the puzzle
  timeLockPuzzleParam          // Puzzle parameters
);
```

- **Output**: An object representing the generated ZKP for the time-lock puzzle.

#### Verifying a Time-Lock Puzzle Proof

Verify the ZKP for the time-lock puzzle to confirm the validity of the generated puzzle without revealing any secret information:

```javascript
const isTimeLockPuzzleVerified = await pvde.verifyTimeLockPuzzleProof(
  timeLockPuzzleZkpParam,      // Uint8Array with ZKP parameters
  timeLockPuzzleZkpVerifyingKey, // Uint8Array with ZKP verifying key
  timeLockPuzzlePublicInput,   // Public input data for verification
  timeLockPuzzleParam,         // Puzzle parameters
  timeLockPuzzleProof          // The proof object generated
);
```

- **Output**: A boolean indicating the success or failure of the verification process.

#### Solving a Time-Lock Puzzle

After verifying the proof, solve the time-lock puzzle to retrieve the symmetric key, which is stored as an array of two arrays for use in encryption:

```javascript
const symmetricKey = await pvde.solveTimeLockPuzzle(
  timeLockPuzzlePublicInput, // Public inputs required for solving
  timeLockPuzzleParam        // Puzzle parameters
);
```

- **Output**: The symmetric key, returned as an array of two arrays, for encryption or decryption operations.

### Encryption Operations (pvde)

This module also supports encryption and decryption using the generated symmetric key, as well as ZKP generation and verification for encrypted messages to ensure data integrity and confidentiality.

#### Generating a Symmetric Key

Generate a symmetric encryption key from an input array. This key is used for encrypting and decrypting messages:

```javascript
const encryptionKey = await pvde.generateSymmetricKey(timeLockPuzzleSecretInput.k);
```

- **Output**: An array of two arrays, representing the symmetric encryption key.

#### Encrypting a Message

Encrypt a plaintext message using the symmetric encryption key generated in the previous step:

```javascript
const encryptedMessage = await pvde.encryptMessage(
  "Hello World",     // Message to encrypt
  encryptionKey      // Symmetric key (array of two arrays)
);
```

- **Output**: A string representing the encrypted message (cipher text).

#### Generating an Encryption Proof

Create a ZKP for the encryption operation. This proof confirms the integrity and correctness of the encryption process without revealing the plaintext:

```javascript
const encryptionProof = await pvde.generateEncryptionProof(
  encryptionZkpParam,         // Uint8Array for encryption ZKP parameters
  encryptionProvingKey,       // Uint8Array for encryption proving key
  encryptionPublicInput,      // Object containing encryptedData (String) and kHashValue (array of two arrays)
  encryptionSecretInput       // Object containing data (String) and k (array)
);
```

- **Output**: An object representing the ZKP for the encryption operation.

#### Verifying an Encryption Proof

Verify the ZKP for an encrypted message, ensuring the validity and integrity of the encryption without exposing any secret data:

```javascript
const isValidEncryptionProof = await pvde.verifyEncryptionProof(
  encryptionZkpParam,         // Uint8Array with encryption ZKP parameters
  encryptionVerifyingKey,     // Uint8Array with encryption verifying key
  encryptionPublicInput,      // Public inputs for encryption
  encryptionProof             // Proof object for verification
);
```

- **Output**: A boolean indicating whether the encryption proof is valid.

#### Decrypting a Message

Use the symmetric key to decrypt the previously encrypted message, recovering the original plaintext:

```javascript
const decryptedMessage = await pvde.decryptCipher(
  cipher,                     // Encrypted message (cipher text)
  decryptionKey               // Symmetric key (array of two arrays)
);
```

- **Output**: The decrypted plaintext message as a string.

---

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
