// pvde.js

import init, {
  generate_time_lock_puzzle_param,
  generate_time_lock_puzzle,
  prove_time_lock_puzzle,
  verify_time_lock_puzzle_proof,
  generate_symmetric_key,
  encrypt,
  solve_time_lock_puzzle,
  decrypt,
  prove_encryption,
  verify_encryption_proof,
} from "./wasm/pkg/pvde_wasm.js";

let initialized = false;

/**
 * Ensures the WebAssembly module is initialized only once.
 * @returns {Promise<void>} A promise that resolves when initialization is complete.
 */
async function ensureInitialized() {
  if (!initialized) {
    await init();
    initialized = true;
  }
}

/**
 * Converts a Uint8Array to a hexadecimal string.
 * @param {Uint8Array} uint8Array - The array to convert.
 * @returns {string} The hexadecimal string representation.
 */
function uint8ArrayToHex(uint8Array) {
  return Array.from(uint8Array, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

/**
 * Reads a response stream and returns its bytes as a Uint8Array.
 * @param {Response} res - The response object.
 * @returns {Promise<Uint8Array>} A promise that resolves to the byte array.
 */
async function readStream(res) {
  const bytes = await res.arrayBuffer();
  return new Uint8Array(bytes);
}

/**
 * Fetches time lock puzzle ZKP parameters from a specified URL.
 * @returns {Promise<Uint8Array>} A promise that resolves to the fetched parameter data.
 */
async function fetchTimeLockPuzzleZkpParam() {
  return fetch(
    "https://raw.githubusercontent.com/radiusxyz/pvde.js/main/public/data/time_lock_puzzle_zkp_param.data"
  ).then((res) => readStream(res));
}

/**
 * Fetches time lock puzzle proving key.
 * @returns {Promise<Uint8Array>} A promise that resolves to the proving key data.
 */
async function fetchTimeLockPuzzleProvingKey() {
  return fetch(
    "https://raw.githubusercontent.com/radiusxyz/pvde.js/main/public/data/time_lock_puzzle_zkp_proving_key.data"
  ).then((res) => readStream(res));
}

/**
 * Fetches time lock puzzle verifying key.
 * @returns {Promise<Uint8Array>} A promise that resolves to the verifying key data.
 */
async function fetchTimeLockPuzzleVerifyingKey() {
  return fetch(
    "https://raw.githubusercontent.com/radiusxyz/pvde.js/main/public/data/time_lock_puzzle_zkp_verifying_key.data"
  ).then((res) => readStream(res));
}

/**
 * Generates parameters for a time lock puzzle.
 * @returns {Promise<Object>} A promise that resolves to the generated time lock puzzle parameters, which includes:
 *   - g (Array): array of values for generator.
 *   - n (Array): array representing modulus.
 *   - t (Number): the time parameter.
 *   - y (Array): array representing the result of exponentiation.
 *   - yTwo (Array): second array for y values.
 */
async function generateTimeLockPuzzleParam() {
  await ensureInitialized();
  const { y_two: yTwo, ...rest } = await generate_time_lock_puzzle_param(2048);
  return { ...rest, yTwo };
}

/**
 * Generates a time lock puzzle with the given parameters.
 * @param {Object} timeLockPuzzleParam - The parameters for generating the puzzle, including:
 *   - g (Array)
 *   - n (Array)
 *   - t (Number)
 *   - y (Array)
 *   - yTwo (Array)
 * @returns {Promise<Array>} A promise that resolves to an array containing puzzle data:
 *   - First item: object with a key `k` (Array).
 *   - Second item: object containing values:
 *     - kHashValue (Array)
 *     - kTwo (Array)
 *     - o (Array)
 *     - r1 (Array)
 *     - r2 (Array)
 *     - z (Array)
 */
async function generateTimeLockPuzzle(timeLockPuzzleParam) {
  await ensureInitialized();
  const { yTwo, ...rest } = timeLockPuzzleParam;
  const snakeCaseTimeLockPuzzleParam = { y_two: yTwo, ...rest };
  const inputs = await generate_time_lock_puzzle(snakeCaseTimeLockPuzzleParam);
  const { k_hash_value: kHashValue, k_two: kTwo, ...restInputs } = inputs[1];
  return [inputs[0], { kHashValue, kTwo, ...restInputs }];
}

/**
 * Generates a zero-knowledge proof for a time lock puzzle.
 * @param {Uint8Array} timeLockPuzzleZkpParam - ZKP parameter data as Uint8Array.
 * @param {Uint8Array} timeLockPuzzleZkpProvingKey - ZKP proving key as Uint8Array.
 * @param {Object} timeLockPuzzlePublicInput - Public input data for the puzzle, including:
 *   - kHashValue (Array)
 *   - kTwo (Array)
 *   - o (Array)
 *   - r1 (Array)
 *   - r2 (Array)
 *   - z (Array)
 * @param {Object} timeLockPuzzleSecretInput - Secret input data for the puzzle, containing:
 *   - k (Array)
 * @param {Object} timeLockPuzzleParam - Parameters for the time lock puzzle (see `generateTimeLockPuzzleParam`).
 * @returns {Promise<Object>} A promise that resolves to the generated proof, formatted as an object.
 */
async function generateTimeLockPuzzleProof(
  timeLockPuzzleZkpParam,
  timeLockPuzzleZkpProvingKey,
  timeLockPuzzlePublicInput,
  timeLockPuzzleSecretInput,
  timeLockPuzzleParam
) {
  await ensureInitialized();
  const { kHashValue, kTwo, ...restTimeLockPuzzlePublicInput } =
    timeLockPuzzlePublicInput;
  const snakeCaseTimeLockPuzzlePublicInput = {
    k_hash_value: kHashValue,
    k_two: kTwo,
    ...restTimeLockPuzzlePublicInput,
  };
  const { yTwo, ...restTimeLockPuzzleParam } = timeLockPuzzleParam;
  const snakeCaseTimeLockPuzzleParam = {
    y_two: yTwo,
    ...restTimeLockPuzzleParam,
  };
  return prove_time_lock_puzzle(
    timeLockPuzzleZkpParam,
    timeLockPuzzleZkpProvingKey,
    snakeCaseTimeLockPuzzlePublicInput,
    timeLockPuzzleSecretInput,
    snakeCaseTimeLockPuzzleParam
  );
}

/**
 * Verifies a zero-knowledge proof for a time lock puzzle.
 * @param {Uint8Array} timeLockPuzzleZkpParam - ZKP parameter data as Uint8Array.
 * @param {Uint8Array} timeLockPuzzleZkpVerifyingKey - ZKP verifying key as Uint8Array.
 * @param {Object} timeLockPuzzlePublicInput - Public input data for the puzzle (see `generateTimeLockPuzzleProof`).
 * @param {Object} timeLockPuzzleParam - Parameters for the puzzle (see `generateTimeLockPuzzleParam`).
 * @param {Object} timeLockPuzzleProof - Proof data for verification (Array).
 * @returns {Promise<boolean>} A promise that resolves to true if verification is successful.
 */
async function verifyTimeLockPuzzleProof(
  timeLockPuzzleZkpParam,
  timeLockPuzzleZkpVerifyingKey,
  timeLockPuzzlePublicInput,
  timeLockPuzzleParam,
  timeLockPuzzleProof
) {
  await ensureInitialized();
  const { kHashValue, kTwo, ...restTimeLockPuzzlePublicInput } =
    timeLockPuzzlePublicInput;
  const snakeCaseTimeLockPuzzlePublicInput = {
    k_hash_value: kHashValue,
    k_two: kTwo,
    ...restTimeLockPuzzlePublicInput,
  };
  const { yTwo, ...restTimeLockPuzzleParam } = timeLockPuzzleParam;
  const snakeCaseTimeLockPuzzleParam = {
    y_two: yTwo,
    ...restTimeLockPuzzleParam,
  };
  return verify_time_lock_puzzle_proof(
    timeLockPuzzleZkpParam,
    timeLockPuzzleZkpVerifyingKey,
    snakeCaseTimeLockPuzzlePublicInput,
    snakeCaseTimeLockPuzzleParam,
    timeLockPuzzleProof
  );
}

/**
 * Encrypts a message with the given encryption key.
 * @param {string} message - The plaintext message.
 * @param {string} encryptionKey - The encryption key.
 * @returns {Promise<string>} A promise that resolves to the encrypted message as a string.
 */
async function encryptMessage(message, encryptionKey) {
  await ensureInitialized();
  return encrypt(message, encryptionKey);
}

/**
 * Generates a zero-knowledge proof for encryption.
 * @param {Uint8Array} encryptionZkpParam - Encryption ZKP parameters as Uint8Array.
 * @param {Uint8Array} encryptionProvingKey - Encryption proving key as Uint8Array.
 * @param {Object} encryptionPublicInput - Public input data for encryption, containing:
 *   - encryptedData (string)
 *   - kHashValue (Array)
 * @param {Object} encryptionSecretInput - Secret input data for encryption, containing:
 *   - data (string)
 *   - k (Array)
 * @returns {Promise<Object>} A promise that resolves to the generated proof.
 */
async function generateEncryptionProof(
  encryptionZkpParam,
  encryptionProvingKey,
  encryptionPublicInput,
  encryptionSecretInput
) {
  await ensureInitialized();
  const { encryptedData, kHashValue } = encryptionPublicInput;
  const snakeCaseEncryptionPublicInput = {
    encrypted_data: encryptedData,
    k_hash_value: kHashValue,
  };
  return prove_encryption(
    encryptionZkpParam,
    encryptionProvingKey,
    snakeCaseEncryptionPublicInput,
    encryptionSecretInput
  );
}

/**
 * Verifies a zero-knowledge proof for encryption.
 * @param {Uint8Array} encryptionZkpParam - Encryption ZKP parameters as Uint8Array.
 * @param {Uint8Array} encryptionVerifyingKey - Encryption verifying key as Uint8Array.
 * @param {Object} encryptionPublicInput - Public input data for encryption (see `generateEncryptionProof`).
 * @param {Object} encryptionProof - Proof data for verification (Array).
 * @returns {Promise<boolean>} A promise that resolves to true if verification is successful.
 */
async function verifyEncryptionProof(
  encryptionZkpParam,
  encryptionVerifyingKey,
  encryptionPublicInput,
  encryptionProof
) {
  await ensureInitialized();
  const { encryptedData, kHashValue } = encryptionPublicInput;
  const snakeCaseEncryptionPublicInput = {
    encrypted_data: encryptedData,
    k_hash_value: kHashValue,
  };
  return verify_encryption_proof(
    encryptionZkpParam,
    encryptionVerifyingKey,
    snakeCaseEncryptionPublicInput,
    encryptionProof
  );
}

/**
 * Solves a time lock puzzle and retrieves the symmetric key.
 * @param {Object} timeLockPuzzlePublicInput - Public input for the time lock puzzle (see `generateTimeLockPuzzleProof`).
 * @param {Object} timeLockPuzzleParam - Parameters for the puzzle (see `generateTimeLockPuzzleParam`).
 * @returns {Promise<Array>} A promise that resolves to the symmetric key as an array.
 */
async function solveTimeLockPuzzle(
  timeLockPuzzlePublicInput,
  timeLockPuzzleParam
) {
  await ensureInitialized();
  return solve_time_lock_puzzle(
    timeLockPuzzlePublicInput.o,
    timeLockPuzzleParam.t,
    timeLockPuzzleParam.n
  );
}

/**
 * Generates a symmetric key using a given value.
 * @param {Array} k - The input value as an array.
 * @returns {Promise<Array>} A promise that resolves to the generated symmetric key as an array of two arrays.
 */
async function generateSymmetricKey(k) {
  await ensureInitialized();
  return generate_symmetric_key(k);
}

/**
 * Decrypts a cipher using a symmetric key.
 * @param {string} cipher - The encrypted message.
 * @param {Array} symmetricKey - The symmetric key as an array of two arrays.
 * @returns {Promise<string>} A promise that resolves to the decrypted message as a string.
 */
async function decryptCipher(cipher, symmetricKey) {
  await ensureInitialized();
  return decrypt(cipher, symmetricKey);
}

export default {
  readStream,
  fetchTimeLockPuzzleZkpParam,
  fetchTimeLockPuzzleProvingKey,
  fetchTimeLockPuzzleVerifyingKey,
  generateTimeLockPuzzleParam,
  generateTimeLockPuzzle,
  generateTimeLockPuzzleProof,
  verifyTimeLockPuzzleProof,
  fetchEncryptionZkpParam,
  fetchEncryptionProvingKey,
  fetchEncryptionVerifyingKey,
  encryptMessage,
  generateEncryptionProof,
  verifyEncryptionProof,
  solveTimeLockPuzzle,
  generateSymmetricKey,
  decryptCipher,
};
