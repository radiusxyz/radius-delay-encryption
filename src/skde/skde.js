// skde.js

import init, { encrypt, decrypt } from "./wasm/pkg/skde_wasm.js";

let initialized = false;

/**
 * Ensures the WebAssembly module is initialized.
 * This function initializes the module only once per session to optimize performance and avoid redundant calls.
 * @returns {Promise<void>} A promise that resolves when the module is initialized.
 */
async function ensureInitialized() {
  if (!initialized) {
    await init();
    initialized = true;
  }
}

/**
 * Encrypts a given message using specified cryptographic parameters and an encryption key.
 * This function ensures the WebAssembly module is initialized before proceeding with encryption.
 *
 * @param {Object} skdeParams - An object containing cryptographic parameters required for encryption:
 *   - {string} n - A large integer modulus, represented as a string, used in modular arithmetic.
 *   - {string} g - Generator value, represented as a string, for cryptographic operations.
 *   - {number} t - Time parameter, an integer that specifies the delay or difficulty of encryption.
 *   - {string} h - A large integer value representing an additional modulus or hash-based parameter.
 *   - {string} max_sequencer_number - The maximum sequence number for managing constraints, represented as a string.
 * @param {string} message - The plaintext message to encrypt, provided as a hex string.
 * @param {Object} encryptionKey - An object containing the public encryption key:
 *   - {string} pk - The public key, represented as a string, used for encryption.
 * @returns {Promise<string>} A promise that resolves to the encrypted ciphertext, represented as a hex string.
 */
async function encryptMessage(skdeParams, message, encryptionKey) {
  await ensureInitialized();
  return encrypt(skdeParams, message, encryptionKey);
}

/**
 * Decrypts a given ciphertext using specified cryptographic parameters and a secret key.
 * This function ensures the WebAssembly module is initialized before proceeding with decryption.
 *
 * @param {Object} skdeParams - An object containing cryptographic parameters required for decryption (same structure as for encryption):
 *   - {string} n - A large integer modulus, represented as a string, used in modular arithmetic.
 *   - {string} g - Generator value, represented as a string, for cryptographic operations.
 *   - {number} t - Time parameter, an integer that specifies the delay or difficulty of decryption.
 *   - {string} h - A large integer value representing an additional modulus or hash-based parameter.
 *   - {string} max_sequencer_number - The maximum sequence number for managing constraints, represented as a string.
 * @param {string} cipherText - The encrypted message (ciphertext) to decrypt, represented as a hex string.
 * @param {Object} secretKey - An object containing the secret key used for decryption:
 *   - {string} sk - The secret key, represented as a string, used to decrypt the ciphertext.
 * @returns {Promise<string>} A promise that resolves to the decrypted plaintext message, represented as a hex string.
 */
async function decryptCipher(skdeParams, cipherText, secretKey) {
  await ensureInitialized();
  return decrypt(skdeParams, cipherText, secretKey);
}

export default { encryptMessage, decryptCipher };
