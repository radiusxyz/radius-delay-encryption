// skde.js

import init, { encrypt, decrypt } from "./wasm/pkg/skde_wasm.js";

let initialized = false;

/**
 * Ensures the WebAssembly module is initialized.
 * Initializes the module only once per session to avoid redundant calls.
 * @returns {Promise<void>} A promise that resolves when the module is initialized.
 */
async function ensureInitialized() {
  if (!initialized) {
    await init();
    initialized = true;
  }
}

/**
 * Encrypts a given message using specified parameters and an encryption key.
 * Ensures the WebAssembly module is initialized before encryption.
 * @param {Object} skdeParams - Parameters required for encryption.
 * @param {string} message - The plaintext message to encrypt.
 * @param {string} encryptionKey - The encryption key used for encrypting the message.
 * @returns {Promise<string>} A promise that resolves to the encrypted ciphertext.
 */
async function encryptMessage(skdeParams, message, encryptionKey) {
  await ensureInitialized();
  return encrypt(skdeParams, message, encryptionKey);
}

/**
 * Decrypts a given ciphertext using specified parameters and a secret key.
 * Ensures the WebAssembly module is initialized before decryption.
 * @param {Object} skdeParams - Parameters required for decryption.
 * @param {string} cipherText - The encrypted message (ciphertext) to decrypt.
 * @param {string} secretKey - The secret key used for decrypting the message.
 * @returns {Promise<string>} A promise that resolves to the decrypted plaintext message.
 */
async function decryptCipher(skdeParams, cipherText, secretKey) {
  await ensureInitialized();
  return decrypt(skdeParams, cipherText, secretKey);
}

export default { encryptMessage, decryptCipher };
