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
} from "./pkg/pvde.js";

let initialized = false;
async function ensureInitialized() {
  if (!initialized) {
    await init();
    initialized = true;
  }
}

function uint8ArrayToHex(uint8Array) {
  return Array.from(uint8Array, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function readStream(res) {
  const bytes = await res.arrayBuffer();
  const uint8bytes = new Uint8Array(bytes);
  return uint8bytes;
}

async function fetchTimeLockPuzzleZkpParam() {
  return await fetch(
    "https://raw.githubusercontent.com/radiusxyz/pvde.js/main/public/data/time_lock_puzzle_zkp_param.data",
    {
      method: "GET",
    }
  ).then((res) => readStream(res));
}

async function fetchTimeLockPuzzleProvingKey() {
  return await fetch(
    "https://raw.githubusercontent.com/radiusxyz/pvde.js/main/public/data/time_lock_puzzle_zkp_proving_key.data",
    {
      method: "GET",
    }
  ).then((res) => readStream(res));
}

async function fetchTimeLockPuzzleVerifyingKey() {
  return await fetch(
    "https://raw.githubusercontent.com/radiusxyz/pvde.js/main/public/data/time_lock_puzzle_zkp_verifying_key.data",
    {
      method: "GET",
    }
  ).then((res) => readStream(res));
}

async function generateTimeLockPuzzleParam() {
  await ensureInitialized();
  const { y_two: yTwo, ...rest } = await generate_time_lock_puzzle_param(2048);

  return {
    ...rest,
    yTwo,
  };
}

async function generateTimeLockPuzzle(timeLockPuzzleParam) {
  await ensureInitialized();

  const { yTwo, ...rest } = timeLockPuzzleParam;
  const snakeCaseTimeLockPuzzleParam = { y_two: yTwo, ...rest };
  const inputs = await generate_time_lock_puzzle(snakeCaseTimeLockPuzzleParam);
  const { k_hash_value: kHashValue, k_two: kTwo, ...restInputs } = inputs[1];

  return [
    inputs[0],
    {
      kHashValue,
      kTwo,
      ...restInputs,
    },
  ];
}

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
  const snakeCaseTimeLockPuzleParam = {
    y_two: yTwo,
    ...restTimeLockPuzzleParam,
  };

  return await prove_time_lock_puzzle(
    timeLockPuzzleZkpParam,
    timeLockPuzzleZkpProvingKey,
    snakeCaseTimeLockPuzzlePublicInput,
    timeLockPuzzleSecretInput, // time-lock puzzle secret input
    snakeCaseTimeLockPuzleParam
  );
}

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

async function fetchEncryptionZkpParam() {
  return await fetch(
    "https://raw.githubusercontent.com/radiusxyz/pvde.js/main/public/data/encryption_zkp_param.data",
    {
      method: "GET",
    }
  ).then((res) => readStream(res));
}

async function fetchEncryptionProvingKey() {
  return await fetch(
    "https://raw.githubusercontent.com/radiusxyz/pvde.js/main/public/data/encryption_zkp_proving_key.data",
    {
      method: "GET",
    }
  ).then((res) => readStream(res));
}

async function fetchEncryptionVerifyingKey() {
  return await fetch(
    "https://raw.githubusercontent.com/radiusxyz/pvde.js/main/public/data/encryption_zkp_verifying_key.data",
    {
      method: "GET",
    }
  ).then((res) => readStream(res));
}

async function encryptMessage(message, encryptionKey) {
  await ensureInitialized();
  return encrypt(message, encryptionKey);
}

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

async function solveTimeLockPuzzle(
  timeLockPuzzlePublicInput,
  timeLockPuzzleParam
) {
  await ensureInitialized();

  const k = await solve_time_lock_puzzle(
    timeLockPuzzlePublicInput.o,
    timeLockPuzzleParam.t,
    timeLockPuzzleParam.n
  );
  return k;
}

async function generateSymmetricKey(k) {
  await ensureInitialized();
  return await generate_symmetric_key(k);
}

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
