import init from "@radiusxyz/wasm-client";

let pvde;

(async () => {
  pvde = await init("./your_module_bg.wasm");
})();

function generate_time_lock_puzzle_param(t) {
  return pvde.generate_time_lock_puzzle_param(t);
}

function generate_time_lock_puzzle(time_lock_puzzle_param) {
  return pvde.generate_time_lock_puzzle_param(time_lock_puzzle_param);
}

function prove_time_lock_puzzle(
  time_lock_puzzle_zkp_param,
  time_lock_puzzle_zkp_proving_key,
  time_lock_puzzle_public_input,
  time_lock_puzzle_secret_input, // time-lock puzzle secret input
  time_lock_puzzle_param
) {
  return pvde.time_lock_puzzle_zkp_param(
    time_lock_puzzle_zkp_param,
    time_lock_puzzle_zkp_proving_key,
    time_lock_puzzle_public_input,
    time_lock_puzzle_secret_input, // time-lock puzzle secret input
    time_lock_puzzle_param
  );
}

function verify_time_lock_puzzle_proof(
  time_lock_puzzle_zkp_param,
  time_lock_puzzle_zkp_verifying_key,
  time_lock_puzzle_public_input,
  time_lock_puzzle_param,
  time_lock_puzzle_proof
) {
  return pvde.verify_time_lock_puzzle_proof(
    time_lock_puzzle_zkp_param,
    time_lock_puzzle_zkp_verifying_key,
    time_lock_puzzle_public_input,
    time_lock_puzzle_param,
    time_lock_puzzle_proof
  );
}

function generate_symmetric_key(k) {
  return pvde.generate_symmetric_key(k);
}

function encrypt(message, encryption_key) {
  return pvde.encrypt(message, encryption_key);
}

function prove_encryption(
  encryption_zkp_param,
  encryption_proving_key,
  encryption_public_input,
  encryption_secret_input
) {
  return pvde.prove_encryption(
    encryption_zkp_param,
    encryption_proving_key,
    encryption_public_input,
    encryption_secret_input
  );
}

function verify_encryption_proof(
  encryption_zkp_param,
  encryption_verifying_key,
  encryption_public_input,
  encryption_proof
) {
  return pvde.verify_encryption_proof(
    encryption_zkp_param,
    encryption_verifying_key,
    encryption_public_input,
    encryption_proof
  );
}

function solve_time_lock_puzzle(o, t, n) {
  return pvde.solve_time_lock_puzzle(o, t, n);
}

function decrypt(encrypted_message, decryption_key) {
  return pvde.decrypt(encrypted_message, decryption_key);
}

// Export functions as needed
export {
  generate_time_lock_puzzle_param,
  generate_time_lock_puzzle,
  prove_time_lock_puzzle,
  verify_time_lock_puzzle_proof,
  generate_symmetric_key,
  encrypt,
  prove_encryption,
  verify_encryption_proof,
  solve_time_lock_puzzle,
  decrypt,
};
