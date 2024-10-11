/* tslint:disable */
/* eslint-disable */
/**
* @param {any} t
* @returns {any}
*/
export function generate_time_lock_puzzle_param(t: any): any;
/**
* @param {any} time_lock_puzzle_param
* @returns {any}
*/
export function generate_time_lock_puzzle(time_lock_puzzle_param: any): any;
/**
* @param {any} time_lock_puzzle_zkp_param
* @param {any} time_lock_puzzle_zkp_proving_key
* @param {any} time_lock_puzzle_public_input
* @param {any} time_lock_puzzle_secret_input
* @param {any} time_lock_puzzle_param
* @returns {any}
*/
export function prove_time_lock_puzzle(time_lock_puzzle_zkp_param: any, time_lock_puzzle_zkp_proving_key: any, time_lock_puzzle_public_input: any, time_lock_puzzle_secret_input: any, time_lock_puzzle_param: any): any;
/**
* @param {any} time_lock_puzzle_zkp_param
* @param {any} time_lock_puzzle_zkp_verifying_key
* @param {any} time_lock_puzzle_public_input
* @param {any} time_lock_puzzle_param
* @param {any} time_lock_puzzle_proof
* @returns {boolean}
*/
export function verify_time_lock_puzzle_proof(time_lock_puzzle_zkp_param: any, time_lock_puzzle_zkp_verifying_key: any, time_lock_puzzle_public_input: any, time_lock_puzzle_param: any, time_lock_puzzle_proof: any): boolean;
/**
* @param {any} o
* @param {any} t
* @param {any} n
* @returns {any}
*/
export function solve_time_lock_puzzle(o: any, t: any, n: any): any;
/**
* @param {any} k
* @returns {any}
*/
export function generate_symmetric_key(k: any): any;
/**
* @param {any} param
* @param {any} proving_key
* @param {any} encryption_public_input
* @param {any} encryption_secret_input
* @returns {any}
*/
export function prove_encryption(param: any, proving_key: any, encryption_public_input: any, encryption_secret_input: any): any;
/**
* @param {any} param
* @param {any} verifying_key
* @param {any} encryption_public_input
* @param {any} proof
* @returns {boolean}
*/
export function verify_encryption_proof(param: any, verifying_key: any, encryption_public_input: any, proof: any): boolean;
/**
* @param {string} data
* @param {any} encrypt
* @returns {any}
*/
export function encrypt(data: string, encrypt: any): any;
/**
* @param {string} encrypted_data
* @param {any} hash_value
* @returns {any}
*/
export function decrypt(encrypted_data: string, hash_value: any): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly generate_time_lock_puzzle_param: (a: number) => number;
  readonly generate_time_lock_puzzle: (a: number) => number;
  readonly prove_time_lock_puzzle: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly verify_time_lock_puzzle_proof: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly solve_time_lock_puzzle: (a: number, b: number, c: number) => number;
  readonly generate_symmetric_key: (a: number) => number;
  readonly prove_encryption: (a: number, b: number, c: number, d: number) => number;
  readonly verify_encryption_proof: (a: number, b: number, c: number, d: number) => number;
  readonly encrypt: (a: number, b: number, c: number) => number;
  readonly decrypt: (a: number, b: number, c: number) => number;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
