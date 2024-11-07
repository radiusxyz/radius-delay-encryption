use serde::Deserialize;
use serde_wasm_bindgen::{from_value, to_value};
use skde::delay_encryption::{decrypt as decryptor, encrypt as encryptor, SkdeParams};
use wasm_bindgen::{prelude::*, JsValue};

#[derive(Deserialize)]
struct SkdeParamsJson {
    n: String,
    g: String,
    t: u32,
    h: String,
    max_sequencer_number: String,
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub fn encrypt(skde_params: JsValue, message: JsValue, encryption_key: &str) -> JsValue {
    let message: String = match message.as_string() {
        Some(msg) => msg,
        None => {
            log("Failed to convert message to string.");
            return JsValue::from_str("Error: Failed to convert message to string.");
        }
    };

    log(&format!("message: {:?}", message));

    let skde_params_json: SkdeParamsJson = match from_value(skde_params) {
        Ok(params) => params,
        Err(e) => {
            log(&format!("Failed to deserialize skde_params: {:?}", e));
            return JsValue::from_str("Error: Failed to deserialize skde_params.");
        }
    };

    let skde_params = SkdeParams {
        n: skde_params_json.n,
        g: skde_params_json.g,
        t: skde_params_json.t,
        h: skde_params_json.h,
        max_sequencer_number: skde_params_json.max_sequencer_number,
    };

    log(&format!("skde_params: {:?}", skde_params));

    log(&format!("encryption_key: {:?}", encryption_key));

    match encryptor(&skde_params, &message, &encryption_key) {
        Ok(ciphertext) => to_value(&ciphertext.to_string()).unwrap_or(JsValue::null()),
        Err(_) => {
            log("Encryption failed.");
            JsValue::from_str("Error: Encryption failed.")
        }
    }
}

#[wasm_bindgen]
pub fn decrypt(skde_params: JsValue, ciphertext: JsValue, decryption_key: &str) -> JsValue {
    let skde_params_json: SkdeParamsJson = match from_value(skde_params) {
        Ok(params) => params,
        Err(e) => {
            log(&format!("Failed to deserialize skde_params: {:?}", e));
            return JsValue::from_str("Error: Failed to deserialize skde_params.");
        }
    };

    let skde_params = SkdeParams {
        n: skde_params_json.n,
        g: skde_params_json.g,
        t: skde_params_json.t,
        h: skde_params_json.h,
        max_sequencer_number: skde_params_json.max_sequencer_number,
    };

    log(&format!("skde_params: {:?}", skde_params));

    let ciphertext: String = match ciphertext.as_string() {
        Some(ciphertext) => ciphertext,
        None => {
            log("Failed to convert ciphertext to string.");
            return JsValue::from_str("Error: Failed to convert ciphertext to string.");
        }
    };

    log(&format!("ciphertext: {:?}", ciphertext));

    log(&format!("decryption_key: {:?}", decryption_key));

    match decryptor(&skde_params, &ciphertext, &decryption_key) {
        Ok(decrypted_message) => {
            to_value(&decrypted_message.to_string()).unwrap_or(JsValue::null())
        }
        Err(_) => JsValue::null(),
    }
}
