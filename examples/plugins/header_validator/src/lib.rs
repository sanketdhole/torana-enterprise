use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
struct WasmEnvelope {
    headers: HashMap<String, String>,
}

#[derive(Serialize)]
struct WasmDecision {
    action: i32,
    status_code: i32,
    reason: Option<String>,
    mutate_headers: Option<HashMap<String, String>>,
}

#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    let _ = Vec::from_raw_parts(ptr, 0, size);
}

#[no_mangle]
pub unsafe extern "C" fn process(ptr: *const u8, len: usize) -> u64 {
    let slice = std::slice::from_raw_parts(ptr, len);
    let envelope: Result<WasmEnvelope, _> = serde_json::from_slice(slice);

    let decision = match envelope {
        Ok(env) => {
            let has_key = env.headers.get("x-api-key").or_else(|| env.headers.get("X-API-Key"));
            let has_auth = env.headers.get("authorization").or_else(|| env.headers.get("Authorization"));

            if has_key.is_none() && has_auth.is_none() {
                WasmDecision {
                    action: 1, // Halt
                    status_code: 401,
                    reason: Some("Missing required authentication header".into()),
                    mutate_headers: None,
                }
            } else {
                let mut mut_headers = HashMap::new();
                mut_headers.insert("X-Validated-By".into(), "Torana-Rust-Validator/1.0".into());
                WasmDecision {
                    action: 2, // Mutate
                    status_code: 200,
                    reason: None,
                    mutate_headers: Some(mut_headers),
                }
            }
        }
        Err(_) => WasmDecision {
            action: 1,
            status_code: 400,
            reason: Some("Malformed JSON envelope".into()),
            mutate_headers: None,
        },
    };

    let out_bytes = serde_json::to_vec(&decision).unwrap_or_default();
    let out_len = out_bytes.len() as u32;
    let out_ptr = alloc(out_len as usize);
    std::ptr::copy_nonoverlapping(out_bytes.as_ptr(), out_ptr, out_len as usize);

    ((out_ptr as u64) << 32) | (out_len as u64)
}
