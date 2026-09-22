use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

static SSN_RE: OnceLock<Regex> = OnceLock::new();
static EMAIL_RE: OnceLock<Regex> = OnceLock::new();

fn get_ssn_re() -> &'static Regex {
    SSN_RE.get_or_init(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap())
}

fn get_email_re() -> &'static Regex {
    EMAIL_RE.get_or_init(|| Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap())
}

fn sanitize(input: &str) -> String {
    let ssn_sanitized = get_ssn_re().replace_all(input, "***-**-****");
    get_email_re().replace_all(&ssn_sanitized, "[REDACTED_EMAIL]").into_owned()
}

#[derive(Deserialize)]
struct WasmEnvelope {
    body: Option<String>,
}

#[derive(Serialize)]
struct WasmDecision {
    action: i32,
    status_code: i32,
    mutate_body: Option<String>,
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
            let body_str = env.body.unwrap_or_default();
            let sanitized = sanitize(&body_str);
            WasmDecision {
                action: 2, // Mutate
                status_code: 200,
                mutate_body: Some(sanitized),
            }
        }
        Err(_) => WasmDecision {
            action: 1, // Halt
            status_code: 400,
            mutate_body: None,
        },
    };

    let out_bytes = serde_json::to_vec(&decision).unwrap_or_default();
    let out_len = out_bytes.len() as u32;
    let out_ptr = alloc(out_len as usize);
    std::ptr::copy_nonoverlapping(out_bytes.as_ptr(), out_ptr, out_len as usize);

    ((out_ptr as u64) << 32) | (out_len as u64)
}

#[no_mangle]
pub unsafe extern "C" fn on_chunk(ptr: *const u8, len: usize) -> u64 {
    let slice = std::slice::from_raw_parts(ptr, len);
    let text = String::from_utf8_lossy(slice);
    let sanitized = sanitize(&text);

    let out_bytes = sanitized.into_bytes();
    let out_len = out_bytes.len() as u32;
    let out_ptr = alloc(out_len as usize);
    std::ptr::copy_nonoverlapping(out_bytes.as_ptr(), out_ptr, out_len as usize);

    ((out_ptr as u64) << 32) | (out_len as u64)
}
