//! JNI bridge for `app.wasl.core.Deep`.
//!
//! All entry points are `extern "system"`, use the safe `JNIEnv` wrappers from the `jni` crate,
//! and convert any error (including a caught panic) into a Java `IOException` instead of
//! aborting the VM. JNI symbol names match Kotlin's `@JvmStatic` methods on the `Deep` object.

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::Duration;

fn throw_io(env: &mut JNIEnv<'_>, msg: impl AsRef<str>) {
    // If a Java exception is already pending, adding another one would be ignored by the JVM.
    let pending = env.exception_check().unwrap_or(true);
    if !pending {
        let _ = env.throw_new("java/io/IOException", msg.as_ref());
    }
}

fn null_array() -> jbyteArray {
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "system" fn Java_app_wasl_core_Deep_nativeEncode<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    input: JByteArray<'local>,
    budget_ms: jlong,
    token: jlong,
) -> jbyteArray {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<Vec<u8>, String> {
        let bytes = env
            .convert_byte_array(&input)
            .map_err(|e| format!("read Java byte array: {e}"))?;
        // budget_ms <= 0: no deadline. A positive budget stops new segments after it elapses.
        let budget = if budget_ms > 0 { Some(Duration::from_millis(budget_ms as u64)) } else { None };
        crate::encode_with(&bytes, budget, token as u64).map_err(|e| e.0)
    }));
    match result {
        Ok(Ok(out)) => match env.byte_array_from_slice(&out) {
            Ok(array) => array.into_raw(),
            Err(e) => {
                throw_io(&mut env, format!("allocate Java byte array: {e}"));
                null_array()
            }
        },
        Ok(Err(msg)) => {
            throw_io(&mut env, msg);
            null_array()
        }
        Err(p) => {
            let msg = panic_message(&p);
            throw_io(&mut env, format!("encoder panic: {msg}"));
            null_array()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_app_wasl_core_Deep_nativeDecode<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    input: JByteArray<'local>,
    osize: jlong,
    osha: JString<'local>,
) -> jbyteArray {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<Vec<u8>, String> {
        let osha = parse_osha(&mut env, &osha)?;
        if osize < 0 {
            return Err("negative osize".to_string());
        }
        let bytes = env
            .convert_byte_array(&input)
            .map_err(|e| format!("read Java byte array: {e}"))?;
        crate::decode(&bytes, osize as u64, &osha).map_err(|e| e.0)
    }));
    match result {
        Ok(Ok(out)) => match env.byte_array_from_slice(&out) {
            Ok(array) => array.into_raw(),
            Err(e) => {
                throw_io(&mut env, format!("allocate Java byte array: {e}"));
                null_array()
            }
        },
        Ok(Err(msg)) => {
            throw_io(&mut env, msg);
            null_array()
        }
        Err(p) => {
            let msg = panic_message(&p);
            throw_io(&mut env, format!("decoder panic: {msg}"));
            null_array()
        }
    }
}

/// Streaming decode from `inPath` to `outPath` (no whole-file buffers). Throws `IOException` on any
/// failure and leaves no `outPath` behind.
#[no_mangle]
pub extern "system" fn Java_app_wasl_core_Deep_nativeDecodeToFile<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    in_path: JString<'local>,
    out_path: JString<'local>,
    osize: jlong,
    osha: JString<'local>,
) {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let osha = parse_osha(&mut env, &osha)?;
        if osize < 0 {
            return Err("negative osize".to_string());
        }
        let input: String = env.get_string(&in_path).map_err(|e| format!("read path: {e}"))?.into();
        let output: String = env.get_string(&out_path).map_err(|e| format!("read path: {e}"))?.into();
        crate::decode_file(Path::new(&input), Path::new(&output), osize as u64, &osha).map_err(|e| e.0)
    }));
    match result {
        Ok(Ok(())) => {}
        Ok(Err(msg)) => throw_io(&mut env, msg),
        Err(p) => {
            let msg = panic_message(&p);
            throw_io(&mut env, format!("decoder panic: {msg}"));
        }
    }
}

/// Ask the encode registered under `token` to stop at its next segment boundary.
#[no_mangle]
pub extern "system" fn Java_app_wasl_core_Deep_nativeCancel<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    token: jlong,
) {
    let _ = catch_unwind(|| crate::cancel(token as u64));
}

fn parse_osha(env: &mut JNIEnv<'_>, s: &JString<'_>) -> Result<[u8; 32], String> {
    let hex: String = env.get_string(s).map_err(|e| format!("read osha: {e}"))?.into();
    crate::parse_sha_hex(&hex).map_err(|e| e.0)
}

#[no_mangle]
pub extern "system" fn Java_app_wasl_core_Deep_nativeVersion<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let result = catch_unwind(AssertUnwindSafe(|| crate::version_string()));
    let s = result.unwrap_or_else(|_| "hopperdeep (panic)".to_string());
    match env.new_string(s) {
        Ok(v) => v.into_raw(),
        Err(e) => {
            throw_io(&mut env, format!("allocate Java string: {e}"));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_app_wasl_core_Deep_nativeIsAvailable<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jboolean {
    let result = catch_unwind(AssertUnwindSafe(crate::is_available));
    if result.unwrap_or(false) { JNI_TRUE } else { JNI_FALSE }
}

fn panic_message(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}
