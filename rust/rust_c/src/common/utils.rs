use alloc::string::{String, ToString};
use core::slice;

use super::ffi::CSliceFFI;
use super::free::Free;
use crate::{extract_array, extract_ptr_with_type};
use cstr_core::{CStr, CString};
use cty::c_char;

use crate::common::types::{PtrString, PtrT};

pub fn convert_c_char(s: String) -> PtrString {
    CString::new(s).unwrap().into_raw()
}

pub unsafe fn recover_c_char(s: *mut c_char) -> String {
    CStr::from_ptr(s).to_str().unwrap().to_string()
}

// Fallible sibling of `recover_c_char`: returns the recovered string when the C string is valid
// UTF-8, and the `Utf8Error` when it is not, instead of panicking. Any `extern "C"` entry point
// that recovers externally supplied bytes (the decoded contents of a scanned QR, or a USB
// transfer) MUST use this and turn the error into a refused-input response, never the panicking
// `recover_c_char`: a panic inside an `extern "C"` fn cannot unwind and aborts the whole firmware.
// A QR in byte mode encodes arbitrary octets, so a crafted code can place a non-UTF-8 byte inside
// an otherwise well-formed `ur:` string, making this edge reachable at the very first parse step.
pub unsafe fn recover_c_char_checked(s: *mut c_char) -> Result<String, core::str::Utf8Error> {
    CStr::from_ptr(s).to_str().map(ToString::to_string)
}

pub unsafe fn check_recover_c_char_lossy(s: *mut c_char) -> (bool, String) {
    match CStr::from_ptr(s).to_str() {
        Ok(value) => (true, value.to_string()),
        Err(_) => (false, CStr::from_ptr(s).to_string_lossy().into_owned()),
    }
}

pub unsafe fn recover_c_array<'a, T: Free>(s: PtrT<CSliceFFI<T>>) -> &'a [T] {
    let boxed_keys = extract_ptr_with_type!(s, CSliceFFI<T>);
    extract_array!(boxed_keys.data, T, boxed_keys.size)
}
