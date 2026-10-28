//! What the kernel says about the sandbox this process runs in. `sandbox_check` answers for the
//! process itself, so code inside the sandbox cannot fake it

use std::ffi::{CString, c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

unsafe extern "C" {
    fn sandbox_check(pid: c_int, operation: *const c_char, kind: c_int, ...) -> c_int;
}

// From sandbox.h: no filter asks whether there is a sandbox at all, 1 filters by path
const NONE: c_int = 0;
const PATH: c_int = 1;

fn pid() -> c_int {
    std::process::id() as c_int
}

/// Whether this process runs in any sandbox
pub fn sandboxed() -> bool {
    // Safe: a null operation with no filter takes no further argument
    unsafe { sandbox_check(pid(), std::ptr::null(), NONE) == 1 }
}

/// Whether this process's sandbox denies `operation`, such as `file-read-data`, on `path`
pub fn denies(operation: &str, path: &Path) -> bool {
    let (Ok(op), Ok(path)) = (
        CString::new(operation),
        CString::new(path.as_os_str().as_bytes()),
    ) else {
        return false;
    };
    // Safe: both strings outlive the call, which only reads them
    unsafe { sandbox_check(pid(), op.as_ptr(), PATH, path.as_ptr()) == 1 }
}
