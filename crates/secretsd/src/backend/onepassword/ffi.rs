//! Dynamic loading of 1Password Desktop's native IPC library
//! (`libop_sdk_ipc_client.so`) and the one safe abstraction around its raw
//! C ABI.
//!
//! The library is **never bundled** — only the one already installed
//! alongside the user's 1Password Desktop is loaded, if present. Every
//! `unsafe` block in the `onepassword` backend lives in this one file;
//! nothing outside it touches a raw function pointer or a native
//! allocation. See `docs/architecture/1password-integration.md` for how
//! the signatures below were reconstructed (via disassembly — no
//! documentation for this protocol exists anywhere public) and for the
//! parts still flagged there as not fully confirmed.
//!
//! `#[allow(dead_code)]` below is deliberate: nothing outside this
//! module's own tests calls `IpcLibrary` yet — the `ipc` module (Step 6)
//! is its first real caller.
#![allow(dead_code)]

use std::path::Path;

use libloading::{Library, Symbol};

/// Overrides where the library is looked up, instead of
/// [`CANDIDATE_PATHS`]. Used by this module's own tests to point at a
/// fixture library; also usable for a non-standard real install.
///
/// Never consulted for anything security-sensitive: it only changes
/// *which* library gets loaded, never what a loaded library is trusted
/// to do.
pub const LIBRARY_PATH_OVERRIDE_ENV: &str = "SECRETS_OP_SDK_IPC_LIB";

/// Where 1Password Desktop's IPC library is looked for when
/// [`LIBRARY_PATH_OVERRIDE_ENV`] is not set. Just the one confirmed real
/// install location for now (see `docs/architecture/1password-
/// integration.md`'s "Environment" section) — more candidates can be
/// appended here without touching any caller.
const CANDIDATE_PATHS: &[&str] = &["/opt/1Password/libop_sdk_ipc_client.so"];

/// The exported `op_sdk_ipc_send_message` symbol's name, as a
/// null-terminated byte string (what `libloading::Library::get` needs).
const SEND_MESSAGE_SYMBOL: &[u8] = b"op_sdk_ipc_send_message\0";

/// The exported `op_sdk_ipc_free_response` symbol's name, null-terminated.
const FREE_RESPONSE_SYMBOL: &[u8] = b"op_sdk_ipc_free_response\0";

/// Raw C signature of `op_sdk_ipc_send_message`, reconstructed via
/// disassembly (see the architecture doc's "`op_sdk_ipc_send_message`'s
/// signature and behavior" section): copies `request_len` bytes from
/// `request_ptr`, and on success (return `0`) writes the native
/// response's length, capacity and data pointer into `out_len`,
/// `out_cap`, `out_ptr` respectively. A negative `request_len` or any
/// null output pointer is rejected by the native code itself before this
/// module's own checks ever run.
type RawSendMessage = unsafe extern "C" fn(
    request_ptr: *const u8,
    request_len: isize,
    out_len: *mut usize,
    out_cap: *mut usize,
    out_ptr: *mut usize,
) -> i32;

/// Raw C signature of `op_sdk_ipc_free_response`. The middle parameter is
/// read by the native code but not used by it (see the architecture
/// doc); passed through anyway so a future library version that starts
/// using it still gets a value consistent with `out_cap` above.
type RawFreeResponse = unsafe extern "C" fn(ptr: *mut u8, unused: usize, len: usize);

/// Everything that can go wrong loading the library or resolving its
/// symbols. Never a panic: 1Password Desktop may simply not be
/// installed, which is an ordinary, expected condition — not a
/// programming error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LoadError {
    /// No override and no candidate path pointed at a loadable library.
    #[error("1Password Desktop's IPC library was not found at any known location")]
    LibraryNotFound,

    /// The library loaded, but a required symbol could not be resolved —
    /// most likely an incompatible 1Password Desktop version (see
    /// "Version compatibility" in the architecture doc).
    #[error("1Password Desktop's IPC library is missing the required '{symbol}' symbol")]
    SymbolNotFound {
        /// Which symbol failed to resolve.
        symbol: &'static str,
    },
}

/// Everything that can go wrong on one `send_message` round trip through
/// the raw FFI. Carries only structural information — a byte length, a
/// native status code — never message contents, which may be secret.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RawIpcError {
    /// The native call returned a nonzero status. What each code means
    /// semantically is not decoded here (see the architecture doc) — the
    /// raw value is preserved so a caller can at least log/compare it.
    #[error("1Password Desktop's IPC library rejected the request (native status {0})")]
    Native(i32),

    /// The native call reported success, but the response it described
    /// is not self-consistent (length exceeding capacity, or a null data
    /// pointer) — treated as corrupt rather than trusted, and never read
    /// out of bounds.
    #[error("1Password Desktop's IPC library returned an inconsistent response")]
    MalformedResponse,
}

/// A loaded `libop_sdk_ipc_client.so`, with both required symbols
/// resolved.
pub struct IpcLibrary {
    // Kept only to keep the library mapped for as long as `send_message`/
    // `free_response` below remain valid to call; never read directly.
    _library: Library,
    send_message: RawSendMessage,
    free_response: RawFreeResponse,
}

impl std::fmt::Debug for IpcLibrary {
    // Manual, rather than derived: neither `libloading::Library` nor a
    // raw function pointer has anything meaningful to print, and
    // deriving would require both to implement `Debug` themselves.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcLibrary").finish_non_exhaustive()
    }
}

impl IpcLibrary {
    /// Locate and load the library: [`LIBRARY_PATH_OVERRIDE_ENV`] if set,
    /// otherwise the first working entry in [`CANDIDATE_PATHS`].
    ///
    /// # Errors
    ///
    /// [`LoadError::LibraryNotFound`] if no candidate loads;
    /// [`LoadError::SymbolNotFound`] if a required symbol is missing.
    /// Never panics.
    pub fn load() -> Result<Self, LoadError> {
        if let Ok(overridden) = std::env::var(LIBRARY_PATH_OVERRIDE_ENV) {
            return Self::try_load(Path::new(&overridden));
        }
        for candidate in CANDIDATE_PATHS {
            if let Ok(library) = Self::try_load(Path::new(candidate)) {
                return Ok(library);
            }
        }
        Err(LoadError::LibraryNotFound)
    }

    /// Load and resolve symbols from exactly the given path, with no
    /// candidate fallback. `pub(crate)`, not `pub`: production code only
    /// ever wants [`IpcLibrary::load`]'s discovery behavior; this is the
    /// seam this module's own tests, and the `ipc`/`session` test
    /// suites, use to point at a fixture library instead.
    pub(crate) fn try_load(path: &Path) -> Result<Self, LoadError> {
        // SAFETY: loading a dynamic library runs its own constructors,
        // the same trust boundary as any other dynamically linked
        // dependency this process loads — unavoidable for a plugin-
        // shaped integration that must not be statically linked (the
        // task's own constraint: never bundle this library).
        let library = unsafe { Library::new(path) }.map_err(|_| LoadError::LibraryNotFound)?;

        // SAFETY: symbol resolution only inspects the dynamic symbol
        // table; the returned pointer is stored, not called yet.
        let send_message: Symbol<RawSendMessage> = unsafe { library.get(SEND_MESSAGE_SYMBOL) }
            .map_err(|_| LoadError::SymbolNotFound {
                symbol: "op_sdk_ipc_send_message",
            })?;
        // SAFETY: same as above.
        let free_response: Symbol<RawFreeResponse> = unsafe { library.get(FREE_RESPONSE_SYMBOL) }
            .map_err(|_| LoadError::SymbolNotFound {
            symbol: "op_sdk_ipc_free_response",
        })?;

        // `Symbol` borrows from `library`; copy out the raw function
        // pointers (function pointers are `Copy`) so they can be stored
        // alongside `library` in the same struct, kept alive for exactly
        // as long as those pointers remain valid to call.
        let send_message = *send_message;
        let free_response = *free_response;

        Ok(Self {
            _library: library,
            send_message,
            free_response,
        })
    }

    /// Send `request`'s raw bytes to 1Password Desktop and return its raw
    /// response bytes, copied into an ordinarily-owned `Vec<u8>`.
    ///
    /// The native response buffer is freed via `op_sdk_ipc_free_response`
    /// before this method returns, on every path — success, native
    /// rejection, or a malformed response — via an RAII guard, never a
    /// manual "call it and hope" at the end of the function.
    ///
    /// This is a byte-level primitive only: it knows nothing about what
    /// bytes constitute a valid request or how to interpret a response's
    /// contents — that is the `ipc` module's job, one layer up.
    ///
    /// # Errors
    ///
    /// See [`RawIpcError`].
    pub fn send_message_raw(&self, request: &[u8]) -> Result<Vec<u8>, RawIpcError> {
        let mut out_len: usize = 0;
        let mut out_cap: usize = 0;
        let mut out_ptr: usize = 0;

        // SAFETY: `self.send_message` was resolved from the dynamic
        // symbol table at construction time and is called with exactly
        // the argument shapes `RawSendMessage` declares; `request`'s
        // pointer/length describe a valid, live `&[u8]` for the
        // duration of this call, and the three `out_*` locals are valid,
        // aligned, exclusively-borrowed slots for exactly that duration.
        let status = unsafe {
            (self.send_message)(
                request.as_ptr(),
                request.len() as isize,
                std::ptr::addr_of_mut!(out_len),
                std::ptr::addr_of_mut!(out_cap),
                std::ptr::addr_of_mut!(out_ptr),
            )
        };

        if status != 0 {
            return Err(RawIpcError::Native(status));
        }
        if out_ptr == 0 || out_len > out_cap {
            // A null data pointer or a length exceeding its own reported
            // capacity can never be a genuine successful response —
            // reject before ever forming a slice from it.
            return Err(RawIpcError::MalformedResponse);
        }

        // Guarantees `op_sdk_ipc_free_response` runs exactly once, on
        // every exit path from here on (including the copy below
        // panicking, which it should not barring OOM) — see its `Drop`.
        let guard = NativeResponseGuard {
            library: self,
            ptr: out_ptr as *mut u8,
            cap: out_cap,
            len: out_len,
        };

        // SAFETY: `guard.ptr`/`guard.len` were just validated as
        // self-consistent (`len <= cap`, non-null) values the native
        // call itself populated for a buffer it allocated and has not
        // yet freed (freed by `guard`'s `Drop`, after this read) — safe
        // to view as a byte slice for exactly the duration of the copy.
        let bytes = unsafe { std::slice::from_raw_parts(guard.ptr, guard.len) }.to_vec();

        drop(guard); // Frees the native buffer; `bytes` is already ours.
        Ok(bytes)
    }
}

/// Frees a native response buffer exactly once, on drop — used so
/// [`IpcLibrary::send_message_raw`] cannot return (successfully or not)
/// without having freed it, regardless of which path it takes.
struct NativeResponseGuard<'a> {
    library: &'a IpcLibrary,
    ptr: *mut u8,
    cap: usize,
    len: usize,
}

impl Drop for NativeResponseGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`cap`/`len` came directly from the successful
        // `send_message` call that constructed this guard, describe a
        // buffer the native library allocated, and have not been freed
        // yet — this is the one and only place that happens for them.
        unsafe { (self.library.free_response)(self.ptr, self.cap, self.len) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::onepassword::test_support::compile_fixture;

    /// A fixture that echoes its input back: allocates a same-size
    /// buffer, copies the request into it, and reports its true
    /// `(len, cap)` — a legitimate, self-consistent response by this
    /// module's own definition of one.
    const ECHO_FIXTURE: &str = r#"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int op_sdk_ipc_send_message(const uint8_t *req_ptr, intptr_t req_len,
                             size_t *out_len, size_t *out_cap, size_t *out_ptr) {
    if (req_len < 0) { return -1; }
    size_t len = (size_t)req_len;
    uint8_t *buf = (uint8_t *)malloc(len > 0 ? len : 1);
    if (len > 0) { memcpy(buf, req_ptr, len); }
    *out_len = len;
    *out_cap = len;
    *out_ptr = (size_t)(uintptr_t)buf;
    return 0;
}

void op_sdk_ipc_free_response(uint8_t *ptr, size_t unused, size_t len) {
    (void)unused;
    (void)len;
    free(ptr);
}
"#;

    /// A fixture exporting only `op_sdk_ipc_send_message`, to exercise
    /// [`LoadError::SymbolNotFound`] for the other required symbol.
    const SEND_MESSAGE_ONLY_FIXTURE: &str = r#"
#include <stdint.h>
#include <stddef.h>

int op_sdk_ipc_send_message(const uint8_t *req_ptr, intptr_t req_len,
                             size_t *out_len, size_t *out_cap, size_t *out_ptr) {
    (void)req_ptr; (void)req_len; (void)out_len; (void)out_cap; (void)out_ptr;
    return -1;
}
"#;

    #[test]
    fn loading_a_missing_library_reports_not_found_without_panicking() {
        let error =
            IpcLibrary::try_load(Path::new("/nonexistent/libop_sdk_ipc_client.so")).unwrap_err();
        assert_eq!(error, LoadError::LibraryNotFound);
    }

    #[test]
    fn a_library_missing_a_required_symbol_reports_which_one() {
        let dir = tempfile::tempdir().unwrap();
        let Some(path) = compile_fixture(dir.path(), SEND_MESSAGE_ONLY_FIXTURE) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let error = IpcLibrary::try_load(&path).unwrap_err();
        assert_eq!(
            error,
            LoadError::SymbolNotFound {
                symbol: "op_sdk_ipc_free_response"
            }
        );
    }

    #[test]
    fn a_complete_fixture_library_loads_and_round_trips_a_message() {
        let dir = tempfile::tempdir().unwrap();
        let Some(path) = compile_fixture(dir.path(), ECHO_FIXTURE) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let library = IpcLibrary::try_load(&path).unwrap();
        let response = library.send_message_raw(b"hello").unwrap();
        assert_eq!(response, b"hello");
    }

    #[test]
    fn an_empty_message_round_trips_to_an_empty_response() {
        let dir = tempfile::tempdir().unwrap();
        let Some(path) = compile_fixture(dir.path(), ECHO_FIXTURE) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let library = IpcLibrary::try_load(&path).unwrap();
        let response = library.send_message_raw(b"").unwrap();
        assert!(response.is_empty());
    }

    #[test]
    fn repeated_calls_free_each_native_response_without_leaking_or_crashing() {
        let dir = tempfile::tempdir().unwrap();
        let Some(path) = compile_fixture(dir.path(), ECHO_FIXTURE) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let library = IpcLibrary::try_load(&path).unwrap();
        // If `free_response` were skipped or called with the wrong
        // arguments, a sanitizer/valgrind run would flag this; even
        // without one, this at least proves repeated calls do not
        // crash or hang.
        for _ in 0..64 {
            let response = library.send_message_raw(b"round trip").unwrap();
            assert_eq!(response, b"round trip");
        }
    }

    #[test]
    fn load_honors_the_override_env_var() {
        let dir = tempfile::tempdir().unwrap();
        let Some(path) = compile_fixture(dir.path(), ECHO_FIXTURE) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        // SAFETY: this test does not run any other test in the same
        // process — `cargo nextest` isolates each test in its own
        // process, so this does not race with another test's own env.
        unsafe { std::env::set_var(LIBRARY_PATH_OVERRIDE_ENV, &path) };
        let library = IpcLibrary::load().unwrap();
        assert_eq!(library.send_message_raw(b"env").unwrap(), b"env");
    }
}
