# 1Password Desktop native integration: investigation notes

Findings from investigating a native `OnePasswordBackend` for `secretsd`,
gathered against a real, installed 1Password Desktop (see "Environment"
below). This is a working document for a compatibility-sensitive adapter,
not a stable protocol specification — see "Compatibility risk" at the
end.

## Chosen architecture

```text
secretsd
   |
   v
OnePasswordBackend        (crates/secretsd/src/backend/onepassword/, ADR-0008/0011)
   |
   v
secretsd's own IPC client   (crates/secretsd/src/backend/onepassword/{ffi,ipc,session}.rs)
   |
   v
libop_sdk_ipc_client.so    (dynamically loaded, never bundled — Step 5)
   |
   v
1Password Desktop           (already-running process, owns auth/session/lock)
```

`secret://Personal/GitHub/password` maps internally to 1Password's own
`op://Personal/GitHub/password`-shaped addressing *inside*
`OnePasswordBackend` only — never on the public `secret://`/D-Bus
surface (per the task's constraints and ADR-0002/0005).

## Environment this was investigated against

- Distribution: Arch Linux (rolling), x86_64.
- 1Password Desktop: installed at `/opt/1Password/`, version 8.11.x
  (exact build not pinned by this document — see "Version compatibility"
  below for why that matters).
- 1Password Desktop was running normally (not specially instrumented)
  during the live-socket checks below.

## What is confirmed (not assumed)

### The library and its exported C symbols

`/opt/1Password/libop_sdk_ipc_client.so` exists and exports exactly two
C-ABI symbols relevant here (`nm -D`):

```text
napi_register_module_v1      # Node-API entry point — irrelevant to us
op_sdk_ipc_free_response
op_sdk_ipc_send_message
```

The library is statically linked from two private, unpublished Rust
crates, visible only via mangled symbol names (`nm` without `-D`, the
file is not stripped): `op_sdk_ipc_client` (the thin FFI/Neon-bindings
wrapper) and `onepassword_ipc_client` (the actual transport). Both are
built on the [`neon`](https://neon-rs.dev/) crate, i.e. this same `.so`
doubles as a Node native addon for 1Password's own Electron frontend
*and* exposes a plain C ABI for external, non-Node consumers like us.

No public crate or repository named `onepassword-ipc-client` (or
similar) was found on crates.io or elsewhere — contrary to this task's
initial assumption of an "official Rust IPC client" with some documented
and some undocumented endpoints, **the entire wire protocol described
below is undocumented anywhere public**. Everything past this paragraph
was reconstructed from the binary and from probing the live transport,
not read from any specification.

### The live transport

1Password Desktop's main process listens on an **abstract** (not
filesystem-backed) `SOCK_STREAM` Unix domain socket named literally
`1PASSWORD_SDK_INTERGATIONS` (that exact spelling — the "INTERGATIONS"
typo is preserved verbatim in the binary and is load-bearing, not a
documentation typo of ours):

```text
$ ss -xl | grep SDK
u_str LISTEN 0 4096   @1PASSWORD_SDK_INTERGATIONS   ...  users:(("1password",pid=...))
```

Confirmed two ways: live, against the actually-running process (`ss -x`
/ `/proc/net/unix`), and statically — the literal 26-byte string
`"1PASSWORD_SDK_INTERGATIONS"` is embedded in `libop_sdk_ipc_client.so`'s
`.rodata` at file offset `0x13a9c` and is passed by `(ptr, len=0x1a)` as
an argument at the exact call site described below, i.e. the library
that ships with Desktop is the thing hard-coding the name Desktop itself
listens on.

At the time of this investigation, **no running process on the system
had `libop_sdk_ipc_client.so` mapped into its address space** (checked
across every 1Password- and `op`-related process's `/proc/*/maps`) — so
there is no legitimate reference client to passively observe traffic
from; the only way to see real protocol traffic is to construct it
ourselves, which requires knowing the message schema this investigation
could not fully recover (see "What remains unknown").

Two unrelated sockets exist alongside it and must not be confused with
this one: `~/.1password/agent.sock` (the SSH agent 1Password itself
provides) and `/run/user/$UID/op-daemon.sock` (the separate `op` CLI's
own background daemon, owned by the `op` binary, not Desktop's IPC
surface).

### `op_sdk_ipc_send_message`'s signature and behavior (via disassembly)

`objdump -d --disassemble=op_sdk_ipc_send_message`, cross-referenced
against `readelf -r` to resolve its internal (non-exported, but
unstripped) callees by name, shows:

- A 5-argument C ABI: `(request_ptr, request_len, out1, out2, out3) -> i32`.
  `request_len` is treated as signed (`isize`); a negative value is
  rejected immediately. All of `request_ptr`, and the three `out*`
  pointers are null-checked up front (any null → returns `-1` before
  doing anything else); `request_len == 0` is handled as a valid,
  special-cased "empty message" rather than rejected.
- When `request_len > 0`, it **copies** the caller's bytes into a freshly
  heap-allocated buffer (`___rust_alloc` then `memcpy`) before doing
  anything else — so a caller's input buffer does not need to outlive
  the call.
- It then calls an internal function resolved (via `readelf -r`'s
  `R_X86_64_RELATIVE` relocations against the unstripped symbol table) to
  `onepassword_ipc_client::send_to`, passing what the calling convention
  and the confirmed literal string above make near-certain is
  `send_to(socket_name: &str, message: Vec<u8>) -> Result<Vec<u8>, E>`
  (the socket name `&str`'s `(ptr, len)` pair is passed in exactly the
  registers/order this call site uses; the `message: Vec<u8>` is passed
  indirectly, consistent with a 24-byte-wide `Vec<u8>` being too large
  for by-value register passing under the System V ABI).
- On the `Ok` branch (detected via a pointer-niche discriminant check
  against the sentinel `-1`, a standard Rust `Result` optimization when
  the success payload contains a non-null pointer): the returned
  `Vec<u8>`'s three raw parts (in the order `Vec::into_raw_parts()`
  documents: `ptr, len, cap`) are written across the three `out*`
  pointers, and the function returns `0`.
- On the `Err` branch: a single byte is read from the error payload and
  used as an index into a small lookup table, producing the returned
  `i32` error code. The table's size implies a **small, enumerable** set
  of native error codes, but decoding what each numeric value *means*
  was not attempted in this pass.

### `op_sdk_ipc_free_response`'s behavior

Three arguments `(ptr, _unused, len)`; the middle argument is read into a
register but never tested or used. If `ptr` and `len` are both non-null/
non-zero, it calls `___rust_dealloc(ptr, size = len, align = 1)`. Two
things worth flagging for Step 6's implementation:

- The middle output word from `send_message` (`out2`, which per the
  `into_raw_parts()` order above should be the response's *length*) does
  not obviously line up with which word `free_response` calls `len` in
  its own dealloc call — resolving this precisely (which of the 3 output
  words is fed to which of `free_response`'s 3 parameters) needs one more
  round of cross-checking before Step 6 calls this for real, to avoid
  passing the wrong size to `__rust_dealloc` (a correctness/memory-safety
  hazard, not just an API-shape question).
- This also means the response is presumably always shrunk-to-fit
  (`len == cap`) before being returned, or `free_response`'s ignored
  middle argument is genuinely dead code — not independently confirmed.

### Message chunking

A separate, confirmed-present function,
`onepassword_ipc_client::chunking::build_chunks`, splits a message into
pieces no larger than **499,999 bytes** (the constant `0x7a11f` is used
directly as a divisor when computing the chunk count) and returns a
`Vec<Vec<u8>>` — each element is exactly 24 bytes wide in memory, the
size of a bare `Vec<u8>`, meaning `build_chunks` itself adds no visible
per-chunk header/sequence metadata; if such metadata exists, it is added
by `send_to` when actually writing each chunk to the socket, which this
investigation did not trace further.

## What remains unknown

The single load-bearing unknown: **the message body's own wire format**
— what bytes must be inside the `Vec<u8>` passed to `send_to` for
1Password Desktop's IPC handler to accept it as a legitimate "initialize
a client" or "invoke an operation" request. Nothing recovered above
reveals this; it is a schema question (JSON? a length-delimited
multi-chunk envelope on top of raw bytes? bincode? protobuf?), not a
transport/FFI question, and the transport/FFI layer is as far as this
session's disassembly reached.

Five ad hoc probes were sent directly to the live socket to test cheap
framing hypotheses (bare JSON, 4-byte big-endian and little-endian
length-prefixed JSON, an empty write, and garbage bytes). None of the
raw bytes sent or received were persisted anywhere (including here) —
only the structural outcome:

| Hypothesis                          | Outcome                              |
| ------------------------------------ | ------------------------------------- |
| Bare `{}`, newline-terminated        | No response; connection stayed open   |
| 4-byte little-endian length + `{}`   | No response; connection stayed open   |
| 4-byte big-endian length + `{}`      | Connection closed immediately (EOF)   |
| Empty write (0 bytes)                | No response; connection stayed open   |
| A few garbage bytes                  | Connection closed immediately (EOF)   |

This is inconclusive — it contradicts a naive "it's just length-prefixed
JSON" theory more than it confirms one, and is not enough signal to
reconstruct a confident wire format. Recovering it with real confidence
would need decompiling `send_to`'s and `build_chunks`'s bodies in full
(their internal message-construction logic, not just their entry
signatures), which is a materially larger effort than this session's
time-box — realistically several further dedicated sessions, not "a few
more hours".

## Version compatibility

Everything above was reverse-engineered from one specific `.so` build
(BuildID `be1b73b2884df0c5705efea3a8323f576db9303c`, shipped with
1Password Desktop 8.11.x on this machine on the date at the top of this
document). The abstract socket name, the exported symbol names, the
chunk-size constant, and the argument layout are all things a future
1Password Desktop release could change without notice, since none of it
is a published, versioned API. Any real implementation built on this
must treat every one of these as an adapter detail to re-verify against
whatever Desktop version is actually installed, not a fact to hard-code
and forget — see `docs/security.md`'s "known MVP limitations" pattern for
how this project already documents this class of caveat elsewhere.

## Compatibility risk

This confirms the task's own framing exactly: this is a
**compatibility-sensitive adapter, not a stable protocol**. The FFI
envelope (Step 5/6's concern) is now reasonably well understood; the
message schema (Step 6/7's concern, specifically what bytes actually
constitute a valid "init" or "invoke" request) is not, and closing that
gap is the critical risk carried into Step 8/9. Calling
`op_sdk_ipc_send_message` for real against a user's live, running
1Password Desktop with a *guessed* request body is not equivalent in
risk to calling it with a confirmed one: worst case, a malformed request
is simply rejected by 1Password Desktop's own input validation (the
`Err` path already observed above exists precisely for that); there is
no evidence from this investigation of a crash risk to Desktop itself,
but confidence here is bounded by what one session's disassembly can
establish. Step 8 revisits this explicitly before performing a real,
one-time invocation.
</content>
