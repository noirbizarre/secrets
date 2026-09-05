# 1Password Desktop native integration: investigation notes

Findings from investigating a native `OnePasswordBackend` for `secretsd`,
gathered against a real, installed 1Password Desktop (see "Environment"
below). This is a working document for a compatibility-sensitive adapter,
not a stable protocol specification — see "Compatibility risk" at the
end.

> **Update, same investigation session:** the sections below up to
> "Version compatibility" record the *first* pass, reconstructed purely
> from disassembly, and originally concluded the message schema was
> unrecoverable in one session. It was found shortly after, in the same
> session: 1Password publishes an official, MIT-licensed Go SDK
> (`github.com/1Password/onepassword-sdk-go`) whose Unix cgo bindings
> call the exact same two exported symbols, against the exact same
> library, to talk to the exact same Desktop integration this document
> is about. See "Confirmed wire protocol" below for the corrected,
> citation-backed account — it **supersedes** the FFI signature and "What
> remains unknown" sections that follow, which are kept only as a record
> of what disassembly alone could and could not establish.

## Chosen architecture

```text
secretsd
   |
   v
OnePasswordBackend        (crates/secretsd/src/backend/onepassword/, ADR-0008/0011)
   |
   v
secretsd's own IPC client   (crates/secretsd/src/backend/onepassword/{ffi,ipc,protocol,session}.rs)
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

> **Superseded by "Confirmed wire protocol" below.** Disassembly got the
> argument *count* and general shape right, but guessed the output
> parameter layout wrong: the real 3rd parameter is `uint8_t**` (a
> pointer to the data pointer), not a `usize` the pointer value is packed
> into, and the real parameter order is `(out_buf, out_len, out_cap)`,
> not `(out_len, out_cap, out_ptr)`. Kept below verbatim as a record of
> what disassembly alone produced, not as guidance to implement against.

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

> **Superseded by "Confirmed wire protocol" below.** The real signature
> is `(buf, len, cap)` and all three are meaningful — disassembly's
> "middle argument is ignored" reading was a misattribution of which
> register held which of the three words, not a real dead parameter.

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

## What the first disassembly-only pass left unknown

The single load-bearing unknown at that point: **the message body's own
wire format** — what bytes must be inside the `Vec<u8>` passed to
`send_to` for 1Password Desktop's IPC handler to accept it as a
legitimate "initialize a client" or "invoke an operation" request.
Nothing recovered by disassembly alone revealed this.

Five ad hoc probes were sent directly to the live socket to test cheap
framing hypotheses (bare JSON, 4-byte big-endian and little-endian
length-prefixed JSON, an empty write, and garbage bytes) before the Go
SDK was found. None of the raw bytes sent or received were persisted
anywhere (including here) — only the structural outcome:

| Hypothesis                          | Outcome                              |
| ------------------------------------ | ------------------------------------- |
| Bare `{}`, newline-terminated        | No response; connection stayed open   |
| 4-byte little-endian length + `{}`   | No response; connection stayed open   |
| 4-byte big-endian length + `{}`      | Connection closed immediately (EOF)   |
| Empty write (0 bytes)                | No response; connection stayed open   |
| A few garbage bytes                  | Connection closed immediately (EOF)   |

Inconclusive on its own — it turns out the framing guessed at here
(bare JSON, no length prefix) was directionally correct, but the *outer
envelope* (see below) needed to be present for the server to respond
usefully; a bare `{}` is not a valid envelope, hence no response.

## Confirmed wire protocol (via 1Password's official Go SDK)

1Password publishes an official, MIT-licensed Go SDK,
[`github.com/1Password/onepassword-sdk-go`](https://github.com/1Password/onepassword-sdk-go),
supporting exactly this scenario — its README documents `WithDesktopAppIntegration`
as a first-class authentication mode. Its Unix build
(`internal/shared_lib_core.go`, `//go:build cgo && (darwin || linux)`)
loads `libop_sdk_ipc_client.so`/`.dylib` and calls the exact same two
exported symbols this project uses, with a C signature stated directly
in its own cgo comment block. This is the authoritative source for
everything below — quoted/paraphrased from that file and
`internal/core.go`/`secrets.go` in the same repository, not re-guessed.

### The real FFI signature

```c
typedef int32_t (*send_message_t)(
    const uint8_t* msg_ptr,
    size_t msg_len,
    uint8_t** out_buf,
    size_t* out_len,
    size_t* out_cap
);
typedef void (*free_message_t)(
    uint8_t* buf,
    size_t len,
    size_t cap
);
```

Corrections versus the disassembly-only pass above: `msg_len` is
unsigned (`size_t`), not signed; the 3rd `send_message` parameter is a
pointer *to* the data pointer (`uint8_t**`), not a `usize` the pointer
value is packed into; the parameter order is `(out_buf, out_len,
out_cap)`; and `free_response` uses all three of `(buf, len, cap)`, not
two. `crates/secretsd/src/backend/onepassword/ffi.rs` was corrected to
match this exactly before ever calling the real library for real (see
its own module doc for the corrected types).

### The message envelope

Every message is one JSON object (`internal.Request`/`Response` in
`shared_lib_core.go`/`core.go`):

```jsonc
// Sent to op_sdk_ipc_send_message:
{
  "kind": "init_client" | "invoke" | "release_client",
  "account_name": "<1Password account name or account UUID>",
  "payload": "<base64 of an inner, kind-specific JSON payload>"
}
// Returned from it:
{ "success": true | false, "payload": "<base64>" }
```

`account_name` is required by the protocol itself (not an implementation
choice): the 1Password account name or account UUID as shown top-left in
the Desktop app's sidebar. On failure, the decoded `payload` is a plain
UTF-8 error message, not further JSON.

**`init_client`'s inner payload** (`internal.ClientConfig`):

```json
{
  "serviceAccountToken": "",
  "programmingLanguage": "Go",
  "sdkVersion": "...",
  "integrationName": "...",
  "integrationVersion": "...",
  "requestLibraryName": "net/http",
  "requestLibraryVersion": "...",
  "os": "linux",
  "osVersion": "0.0.0",
  "architecture": "amd64",
  "account_name": "<same account name/UUID as the outer envelope>"
}
```

Note `account_name` is the one field that is *not* camelCase, unlike
every sibling field — confirmed by reading the actual Go struct tags,
not assumed from the pattern. A successful response's decoded payload is
bare JSON for a `uint64` client ID (e.g. `42`), to be passed as
`clientId` in every subsequent `invoke` call for this client.

**`sdkVersion` is validated server-side and rejects a semver-looking
placeholder on its own** — found only by `strace`-comparing this
project's raw request bytes against the real Go SDK's own raw request
bytes on the same socket (see
`docs/architecture/1password-poc-results.md`'s "Root cause found"
section for the full story). The Go SDK sends a 7-digit build-number
string (its `//go:embed release/version-build` value, e.g. `"0040102"`
for its `v0.4.1` release) — not `"v0.4.1"`, not any other semver shape.
`protocol.rs`'s `CONFIRMED_SDK_VERSION` uses this exact confirmed value;
treat it as a compatibility-fragile magic value, not a stable constant —
see "Compatibility risk" below.

**`invoke`'s inner payload** (`internal.InvokeConfig`):

```json
{
  "invocation": {
    "clientId": 42,
    "parameters": {
      "name": "SecretsResolve",
      "parameters": { "secret_reference": "op://vault/item/field" }
    }
  }
}
```

`MethodName`/`SerializedParams` field names are `"name"`/`"parameters"`
(`internal.Parameters`), not the Go-side names. `secrets.go` confirms
`"SecretsResolve"` as the exact method name for resolving one `op://...`
reference, with `{"secret_reference": "..."}` as its only parameter. A
successful response's decoded payload is a JSON string (the resolved
value, quoted).

### Required prerequisite

1Password Desktop's own error strings, embedded in the Go SDK
(`errChannelClosed`/`errConnectionDropped` in `internal/core.go`), state
the channel stays closed unless **Settings → Developer → "Integrate with
other apps"** (or "Integrate with the 1Password SDKs") is enabled in the
Desktop app — a real, user-facing gate, not something request bytes can
route around.

### `crates/secretsd/src/backend/onepassword/protocol.rs`

Implements the envelope/payload construction and response parsing above,
verified by unit tests that assert on the exact JSON field names (a
typo here would silently build a request 1Password Desktop's own
deserializer rejects, with no useful diagnostic). Kept as its own module,
separate from `ipc.rs`'s deliberately protocol-agnostic `Request`/
`Response`, so the byte-level IPC primitive still does not need to know
what a legitimate message looks like — only `protocol.rs` does.

One detail confirmed only by running the real Step 8 probe, not by
reading the Go SDK's source: the outer envelope's `payload` field is
**not always** base64 text. On at least one internal-error response
path, the real Desktop app returned `payload` as a raw JSON array of
byte values instead — plausibly an early failure path that bypasses
whatever wraps normal responses in base64. `protocol.rs` decodes either
shape. See a forthcoming "POC results" document for the full run.

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

This still confirms the task's own framing: this is a
**compatibility-sensitive adapter, not a stable protocol** — 1Password's
Go SDK's own envelope/`ClientConfig`/`InvokeConfig` shapes are
implementation details of an "SDKs are in active development... version
0... possibility of breaking changes" project (the Go SDK's own README),
not a versioned wire contract either project commits to forever. This
project depends on it anyway, because it is the only source — official
or otherwise — that documents this Desktop-local channel at all; treat
every field name and the FFI signature above as due for re-verification
against whatever 1Password Desktop / SDK version is actually installed
when this stops working, not a fact to hard-code and forget.

With the message schema now confirmed rather than guessed, Step 8's real
invocation risk is substantially lower than it was when this document
first concluded the schema was unrecoverable: a malformed request is
still just rejected by 1Password Desktop's own input validation (the
`Err` path already observed above exists precisely for that), and there
is no evidence from this investigation of a crash risk to Desktop
itself. Step 8 proceeds using the confirmed protocol.

The single most fragile part confirmed by this investigation is
`sdkVersion` (`CONFIRMED_SDK_VERSION` in `protocol.rs`): a real, working
value was found only by capturing what one specific Go SDK release
(`v0.4.1`) actually sends, and 1Password Desktop's server-side
validation rejects anything it does not recognize with an opaque error
that names no specific field. If this integration ever starts failing
again with the same `HttpStatus(400)`/"delegated session" shape, this
field is the first thing to re-verify — the same way it was found here
(`strace` a current official SDK release, compare raw bytes).
</content>
