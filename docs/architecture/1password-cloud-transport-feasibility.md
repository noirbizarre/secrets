# 1Password Desktop-free cloud transport: feasibility investigation

Investigation into whether `secretsd` could talk to a user's normal
1Password account directly over the network — as another native 1Password
client, authenticated as the user — without requiring the 1Password
Desktop application to be installed and running. This is a research
report, not an implementation: nothing described here has been built.
It builds on, and should be read alongside,
[1password-integration.md](1password-integration.md) and
[1password-poc-results.md](1password-poc-results.md), which document the
Desktop IPC backend this project actually ships.

The brief this investigation answers explicitly excluded 1Password's
public Service Account API and 1Password Connect as sufficient answers —
the question is about acting as the user's own account, the same one used
normally from mobile, web, and desktop.

---

## 1. Executive summary

- **Facts, not inference:** the current `OnePasswordBackend` does not use
  any official 1Password Rust SDK crate. It dynamically loads the *same*
  native library (`/opt/1Password/libop_sdk_ipc_client.so`) that 1Password
  Desktop ships and that the official Go SDK's `cgo` path also dlopens, and
  speaks the same reverse-engineered JSON-over-abstract-Unix-socket protocol
  documented in `docs/architecture/1password-integration.md` and validated
  end-to-end in `docs/architecture/1password-poc-results.md`.
- **The key new finding of this investigation:** 1Password's own official Go
  SDK already contains a second, Desktop-free transport. `internal/core.go`
  defines a `Core` interface (`InitClient`/`Invoke`/`ReleaseClient`, byte-in
  byte-out) with **two** implementations selected at `NewClient()` time:
  `SharedLibCore` (dlopen the native `.so`, talk to Desktop — what `secretsd`
  already reimplements) and **`ExtismCore`** (`internal/extism_core.go`),
  which loads an **embedded 9.5 MB WASM binary** (`internal/wasm/core.wasm`,
  loaded via the [Extism](https://extism.org) WASM plugin runtime) that runs
  1Password's actual SDK-core logic **in-process**, with network access
  restricted by an `AllowedHosts` allow-list (`*.1password.com`, `.ca`,
  `.eu`, plus internal staging domains) provided by Extism's built-in HTTP
  capability — not a custom host function. This proves 1Password's own
  client-protocol/crypto engine is portable, native-code-free, and capable
  of talking directly to 1Password's cloud **today, in the official SDK**,
  with zero dependency on Desktop.
- **The catch, originally:** `ExtismCore` is wired, in the public Go SDK
  *API surface*, to exactly one non-Desktop credential shape: a **Service
  Account token** (`ClientConfig.SAToken`). No field, method, or code path
  in the public Go source feeds a normal user's master password / Secret
  Key into `ExtismCore`.
- **Binary-inspection finding that changes the picture materially (this
  investigation session, not inference — done by downloading the actual
  `internal/wasm/core.wasm` artifact from the `main` branch and parsing its
  WASM export/string tables directly, since `wasm2wat`/`wasm-objdump` were
  not available in this environment; a from-scratch WASM export-table
  parser and `strings -n 4/5/6` were used instead):** the *compiled*
  `core.wasm` is **not** scoped to Service-Account-only logic. Its string
  table contains full, unstripped Rust mangled symbol names revealing that
  the entire user-authentication protocol is compiled in, as real,
  first-class Rust crates — not vestigial or dead code:
  - `op_srp` — a complete SRP implementation (`SrpGroup`, group parameter
    literal `"SRPg-4096"`, `X::start_auth`, `BigB`, `ServerHash`,
    `Exchange<Started>::received_server_user_b`,
    `Exchange<PendingVerification>::received_server_hash`).
  - `op_crypto::muk::Muk::derive_srp_x_key` — derives the SRP `x` value
    (and the Master Unlock Key) from **exactly** the publicly-documented
    inputs (Secret Key + account password), i.e. the same derivation
    `support.1password.com/1password-security`/`secret-key-security`
    describes in prose.
  - `op_sdk_b5_client` — a full client for 1Password's real backend
    ("B5"), with `UnauthenticatedB5Client`/`AuthenticatedB5Client`,
    `UnauthenticatedSession`/`AuthenticatedSession`,
    `auth_flow::authenticate_session`, `routes::auth::lookup_auth`,
    `routes::auth::complete_auth`, `AuthProvider::compute_srp_x`, and
    `AuthenticatedSession::decrypt_response` (evidence of an
    **application-layer encryption envelope on top of TLS**, not TLS
    alone).
  - A `ServiceAccountCredentials` struct, confirmed to have **8 fields**
    from its own serde-derived string table:
    `signInAddress, email, secretKey, srpX, muk, userAuth, deviceUuid,
    throttleSecret` — i.e. what the Go SDK's single opaque `SAToken`
    string decodes to internally is a full SRP-ready credential bundle
    (email/sign-in address, the raw Secret Key, a *precomputed* `srpX`
    and `muk`, plus device/session-throttling identifiers), not a bare
    bearer token in the OAuth sense.
  - `op_sdk_core::invocations::{AuthenticatedInvocation,
    UnauthenticatedInvocation, handle_authenticated_invocation,
    handle_unauthenticated_invocation}` — confirms only **two** operations
    (`ValidateSecretReference`, `GeneratePassword`) run unauthenticated;
    every other operation (`SecretsResolve`, `VaultsList`, `ItemsGetAll`,
    `ItemsCreate`, vault/group/share management, etc. — ~29 variants
    enumerated in the string table) requires the `AuthenticatedSession`
    this SRP flow produces.
  - `op_sdk_decrypted_item_api::unlocker::AccountUnlocker::
    get_vaults_unlock_keys` — confirms per-vault key unwrapping also
    happens inside this same WASM core, not server-side, consistent with
    1Password's E2E encryption claims.
- **What this means, precisely:** the cryptographic/protocol engine needed
  to authenticate as a full account (not a Service Account) already exists,
  compiled, licensed-in-the-same-repository-as-MIT, and reachable — it is
  simply not exposed by the Go SDK's typed public API, which only ever
  constructs the equivalent of a `ServiceAccountCredentials` value from an
  opaque pre-issued token string. This is a **materially smaller gap**
  than "reimplement SRP/PAKE from scratch": the missing pieces are (a) the
  exact wire/serialization format of the `SAToken` string (to confirm it
  really is a serialized `ServiceAccountCredentials` and learn its
  encoding), (b) whether substituting a normal personal account's
  `email`/`secretKey` (with `srpX`/`muk` derived locally via the same
  `derive_srp_x_key`, exactly as this code already does) in place of a
  Service Account's values produces a request 1Password's real B5 backend
  actually accepts, and (c) what `deviceUuid`/`throttleSecret` need to be
  for a *personal* account — these plausibly tie into 1Password's known,
  separate, interactive "verify this new device" email/link flow for
  first-time personal-account sign-in, which is a genuinely distinct,
  still-undocumented server-side authorization step a pre-provisioned
  Service Account does not need to go through. None of (a)-(c) were
  resolved in this pass — see §12.
- **Classification (see §11 for full reasoning): Orange — feasible only by
  reverse-engineering parts of the native client protocol**, but narrower
  in scope than initially assessed: not "reimplement an undocumented PAKE
  protocol," but "reverse-engineer one credential-bundle encoding and
  validate server-side acceptance of substituted personal-account fields
  against machinery that already fully exists, compiled and MIT-adjacent,
  in the public SDK." The remaining risk is concentrated in the
  server-side authorization semantics (device verification / throttling)
  for first-time personal-account sign-in, not in the cryptography itself.
- **Smallest-code-to-remove-Desktop answer (§11, final question):** if the
  goal is narrowed to "the same capability the SDK already supports without
  Desktop" (Service Account access), the answer is close to zero new code:
  wire a `service_account_token` config option into `OnePasswordBackend`
  and send `serviceAccountToken` instead of `account_name` in the existing
  `init_client` envelope — everything else in `ffi.rs`/`ipc.rs`/
  `protocol.rs`/`session.rs`/`backend.rs` is transport-agnostic already. If
  the goal is the full "acts as the user, without Desktop" capability as
  stated, there is no small amount of code — it requires reimplementing an
  undocumented, closed-source authentication protocol first.

---

## 2. Current `secrets` architecture (facts, from direct code reading)

```text
secretsd
  |
  v
OnePasswordBackend (backend.rs)          <- only file depending on secrets_core
  |  builds op:// references, maps errors/field kinds
  v
SessionManager (session.rs)              <- single-flight auth, TTL, client_id lifecycle
  |  Authenticator trait -> OnePasswordAuthenticator::authenticate()
  v
IpcClient (ipc.rs)                       <- protocol-agnostic byte-in/byte-out + timeout thread
  |  Request(Vec<u8>) / Response(Vec<u8>), never Debug-prints bytes
  v
protocol.rs                              <- the ONLY file that knows the JSON wire schema
  |  Envelope{kind, account_name, payload(base64)}, ClientConfig, InvokeConfig
  v
IpcLibrary (ffi.rs)                      <- dlopen/dlsym via `libloading`, all `unsafe` confined here
  |  op_sdk_ipc_send_message / op_sdk_ipc_free_response (C ABI, corrected against Go SDK cgo header)
  v
/opt/1Password/libop_sdk_ipc_client.so   <- 1Password's own native lib (statically links private
  |                                          `op_sdk_ipc_client` + `onepassword_ipc_client` crates,
  |                                          built on `neon`; doubles as a Node addon)
  v
abstract Unix socket @1PASSWORD_SDK_INTERGATIONS  <- literal typo, confirmed live + in .rodata
  v
1Password Desktop process (already running, owns auth/session/lock, does its own HTTPS to 1Password cloud)
```

Layer responsibilities, exact source:

| Layer | File | Owns |
|---|---|---|
| Domain adapter | `backend.rs` | `Backend`/`BackendSession` impl, `op://` construction, error/field-kind mapping. Only file touching `secrets_core`. |
| Session lifecycle | `session.rs` | `SessionSnapshot` state machine, single-flight auth via `Mutex`+`Condvar`, TTL (`DEFAULT_SESSION_TTL = 5min`), `client_id: u64` (not a secret). |
| Wire protocol | `protocol.rs` | JSON envelope/payload shapes, `CONFIRMED_SDK_VERSION = "0040102"` (Go SDK v0.4.1's internal build string — required or Desktop's server-side session delegation rejects with HTTP 400), response parsing (dual base64/raw-array payload decoding). |
| Byte transport | `ipc.rs` | `Request`/`Response` opaque byte wrappers, timeout-bounded thread-based invocation, redacting `Debug`. |
| FFI | `ffi.rs` | `libloading`-based dlopen/dlsym of exactly 2 symbols, `NativeResponseGuard` RAII free, `LIBRARY_PATH_OVERRIDE_ENV` for tests. |
| Response types | `types.rs` | Deserialize-only structs; **deliberately never declare 1Password's `value` field**, so secret values are dropped by serde before ever being named. |

Dependencies actually used: `libloading = "0.8.9"`, `base64`, `serde`/`serde_json`, `thiserror`,
`zeroize` — **no** 1Password crate of any kind (confirmed: zero matches in `Cargo.lock` for
`onepassword|op-sdk|op_sdk|1password`). No `build.rs`, no vendored native libraries, no bindgen.

This is already fully consistent with ADR-012 (native IPC over shelling out to `op` CLI, to
respect ADR-001's "D-Bus is the only IPC mechanism" rule at the `secretsd`-external boundary)
and ADR-011 (`BackendSession` for backend-owned session/lock state).

---

## 3. 1Password SDK/Core architecture (from the official Go SDK, `github.com/1Password/onepassword-sdk-go`, current `main`)

```text
onepassword-sdk-go (Go, MIT)
  |
  +-- Client / *API wrappers (client.go, secrets.go, vaults.go, items.go, ...)
        |
        v
      internal.CoreWrapper  (internal/core.go)   <-- THE TRANSPORT ABSTRACTION
        |  JSON-marshals ClientConfig/InvokeConfig -> []byte, calls Core.InitClient/Invoke/ReleaseClient
        |
        +-- internal.Core interface { InitClient, Invoke, ReleaseClient }
              |
              +-- SharedLibCore (shared_lib_core_unix.go / _windows.go)
              |     cgo dlopen/dlsym of libop_sdk_ipc_client.so/.dll
              |     -> op_sdk_ipc_send_message/op_sdk_ipc_free_response
              |     -> abstract Unix socket -> Desktop process -> Desktop's own HTTPS to 1Password cloud
              |     Selected when: WithDesktopAppIntegration(accountName) is set.
              |
              +-- ExtismCore (extism_core.go)                     <-- THE UNDOCUMENTED FINDING
                    loads embedded internal/wasm/core.wasm (9.5 MB) via github.com/extism/go-sdk
                    WASM exports called by name: "init_client", "invoke", "release_client"
                    Host imports provided (internal/imported.go): random_fill (CSPRNG), unix time,
                      tz offset — NO custom HTTP host function.
                    Network access to 1Password's own cloud is via Extism's *built-in* HTTP
                      capability, gated by manifest.AllowedHosts:
                        *.1password.com, *.1password.ca, *.1password.eu,
                        *.b5staging.com, *.b5dev.com/.ca/.eu, *.b5test.com/.ca/.eu,
                        *.b5rev.com, *.b5local.com   (all internal 1Password backend domains)
                    Selected when: WithServiceAccountToken(token) is set (today's only public trigger).
```

**This answers investigation objective #2 directly:** yes, there is a real
internal transport abstraction (`internal.Core`), and yes, the Desktop IPC
path is *literally* just one adapter behind it — `ExtismCore` is the other,
and it is a **direct cloud transport with no Desktop dependency**, running
today, in production, in the official SDK, for Service-Account auth.

**What `ExtismCore` proves architecturally (facts):**

1. 1Password's actual SDK-core "business logic" (request building, response
   parsing, the method dispatch behind names like `SecretsResolve`,
   `VaultsList`, `ItemsList`, `GeneratePassword`, `EnvironmentsGetVariables`)
   is portable, native-toolchain-free code (compiles to `wasm32`), shipped
   as a single binary artifact embedded directly in the Go module via
   `//go:embed`.
2. That same core, when it needs to talk to 1Password's cloud, does so with
   an ordinary outbound HTTPS call to a 1Password-owned domain, gated only
   by an allow-list — i.e., whatever wire protocol it uses **from the WASM
   sandbox to 1Password's cloud is unremarkable HTTP(S)**, not some special
   OS-level or hardware-bound channel. (Objective #3's protocol question is
   *partially* answered by this: HTTPS, not gRPC/QUIC/WebSocket, at least
   for this code path — see §6 for the important caveat about what this
   does and does not cover.)
3. The *identical* `ClientConfig`/`InvokeConfig` JSON schema and identical
   `invoke` method names are used by both `SharedLibCore` and `ExtismCore` —
   confirming `protocol.rs` in this repo is reimplementing the **transport-
   independent** part of 1Password's protocol, not something Desktop-
   specific. This is strong evidence that `secretsd`'s `protocol.rs` would
   need little to no change if a cloud transport were substituted for the
   FFI/IPC layers — see §9.

---

## 4. Authentication flow — mapped precisely, with an explicit unresolved boundary

Two authentication modes exist in the public SDK today; a third exists only
in 1Password's other, closed-source clients.

### 4a. Service Account token (public, documented, `ExtismCore`)

- A Service Account token is generated out-of-band via 1Password's web
  dashboard (`my.1password.com/developer-tools/...`), is a static bearer
  credential, is scoped to specific vaults, and is passed as
  `ClientConfig.SAToken`.
- `secretsd`/`OnePasswordBackend` **does not use this today** (only
  `account_name` is populated; `serviceAccountToken` is always sent empty).
- Explicitly excluded by the user's brief as "not sufficient" — it does not
  authenticate *as the user's normal account*, only as a scoped, separate
  identity the user must provision and manage.

### 4b. Desktop-delegated session (what `secretsd` implements today)

- `secretsd` never sees a password, Secret Key, or long-lived token. It
  sends `{account_name, integrationName, integrationVersion, sdkVersion=
  "0040102", ...}` and Desktop:
  1. Shows a one-time human-facing "Integrate with other apps" approval
     prompt per integration name (confirmed live in
     `1password-poc-results.md`).
  2. Internally calls what its own error strings name a **"delegated
     session"** — Desktop performs an HTTPS call to 1Password's backend
     *on behalf of* the already-signed-in user, using session state Desktop
     itself already holds (the user signed into Desktop normally, with
     their master password + Secret Key, at some earlier point — outside
     this protocol entirely).
  3. Returns an opaque `client_id: u64` — "1Password's own session handle,
     not a credential" (session.rs comment, confirmed correct: it carries
     no cryptographic material, it's a lookup key into Desktop's own
     process memory).
  4. All subsequent `invoke` calls (e.g. `SecretsResolve`) are dispatched
     by Desktop using the credentials/keys it already has decrypted in its
     own memory — `secretsd` never receives or handles an encryption key.
- **Conclusion:** Desktop is not "merely" a dumb transport relay for this
  mode — it is the thing holding the actual cryptographic session/keys.
  `secretsd`'s current design is correctly described in its own docs as
  depending on Desktop for both transport *and* authentication/authorization
  in this mode; the "delegated session" HTTPS call *from Desktop to
  1Password's cloud* is exactly the network protocol objective #3 asks
  about, but this investigation has no way to observe its wire format
  without deeper instrumentation of Desktop itself (see §12) — only that it
  exists, is HTTPS, and is gated by a per-account/session concept
  1Password's own error text calls "delegation."

### 4c. Full interactive user login (what would be needed for the user's actual ask — NOT present in the public SDK)

- Publicly documented (not inferred) via 1Password's Security Design
  materials (`support.1password.com/1password-security`,
  `support.1password.com/secret-key-security`,
  `support.1password.com/secure-remote-password`):
  - A 128-bit **Secret Key**, generated locally at account creation, never
    transmitted, combined with the user's **account password**.
  - **PBKDF2-HMAC-SHA256** key stretching of the account password.
  - **SRP (Secure Remote Password)**, a PAKE protocol, used so the
    password itself is never sent over the network during sign-in.
  - Resulting keys decrypt a local, end-to-end-encrypted vault; data at
    rest/in transit is AES-GCM-256.
- **This flow is not exposed anywhere in `onepassword-sdk-go`'s Go source**
  — no field for a Secret Key or account password exists in `ClientConfig`,
  no method resembling "sign in"/"authenticate with credentials" is called
  from Go.
- **Resolved by binary inspection (this session — see the Executive Summary
  finding above and §12's methodology): the logic itself is not absent.**
  Direct inspection of `internal/wasm/core.wasm`'s string table shows the
  full SRP handshake, the Secret-Key/MUK derivation, and a real client for
  1Password's backend ("B5") compiled in as first-class Rust crates:
  `op_srp` (SRP-4096 group, `X::start_auth`, `BigB`, `ServerHash`,
  `Exchange<Started>`/`Exchange<PendingVerification>` state machine),
  `op_crypto::muk::Muk::derive_srp_x_key`, and `op_sdk_b5_client`
  (`UnauthenticatedB5Client`/`AuthenticatedB5Client`,
  `auth_flow::authenticate_session`, `routes::auth::{lookup_auth,
  complete_auth}`, `AuthenticatedSession::decrypt_response`). A
  `ServiceAccountCredentials` struct (8 fields: `signInAddress, email,
  secretKey, srpX, muk, userAuth, deviceUuid, throttleSecret`) is the
  actual shape `ClientConfig.SAToken` decodes into internally — i.e. what
  the Go SDK calls a "token" is a serialized bundle containing the same
  `email`/`secretKey` a personal account has, plus precomputed `srpX`/
  `muk` values derivable (via the very same `derive_srp_x_key` function)
  from a personal account's Secret Key and master password.
- **What remains genuinely unresolved (not a code-presence question
  anymore, an encoding/authorization question):**
  1. The exact serialization/encoding of the `SAToken` string into a
     `ServiceAccountCredentials`-shaped value (format, versioning, any
     integrity/MAC wrapping) — not determined in this pass.
  2. Whether 1Password's real B5 backend authorizes an `authenticate_session`
     call carrying a *personal* account's `email`/`secretKey`-derived
     fields the same way it does for a Service Account's, or whether
     server-side account-type/device-registration checks reject it.
  3. What `deviceUuid`/`throttleSecret` need to be for a personal account —
     plausibly tied to 1Password's separate, publicly-observable-but-
     undocumented-at-the-protocol-level "verify this new device" email/link
     flow that personal accounts go through on first sign-in from a new
     client, which a pre-provisioned Service Account is not known to
     require.
  None of these three are "is the crypto present" questions (settled: yes)
  — they are "does 1Password's server accept a personal-account-shaped
  version of a payload structurally identical to one it already accepts"
  questions, only answerable by constructing and sending such a payload,
  which this investigation does not do (see §12).

---

## 5. Desktop IPC flow (for completeness — already documented in-repo)

Fully covered by `docs/architecture/1password-integration.md` (confirmed
live + via the Go SDK's own cgo source) and reproduced in §2/§3 above:
abstract Unix socket `@1PASSWORD_SDK_INTERGATIONS`, JSON envelope
(`{kind, account_name, payload}`), two C-ABI symbols
(`op_sdk_ipc_send_message`/`op_sdk_ipc_free_response`), chunking above
499,999 bytes handled inside the native library, not by callers.

---

## 6. Cloud/network protocol findings — what is confirmed vs. still unknown

**Confirmed (from `ExtismCore`, i.e. the Service-Account cloud path):**

- Protocol: ordinary HTTPS (Extism's built-in HTTP capability is a
  synchronous request/response HTTP client, not gRPC/WebSocket/QUIC).
- Endpoints: gated to `*.1password.com`, `.ca`, `.eu`, plus internal
  `b5{staging,dev,test,rev,local}.{com,ca,eu}` domains — "B5" is
  1Password's long-standing internal backend codename (consistent with
  public knowledge from 1Password engineering blog posts referencing "B5"
  as their account-hosting service name).
- Whether this is REST-shaped JSON, or some other envelope, over that
  HTTPS call is **not fully determined** — Extism's HTTP capability is
  generic; the exact request/response byte format was not decompiled.
  However, `op_sdk_b5_client::AuthenticatedSession::decrypt_response` (a
  real, named symbol in the binary) proves there is an **application-layer
  decryption step applied to responses on top of whatever the HTTPS/TLS
  transport already provides** — i.e. 1Password does not rely on TLS alone
  even for its own official client; response bodies carry a second,
  session-derived-key encryption layer. This is a fact worth carrying into
  any reimplementation attempt: matching only the JSON/HTTPS shape is not
  sufficient, the payload-level encryption scheme must match too.
- The B5 client also structurally distinguishes `UnauthenticatedB5Client`
  (used for `lookup_auth`/`complete_auth`, i.e. the SRP handshake itself,
  before a session exists) from `AuthenticatedB5Client` (used for every
  `AuthenticatedInvocation`, i.e. actual data operations) — a clean two-
  phase design mirroring SRP's own two-phase (identify-then-verify)
  structure.

**Not confirmed / explicitly out of scope of what source-reading can show:**

- What protocol Desktop itself uses for its "delegated session" HTTPS call
  (§4b) — could be the same REST-ish protocol as `ExtismCore`'s, could
  differ. No evidence either way without instrumenting a running Desktop
  process (packet capture/TLS interception), which was not performed as
  part of this investigation and is a legally/ethically distinct action
  from reading public source code (see §10).
- Whether 1Password's real backend ("B5") protocol for authenticated,
  non-service-account sessions is JSON/REST, protobuf, or something else.
  No protobuf/gRPC generated code, `.proto` files, or HTTP/2-specific
  client configuration was found anywhere in the Go SDK or its
  dependencies (`go.sum` — checked for `google.golang.org/grpc`,
  `google.golang.org/protobuf`: not present as direct or Extism-transitive
  dependencies of the parts inspected).

---

## 7. Feasibility table

| Capability | Current Desktop path | Existing Core support (no Desktop) | Public API | Needs reimplementation |
|---|---|---|---|---|
| Authenticate as the user's normal account | Desktop-delegated session (client_id handle) | **Partially** — the SRP/MUK/B5-client machinery (`op_srp`, `op_crypto::muk`, `op_sdk_b5_client`) is compiled into `core.wasm` and used today, but only ever fed a `ServiceAccountCredentials`-shaped value via the opaque `SAToken` string; no public path constructs that value from a personal `email`+`secretKey`+password | No (Go SDK exposes only `SAToken`) | **Encoding + server-acceptance reverse-engineering**, not cryptographic reimplementation — see §4c |
| Authenticate as a Service Account | N/A (unused) | **Yes** — `ExtismCore` + `SAToken` | Yes (documented) | No |
| List accounts | Implicit (single account by name/UUID) | Not exposed via Go SDK at all | No | Unknown — no `invoke` method name observed for this |
| List vaults | `VaultsList` invoke, via Desktop | Same `invoke` method name works over `ExtismCore` once authenticated | Yes (`vaults.go`) | No — same schema, just needs a valid client/session either way |
| List items | `ItemsList` invoke | Same | Yes (`items.go`) | No |
| Fetch item | `ItemsGetAll`/individual get | Same | Yes | No |
| Resolve secret reference | `SecretsResolve` invoke | Same (works identically over `ExtismCore` with SA auth today) | Yes (`secrets.go`) | No |
| Decrypt item | Happens server/Desktop-side, never in `secretsd` | Happens inside `core.wasm`/server, never in caller | N/A | No — by design, this is intentionally never client-observable plaintext logic to reimplement |
| Session refresh | Desktop reissues `client_id` on `DesktopSessionExpiredError` (Go SDK's `clientInvoke` retries `InitClient` once) | `ExtismCore` re-inits similarly, no Desktop-specific concept | Partially (retry logic is in Go SDK, not a documented API) | No, for SA path; Yes, for user-auth path (session lifecycle for that credential type is undefined) |

**Reading this table:** every capability *except authentication itself* is
already schema-identical across both transports and already implemented in
`protocol.rs`/`types.rs`/`backend.rs`. The entire gap is the credential/
session-establishment step.

---

## 8. Transport abstraction findings

> "Is the Desktop IPC connection merely an adapter around a deeper client/
> session/protocol implementation?"

**Yes, confirmed, not inferred.** `internal.Core` (Go interface) /
`internal.CoreWrapper` is exactly this abstraction in the official SDK, and
`secretsd`'s own `ffi.rs`/`ipc.rs` boundary already mirrors it structurally
(a byte-in/byte-out seam with the JSON schema living one layer up, in
`protocol.rs`). `secretsd` independently arrived at the same layering
1Password itself uses internally — this is a good sign for §9's proposed
design, not a coincidence to be suspicious of, since both are constrained
by the same JSON schema on one side and "some byte-oriented executor" on
the other.

---

## 9. Proposed Rust architecture (design only, not implemented)

Insert the seam at exactly the boundary `ffi.rs`/`ipc.rs` already establish,
without touching `protocol.rs`, `session.rs`, `types.rs`, or `backend.rs`'s
public shape:

```rust
// crates/secretsd/src/backend/onepassword/transport.rs (new)
//
// Why a trait here and not a bigger refactor: protocol.rs already proved
// (see docs) that the JSON schema is transport-independent — Desktop IPC
// and 1Password's own ExtismCore send/receive byte-identical envelopes.
// The only thing that varies is how a `Request`'s bytes reach 1Password
// and how a `Response`'s bytes come back; `ipc::IpcClient` already
// encapsulates exactly that half of the current design.
pub trait OnePasswordTransport: Send + Sync {
    fn invoke(&self, request: &crate::backend::onepassword::ipc::Request)
        -> Result<crate::backend::onepassword::ipc::Response, TransportError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("...")] Ipc(#[from] super::ipc::IpcError),
    #[error("...")] Cloud(#[from] CloudTransportError), // new variant, only if/when built
}
```

- `IpcClient` (today's `ffi`+`ipc` stack) becomes one implementor:
  `impl OnePasswordTransport for IpcClient`.
- `SessionManager::execute`'s closure signature changes from
  `FnOnce(&IpcClient, u64)` to `FnOnce(&dyn OnePasswordTransport, u64)` —
  a small, mechanical change; everything inside `backend.rs`'s call sites
  (`protocol::init_client_request(...)`, `client.invoke(&request)`) is
  unchanged because it already only calls `.invoke()`.
- A hypothetical `CloudTransport` (only buildable once §4c's authentication
  gap is closed) would live beside `ffi.rs`/`ipc.rs`, e.g.
  `cloud.rs`/`cloud_auth.rs`, and would need:
  - **HTTP client**: given §6's finding (ordinary HTTPS, not gRPC), a
    `reqwest` or `hyper`-based async client is a better fit than `tonic`;
    there is no evidence of protobuf/gRPC anywhere in this protocol family,
    so proposing `tonic` would be over-engineering not supported by the
    evidence.
  - **Async/sync boundary**: today's `IpcClient::invoke` is deliberately
    sync-with-a-thread (ipc.rs's own comment: FFI calls are blocking and
    uncancellable). A `CloudTransport` built on an async HTTP client would
    need the same "spawn + bounded join" pattern `ipc.rs` already uses, or
    `secretsd` would need an async runtime boundary decision made once,
    centrally — out of scope to decide here, flagged as a real design
    fork.
  - **TLS**: standard `rustls`/`webpki-roots`, certificate pinning would be
    an explicit added risk (see §10) not present in today's design.
  - **Auth/session**: an `Authenticator` implementation parallel to
    `OnePasswordAuthenticator`, but its `authenticate()` would need to
    perform whatever §4c's handshake turns out to require — this is where
    all the actual new work is, not in the transport shape. Given §4c's
    finding, this does **not** necessarily mean writing an SRP client from
    scratch in Rust: if `core.wasm` (or its licensing-permitting equivalent)
    can be embedded the same way `ExtismCore` embeds it, `authenticate()`
    could be "construct a `ServiceAccountCredentials`-shaped JSON payload
    from a personal account's fields and call the WASM `init_client` export
    with it" — i.e. reuse 1Password's own compiled SRP/MUK/B5-client code
    rather than reimplementing it, *if* §12's unknowns resolve favorably.
  - **Secure memory**: any credential material a cloud transport would hold
    (unlike today's design, which holds none) must be `Zeroize`/
    `ZeroizeOnDrop` per this repo's non-negotiable invariant #4 — a new,
    real obligation the current Desktop-delegated design does not have.
  - **Retry/error mapping**: `CallError`/`map_generic_error` in `backend.rs`
    would gain new variants for HTTP-layer failures (timeouts, TLS errors,
    HTTP 4xx/5xx) analogous to today's `IpcError`/`RawIpcError` handling.

This design changes roughly 3 files mechanically (`session.rs`'s generic
bound, a new `transport.rs`, `mod.rs`'s exports) and adds zero risk to the
existing Desktop path — but a working `CloudTransport` cannot be completed
until §4c is resolved, so this section is a shape, not a schedule.

---

## 10. Security analysis

- **Attack surface:** a second client authenticated as the *actual user
  account* (not a scoped Service Account) is strictly more sensitive than
  today's design — today, `secretsd` never holds any 1Password credential
  or key at all (Desktop does). A `CloudTransport` implementing §4c would
  necessarily hold session/derived-key material in `secretsd`'s own memory
  for the first time in this backend's history. That is a new plaintext-
  in-memory boundary this project does not currently have for 1Password,
  and directly implicates non-negotiable invariant #4
  (`Zeroize`/`ZeroizeOnDrop`).
- **Plaintext locations:** today, decrypted values only ever exist inside
  1Password Desktop's own process and briefly in `secretsd`'s IPC response
  buffers (already flagged as a known limitation in `docs/security.md`). A
  cloud transport would not change *where* decryption happens (still
  server/`core.wasm`-side, based on `ExtismCore`'s evidence) but would add
  a new **authentication key material** plaintext location that does not
  exist today.
- **Bypassing an intentional boundary?** Yes, partially, by design intent:
  1Password's Desktop-delegated-session approval prompt (§4b) is an
  explicit, human-facing consent gate ("Integrate with other apps").
  Implementing §4c would let `secretsd` act as a full account client
  without ever routing through that consent gate, because it would not be
  using Desktop's session at all. This is not "hacking around" a technical
  restriction — the SRP/Secret-Key protocol has no such gate baked in (any
  1Password client that has your Secret Key + password can authenticate);
  but it does remove the one piece of interactive user oversight the
  current, Desktop-delegated design uniquely provides. Worth surfacing to
  the project owner as a deliberate trade-off, not just an engineering one.
- **Would it weaken 1Password's own guarantees?** Not the E2E encryption
  itself (decryption still happens server/core-side per available
  evidence). The risk profile now depends heavily on *which* of §9's two
  paths is taken: reusing 1Password's own compiled `core.wasm` SRP/MUK/B5
  code (if licensing permits) carries materially lower correctness risk
  than an independent Rust reimplementation of SRP, since the former reuses
  1Password's own audited cryptography verbatim and only risks getting the
  surrounding *envelope* (credential encoding, device/session fields)
  wrong — a wrong envelope tends to fail loudly (server rejects the
  request) rather than silently succeed with weakened security. An
  independent reimplementation of `op_srp`/`derive_srp_x_key` from scratch
  would carry the full classic PAKE-reimplementation risk profile
  (subtle correctness bugs with direct key-recovery consequences) that
  reuse avoids. This distinction — reuse vs. reimplement — is the single
  biggest security-relevant design fork this investigation surfaces.

---

## 11. Legal/maintenance considerations and final conclusion

**Concrete engineering risks (not generic disclaimers):**

- **Protocol instability**: already true today for the Desktop IPC path
  (documented in-repo: unversioned socket name, symbol names, chunk-size
  constant, and the load-bearing `CONFIRMED_SDK_VERSION` magic value). A
  reimplemented user-auth handshake would carry the same class of risk,
  amplified — SRP implementations are unforgiving of subtle parameter
  mismatches (group parameters, hashing order, padding) and 1Password
  publishes no test vectors for third parties.
- **License scope of `core.wasm`**: the Go SDK repository is MIT-licensed
  and the 9.5 MB `core.wasm` binary is committed inside it — but it is a
  compiled artifact of private, unpublished Rust crates (per the Desktop
  `.so`'s own symbol evidence in §2/§3); whether the *repository's* MIT
  license is intended to cover redistributing/reusing that specific
  compiled binary independently of the Go SDK (e.g., loading it directly
  from Rust via `extism` bindings, bypassing Go entirely) is a genuine
  open licensing question this investigation flags but does not resolve —
  treat as needing explicit confirmation from 1Password, not an assumption
  either way.
- **No evidence of client attestation or certificate pinning** in the
  `ExtismCore` path (a generic Extism HTTP capability call would not
  support custom pinning without deeper WASM-side logic) — but this only
  covers the Service-Account path; Desktop's own delegated-session call may
  behave differently and was not (and could not responsibly be) inspected
  by TLS interception in this pass.
- **Likelihood of protocol change:** high, by 1Password's own framing — the
  Go SDK's README states "SDKs are in active development... version 0...
  possibility of breaking changes," and this repo's own docs already
  record one real, encountered breaking-shaped issue (`CONFIRMED_SDK_VERSION`).

### Final classification

**Orange, bordering on Yellow — feasible, and the cryptographic protocol
itself is not the missing piece, but reaching it still requires reverse-
engineering an undocumented credential encoding and validating undocumented
server-side authorization behavior.**

Revised from the initial pass after binary inspection (§12's methodology,
Executive Summary): this is **not** "Orange because the SRP/Secret-Key
protocol must be reimplemented from scratch" — that protocol demonstrably
already exists, compiled, in the same MIT-licensed repository, as `op_srp`/
`op_crypto::muk`/`op_sdk_b5_client`, and is exercised today for Service
Accounts. What keeps this out of Yellow (a documented-but-internal API) is
that: (a) the credential encoding (`SAToken` → `ServiceAccountCredentials`)
is not documented anywhere public, so using it for a personal account
requires reverse-engineering that encoding, not just calling an undocumented
function with known inputs; and (b) it is unconfirmed whether 1Password's
server-side authorization even permits a personal account to authenticate
through this path at all (§4c's device-verification concern) — that is a
server-side policy question no amount of client-side source reading can
resolve, only an actual (against-ToS-risk) attempt can. Not Red: nothing
found suggests a deliberate technical barrier against a native-free client
per se — `ExtismCore` *is* exactly that, shipped by 1Password itself. Not
Green: not directly supported today for personal accounts by any documented
path.

### The exact question asked

> "What is the smallest amount of code I would have to write to replace the
> Desktop dependency with a direct 1Password cloud transport while keeping
> as much of the existing Rust Core implementation as possible?"

Two honest answers depending on which requirement is actually load-bearing:

1. **If "the same account, but a different (Service Account) credential" is
   acceptable** (contradicts the brief's explicit exclusion, stated here
   only for completeness because the evidence makes it the *only* small
   answer that exists): almost no new code. `protocol.rs`'s
   `ClientConfig`-equivalent struct already has the exact field shape
   needed (`service_account_token`); `ffi.rs`/`ipc.rs`/`session.rs` are
   already transport-agnostic; the smallest change is populating
   `service_account_token` instead of `account_name`/leaving it empty, and
   the FFI/socket transport is *still* required (Service Account auth
   still flows through the same `op_sdk_ipc_send_message` symbol when
   using `SharedLibCore`) *unless* a Rust equivalent of `ExtismCore` is
   built — which is a real but bounded task: embed/host `core.wasm` (or
   1Password's WASM core, if redistribution terms allow) via the `extism`
   Rust host SDK, implement the same 3 host imports (`random_fill`,
   `unix_time_milliseconds_imported`, `utc_offset_seconds`), and reuse
   `protocol.rs` completely unchanged (byte-identical schema, confirmed in
   §3). Rough size: a few hundred lines, mostly host-function glue.
2. **If "authenticated as the user's normal account, no Desktop" is
   load-bearing** (the actual brief), revised after binary inspection: the
   answer is no longer "an entire protocol must be reimplemented" — the
   protocol (`op_srp`, `op_crypto::muk::derive_srp_x_key`,
   `op_sdk_b5_client`) already exists, compiled, in the public
   `core.wasm`. The realistic smallest path is:
   1. Embed `core.wasm` in `secretsd` via the `extism` Rust host SDK (a
      Rust crate exists for this; `ExtismCore`'s Go usage in §3 is a
      template), implementing the same 3 host imports Go provides
      (`random_fill`, `unix_time_milliseconds_imported`,
      `utc_offset_seconds`) — bounded, mechanical work, on the order of a
      few hundred lines, matching item 1's estimate above.
   2. Reverse-engineer the `SAToken`→`ServiceAccountCredentials` wire
      encoding (likely feasible: construct several real Service Account
      tokens via 1Password's dashboard, diff their decoded structure, or
      instrument a test `ExtismCore` call to observe what `init_client`'s
      payload looks like once decoded from a real token) — unbounded until
      attempted, but scoped to "one struct's serialization," not a whole
      protocol.
   3. Construct an equivalent payload for a personal account (`email` +
      `secretKey`, deriving `srpX`/`muk` via the same exported/compiled
      `derive_srp_x_key` logic if reachable, or replicating just that one
      derivation function independently if not directly callable) and test
      whether 1Password's real backend accepts an `authenticate_session`
      call built this way.
   4. Resolve whatever `deviceUuid`/`throttleSecret`/device-verification
      requirement blocks step 3, if any — this is the one step that could
      still turn out to be a hard, possibly server-enforced blocker (e.g.
      requiring an interactive device-verification email/link this WASM
      core does not itself send, since Service Accounts are pre-verified
      by construction) and is the most likely place this whole effort
      could stall despite everything else working.
   Steps 1-2 are genuinely small (days, not months). Step 3's outcome is
   unknown until attempted. Step 4 is the real remaining risk this
   investigation cannot resolve from source/binary reading alone — see
   §12. This is a substantially more optimistic estimate than the
   pre-binary-inspection pass of this same report, and is the most
   important revision this investigation session produced.

---

## 12. Exact list of unknowns requiring runtime experimentation

**Resolved during this investigation session** (kept here for
traceability):

- ~~Does `core.wasm` contain SRP/Secret-Key logic, or was it compiled
  out?~~ **Resolved: present.** Confirmed by directly downloading
  `internal/wasm/core.wasm` from the `main` branch and inspecting it with
  a from-scratch WASM export-table parser plus `strings -n 4/5/6` (no
  `wasm2wat`/`wasm-objdump` available in this environment) — see the
  Executive Summary and §4c for the exact symbols found (`op_srp`,
  `op_crypto::muk::derive_srp_x_key`, `op_sdk_b5_client`,
  `ServiceAccountCredentials`).
- ~~Does the exported `invoke`/`init_client` surface hint at a separate
  auth method?~~ **Resolved: no** — only `init_client`/`invoke`/
  `release_client` are WASM exports; method dispatch (`SecretsResolve`,
  the ~29 `AuthenticatedInvocation` variants, etc.) happens via string-name
  matching *inside* `invoke`'s single export, confirmed by the
  `AuthenticatedInvocation`/`UnauthenticatedInvocation` enum's own
  serde-derived string table. Session establishment happens during
  `init_client`, driven by whatever `ClientConfig`-equivalent payload
  (currently only ever a `ServiceAccountCredentials` bundle) is given.

**Still open, requiring further runtime experimentation:**

1. **The exact encoding of a Service Account token into a
   `ServiceAccountCredentials` value** — format, versioning, any checksum/
   MAC. Action: obtain one or more real Service Account tokens (via
   1Password's own dashboard, a legitimate, ToS-compliant action), and
   either (a) statically analyze the token string's structure, or (b)
   instrument a local `ExtismCore`/Extism-Rust-host call to observe the
   decoded `ClientConfig`/credentials value at the WASM boundary.
2. **Whether 1Password's real backend authorizes an `authenticate_session`
   built from a personal account's `email`/`secretKey`-derived fields**
   (in place of a Service Account's) — the single highest-impact unknown;
   only answerable by constructing and sending such a request, which
   carries real account/ToS risk and should not be attempted without the
   account owner's explicit, informed authorization (this is the same
   account already used for this project's Desktop-IPC POC, so the
   precedent for careful, consented experimentation exists in this repo's
   own history — see `1password-poc-results.md`).
3. **What `deviceUuid`/`throttleSecret` need to be for a personal account,
   and whether personal accounts require an interactive device-
   verification step (email/link) this WASM core does not itself
   perform** — the most likely genuine blocker; requires either targeted
   experimentation (attempt step 2 and observe the specific failure mode)
   or asking 1Password directly.
4. **What wire format Desktop's own "delegated session" HTTPS call uses**
   (§4b) — likely irrelevant now that §4c's `ExtismCore` path looks more
   promising than reverse-engineering Desktop's own channel, but still
   unresolved; would require TLS interception of a running Desktop process,
   not attempted in this pass.
5. **Whether 1Password's licensing intends `core.wasm` to be usable
   standalone**, loaded directly from Rust via the `extism` host SDK
   outside the Go SDK's own build — a compiled artifact of private crates
   committed into an MIT-licensed repository; the *repository's* license
   covers the repository, but whether 1Password intends third parties to
   extract and reuse this specific binary independently of their own Go
   SDK is an open question only 1Password can answer with certainty.
   Given `docs/architecture/1password-integration.md`'s own precedent of
   depending on reverse-engineered, unversioned behavior, this project
   would be assuming similar risk here, but at the additional scale of
   redistributing/loading a 9.5 MB compiled artifact rather than just
   calling two already-installed system symbols.
6. **Whether the `op` CLI's own `op signin`** (closed-source, but its
   *observable* behavior — env vars, session token format, `~/.op/config`
   — was not inspected in this pass) **or the browser extension/web
   vault's client-side JavaScript** (the most plausibly inspectable closed
   client, since browser code ships in the clear, modulo minification)
   **could shortcut #1-#3** by providing an independent, human-readable
   reference for the credential/session flow, without needing to
   experiment directly against a live personal account.

---

## Next steps

No code has been changed as part of this investigation. If this project
decides to pursue the Orange path from §11:

1. Resolve unknowns #1-#3 in §12 before writing any Rust — they determine
   whether a `CloudTransport` is worth building at all.
2. If pursued, start with the `OnePasswordTransport` trait seam from §9
   (`IpcClient` as its sole implementor, a pure refactor with no behavior
   change), verified by the existing `onepassword` backend test suite
   (`cargo test -p secretsd backend::onepassword::`) and the manual
   `onepassword_probe` example — before attempting a `CloudTransport`
   implementation.
3. Do not attempt unknown #2 (testing personal-account credentials against
   1Password's real backend) without the account owner's explicit,
   informed authorization, given the ToS/account-risk this investigation
   flags in §12.
