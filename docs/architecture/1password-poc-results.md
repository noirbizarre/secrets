# 1Password Desktop POC results

Evaluation of the native 1Password Desktop integration POC (Steps 1–8),
run for real against an installed 1Password Desktop. Written honestly,
against the task's own PASS/BLOCKED criteria — this is neither a full
PASS nor an uninformative BLOCKED, and says so precisely rather than
forcing one label.

## Verdict: BLOCKED, but at a specific, external, well-isolated stage

**The daemon-side integration itself — the part `secretsd` controls —
works completely, end to end, confirmed against the real Desktop app,
not fixtures.** What does not currently work is 1Password Desktop's own
server-side session establishment for this account, which returns an
HTTP 400 regardless of anything this project's client sends. That
specific failure is outside what client-side code can fix. Per the
task's own instruction to stop rather than route around a genuine
blocker: this stops here, at Step 9, without implementing
`OnePasswordBackend` (Step 10), since Step 10 requires actually
retrieving a secret, which this POC could not do.

## Environment

- Distribution: Arch Linux (rolling), x86_64.
- 1Password Desktop: 8.11.x, installed at `/opt/1Password/`.
- Library discovery path used: `/opt/1Password/libop_sdk_ipc_client.so`
  (the first and only candidate in `ffi::CANDIDATE_PATHS`; found on the
  first try).
- Settings > Developer > "Integrate with other apps" was enabled before
  testing (a required prerequisite — see the integration doc).

## What was confirmed working, for real

1. **Library loading** (`ffi::IpcLibrary::load()`): succeeds against the
   real, installed library.
2. **The FFI signature**: `send_message`/`free_response` calls succeed
   with real arguments and real native memory — no crash, no hang, no
   memory error observed across dozens of real and fixture-driven calls.
3. **The message envelope and `init_client` payload shape**
   (`protocol::init_client_request`): 1Password Desktop's own JSON
   deserializer accepted every request sent — never a parse-level
   rejection, across seven separate real invocations with varying
   `programmingLanguage`/`sdkVersion`/`integrationName` values.
4. **The authorization flow**: a real, human-facing approval prompt
   appeared in the 1Password Desktop app for a new integration/account
   pairing, and approving it let the request through to the next stage.
   A timed-out (unapproved) attempt returned `IpcError::Timeout`
   cleanly — confirmed by observation, not just fixture tests — rather
   than hanging `secretsd` indefinitely.
5. **Bounded timeouts throughout** (`IpcClient::invoke`,
   `SessionManager`'s leader/follower paths): every real call observed
   returned within its configured timeout, once or not at all.
6. **The response envelope structure**
   (`{"success", "payload"}`, confirmed both in the success shape the Go
   SDK documents and in a real failure shape observed here — see below).

## What did not work, and exactly where

Every attempt failed at the same point: after `init_client`'s request is
accepted and (the first time, per integration name) approved, 1Password
Desktop's response is:

```text
success: false
payload (decoded): An error occurred when processing SDK request: Error {
  msg: Internal error: Failed to create delegated session, inner: Some(Error {
    msg: Failed to delegate a session, inner: Some(FetchError(<unknown reason>,
    code: HttpStatus(400), Session ID: Some(Session ID: <redacted>))) }) }
```

(Session IDs redacted here even though they are not field *values* in
the Secrets sense — they are 1Password's own internal identifiers, not
this project's data, and carry no benefit to publishing verbatim.)

This is a **server-side** rejection: 1Password Desktop attempted an
HTTPS call (to establish a "delegated session," a concept internal to
1Password's own backend, not part of the wire protocol this project
implements) and that call's server returned HTTP 400.

### Ruling out a request-format cause

Five real variations were tried, isolating the cause methodically:

| Variation | Outcome |
| --- | --- |
| Original request (`programmingLanguage: "Rust"`, placeholder `sdkVersion`) | Same delegated-session HTTP 400 |
| `programmingLanguage: "Go"`, `sdkVersion` still a placeholder | Same error, same session ID (session reused, no new prompt) |
| `sdkVersion` set to the Go SDK's actual latest published tag (`v0.4.1`) | Same error, same session ID |
| `integrationName` changed to a never-before-seen value | Same error, same session ID, no new approval prompt |
| Full 1Password Desktop app restart (fresh process, confirmed by PID change) | A **new** session ID, but the identical HTTP 400 |

None of the four request-content changes altered the outcome or even
triggered a new approval prompt — strongly suggesting 1Password Desktop
caches one "delegated session" attempt per app-launch (not per
integration name, contrary to an earlier working theory), and every
avenue to construct a *different* request produces the same result. The
restart did produce a materially fresh attempt (a new session ID), which
still failed identically — ruling out "stuck cached state from a
previous run" as the explanation.

### Likely cause

Not library loading, not FFI/ABI mismatch, not JSON protocol
compatibility, not this project's own authorization or session
management logic — all five of those are confirmed working above. The
remaining, most likely explanations, in order of likelihood:

1. **Account- or environment-specific**: something about this specific
   1Password account, its subscription tier, or network reachability to
   1Password's own backend from this machine, that only 1Password's own
   support channel or a second, different account could confirm or
   rule out. This project's client code has no visibility into why the
   *server* returned 400.
2. A transient issue with 1Password's backend at the time of testing
   (less likely, given it reproduced identically across a full app
   restart and roughly 15 minutes of separate attempts).

The user (repository owner) confirmed the required "Integrate with
other apps" Desktop setting was already enabled before testing, so that
specific, commonly-cited prerequisite is not the cause.

## A protocol detail confirmed only by this real run

The response envelope's `payload` field is **not always** base64 text,
contrary to what reading only the Go SDK's client-side code would
suggest. The failure response above arrived with `payload` as a raw
JSON array of byte values instead of a base64 string — `protocol.rs`
was corrected (Step 8's commit) to accept either shape, with a test
using this real (redacted) shape.

## Recommendation

Do not implement `OnePasswordBackend` (Step 10) yet — there is nothing
further to build against an integration that cannot complete its first
real operation, and doing so now would mean shipping untestable code.
If this is revisited later (a different account, after contacting
1Password support, or once whatever is causing the HTTP 400 changes):
Steps 5–8's code needs no rework to try again — `ffi.rs`, `ipc.rs`,
`protocol.rs` and `session.rs` are all confirmed working against the
real library and only need a session that successfully delegates to
proceed to an actual `SecretsResolve` call.
</content>
