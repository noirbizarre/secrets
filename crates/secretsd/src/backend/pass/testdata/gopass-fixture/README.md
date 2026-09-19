# `gopass`-initialized fixture store

Generated once with the real `gpg` (2.4.9) and `gopass` (1.17.0) binaries,
fully isolated from any real keyring/store via a throwaway `GNUPGHOME`
and `XDG_CONFIG_HOME`/`XDG_DATA_HOME` — never touches a real
`~/.gnupg`/`~/.password-store`/`~/.config/gopass`. No real secrets;
every key and value here is a throwaway fixture.

Used by `backend::pass::backend::tests::
reads_a_real_gopass_initialized_store_without_modification` to prove
on-disk-format compatibility without needing `gpg`/`gopass` installed in
CI — `PassBackend` reads these files exactly as it would a hand-rolled
`pass` store, since `gopass`'s default `gpgcli` crypto backend produces
byte-identical `.gpg-id`/`.gpg` files to plain `pass`.

## Layout

- `key.asc` — the fixture's OpenPGP secret key, ascii-armored
  (`gpg --export-secret-keys --armor`), passphrase `fixture passphrase`.
- `store/.gpg-id` — the root recipient (this fixture's own key).
- `store/Personal/GitHub.gpg` — `correct horse battery staple` /
  `login: octocat` / `url: github.com`.
- `store/Personal/OtpOnly.gpg` — a `pass-otp`-style OTP-only entry (first
  line is itself an `otpauth://` URI, no separate password line).
- `store/Servers/.gpg-id` + `store/Servers/db.gpg` — a nested `.gpg-id`
  override, encrypted to a *different*, unrelated, discarded key. Proves
  ADR-019's decision that a nested `.gpg-id` never gates decryption
  (walked over, but always ignored) — `PassBackend` cannot decrypt this
  one with `key.asc` and must degrade gracefully rather than fail the
  whole listing (see `an_item_undecryptable_by_the_configured_key_
  degrades_gracefully_in_listing`, which exercises the same scenario
  in-process).
- `store/config` — `gopass`'s own storage-backend marker
  (`backend = fs`) — inert; `PassBackend`'s walker ignores anything
  without a `.gpg` extension.

## Regenerating

```console
$ export GNUPGHOME=$(mktemp -d)
$ export XDG_CONFIG_HOME=$(mktemp -d) XDG_DATA_HOME=$(mktemp -d)
$ gpg --batch --pinentry-mode loopback --generate-key - <<'EOF'
Key-Type: EDDSA
Key-Curve: Ed25519
Key-Usage: sign
Subkey-Type: ECDH
Subkey-Curve: Cv25519
Subkey-Usage: encrypt
Name-Real: secrets-test-fixture
Name-Email: fixture@example.invalid
Expire-Date: 0
Passphrase: fixture passphrase
%commit
EOF
$ KEYID=<fingerprint from `gpg --list-secret-keys --with-colons`>
$ gopass init --storage=fs "$KEYID"
$ printf 'correct horse battery staple\nlogin: octocat\nurl: github.com\n' \
    | gopass insert -m Personal/GitHub
$ gopass insert -m Personal/OtpOnly <<< \
    'otpauth://totp/Example:octocat?secret=JBSWY3DPEHPK3PXP&issuer=Example'
# a second, throwaway key for the nested override:
$ gpg --batch --generate-key - <<'EOF'
Key-Type: EDDSA
Key-Curve: Ed25519
Key-Usage: sign
Subkey-Type: ECDH
Subkey-Curve: Cv25519
Subkey-Usage: encrypt
Name-Real: secrets-test-fixture-mount
Name-Email: mount@example.invalid
Expire-Date: 0
%no-protection
%commit
EOF
$ MOUNT_KEYID=<fingerprint>
$ mkdir "$XDG_DATA_HOME/gopass/stores/root/Servers"
$ echo "$MOUNT_KEYID" > "$XDG_DATA_HOME/gopass/stores/root/Servers/.gpg-id"
$ echo 'unreachable-by-the-configured-fixture-key' | gpg --batch --yes \
    --trust-model always --recipient "$MOUNT_KEYID" --encrypt \
    --output "$XDG_DATA_HOME/gopass/stores/root/Servers/db.gpg"
$ gpg --export-secret-keys --armor "$KEYID" > key.asc
$ rm -rf store/.public-keys  # gopass's own convenience export, unneeded
```
