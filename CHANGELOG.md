# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 - 2026-11-12

### 💫 Features

- **secrets-cli** Add `secrets show` to list an item's fields - ([ef68e7b](https://github.com/noirbizarre/secrets/commit/ef68e7beaf39300e95189a0bb7ff673b34fbd227))
- **secrets-cli** Harden secret output semantics for `secrets get` - ([22eb744](https://github.com/noirbizarre/secrets/commit/22eb7441bb96e3e13ab56064ca83bc145f3b7ef0))
- **secretsd** Add the pass/gopass backend (ADR-019) ([#39](https://github.com/noirbizarre/secrets/issues/39)) - ([b4a0710](https://github.com/noirbizarre/secrets/commit/b4a0710475cb1393f0f81f38b65f2a09819bb3f4))
- **secretsd** Make the Secret Service topology live instead of fixed-at-startup - ([2b47e4e](https://github.com/noirbizarre/secrets/commit/2b47e4ef1f11cee38150449226c7467d14ad238d))
- **secretsd** Make the 1Password backend session state visible over Secret Service and the SSH agent - ([3301a2d](https://github.com/noirbizarre/secrets/commit/3301a2db15666a1adec79f3c86c1d6d816333daa))
- **secretsd** Register the standard org.freedesktop.secrets bus name - ([f026b84](https://github.com/noirbizarre/secrets/commit/f026b84970dc1ddb61847d7f4cb325ffee38e362))
- Implement multi-store support (ADR-018) ([#38](https://github.com/noirbizarre/secrets/issues/38)) - ([e1db809](https://github.com/noirbizarre/secrets/commit/e1db809f39a5719c99e561567765871b399d458a))
- Implement the prompt broker and provider protocol ([#23](https://github.com/noirbizarre/secrets/issues/23)) - ([3ede803](https://github.com/noirbizarre/secrets/commit/3ede80384e02c787fb1fc5ba7d50330d743867ed))
- Add mise tasks to run the cli and daemon - ([4d2ad97](https://github.com/noirbizarre/secrets/commit/4d2ad97841f0d828bdcde2be647820aa51b51415))
- Add public rust client library - ([9fd273e](https://github.com/noirbizarre/secrets/commit/9fd273e4dcbb35ccb1f224b7cb36aa03907c1516))
- Add configurable backend selection - ([3b4e997](https://github.com/noirbizarre/secrets/commit/3b4e997f0fccf299afe436079b13bd99405483c4))
- Add 1password backend - ([730a4e9](https://github.com/noirbizarre/secrets/commit/730a4e90d7f4ce17f43a2510c0d98c34fc68d998))
- Add 1password desktop session management - ([378ae24](https://github.com/noirbizarre/secrets/commit/378ae24051c9ce2e16116ee8f7650fd13e0df28b))
- Implement minimal 1password desktop ipc client - ([b51a8d4](https://github.com/noirbizarre/secrets/commit/b51a8d4b7e53598d709fc3d59690288537e83f5d))
- Add 1password desktop ipc library loader - ([286dec1](https://github.com/noirbizarre/secrets/commit/286dec18fcb06663b3d614853db779d5f962063e))
- Implement the Secrets MVP workspace (core, daemon, cli) - ([ec0a665](https://github.com/noirbizarre/secrets/commit/ec0a665d9155bbd1ffccf2c3ea8bbde7301a5d2b))

### 🐛 Bug Fixes

- **ci** Regenerate mise.lock with linux-x64 lockfile URLs - ([dfd368f](https://github.com/noirbizarre/secrets/commit/dfd368fa7ef4dab5c04c78b287494eeca36a5695))
- **secrets-client** Return SecretValue from SecretsClient::get - ([d40ee88](https://github.com/noirbizarre/secrets/commit/d40ee88a016a1f588f26b994d3a1c40bc543425c))
- **secretsd** Chunk ItemsGetAll into batches of 50 items - ([3f4b362](https://github.com/noirbizarre/secrets/commit/3f4b3621fff9309dcca9ba76fe46fff9efb639be))
- **secretsd** FieldData::decrypt returns a typed error, not () - ([2bf059d](https://github.com/noirbizarre/secrets/commit/2bf059d16c40ac2a9574ccd4f739fbfc0f22f21b))
- **secretsd** Make the SSH agent's tokio runtime single-threaded - ([919f184](https://github.com/noirbizarre/secrets/commit/919f1848bd7f9e6c4bb2144be609e0683c7227f0))
- **secretsd** Zeroize get_field's raw response bytes - ([c8e44ed](https://github.com/noirbizarre/secrets/commit/c8e44eda10ad2b27253b6e2ac4cb1a1a74a0fc77))
- **secretsd** Zeroize ResolvedSecret on drop - ([4bc1b06](https://github.com/noirbizarre/secrets/commit/4bc1b0620c46f255df72597b522d00bb968d071e))
- Correct 1password sdkVersion and confirm real secret resolution - ([56e28f9](https://github.com/noirbizarre/secrets/commit/56e28f9a98234c682fb89d29d1689cca4ed159ad))
- Correct 1password ipc ffi signature and confirm wire protocol - ([15f4d02](https://github.com/noirbizarre/secrets/commit/15f4d022c7c06317cc53b3b2021ec679074fbb57))

### 🔨 Refactor

- **secrets-cli** Stop re-wrapping the value secrets-client already wraps - ([9484d64](https://github.com/noirbizarre/secrets/commit/9484d6423e4ec693693de60e0b3facc2fde824d5))
- Make cli use public secrets client - ([ff6e0ca](https://github.com/noirbizarre/secrets/commit/ff6e0ca3c7c493f20157b1c3606796a09ee4ab9d))
- Clarify secret reference resolution semantics - ([06ca462](https://github.com/noirbizarre/secrets/commit/06ca462eecbacccc795fa3ade9a2aed63fb341de))
- Separate daemon and backend authentication state - ([1c67324](https://github.com/noirbizarre/secrets/commit/1c673246e9ed290976192630ac6768e5a077d578))
- Decouple daemon state from local backend - ([3c5a98c](https://github.com/noirbizarre/secrets/commit/3c5a98ca230e6736c8579ff6661a8790140f22c9))

### 📚 Documentation

- **adr-005** Fix method count (Six -> Seven) - ([ffdc91e](https://github.com/noirbizarre/secrets/commit/ffdc91e2352b80ff3872d13e8aa5bbbfb632c93e))
- **agents** Fix stale client::Client reference in invariant #2 - ([07aef9f](https://github.com/noirbizarre/secrets/commit/07aef9f27edd033f328dbf03cb876bb4b66da970))
- **logo** Add logo ([#20](https://github.com/noirbizarre/secrets/issues/20)) - ([b20c354](https://github.com/noirbizarre/secrets/commit/b20c354a548ffa4c3b790cf2b01205e554728b27))
- **plan** Add missing PLAN.md entries for ADR-011, ADR-012, ADR-014 - ([ab6324a](https://github.com/noirbizarre/secrets/commit/ab6324a4c34897cbe18b3ea27e135eebc0de28c6))
- **readme** Name the CLI crate secrets-cli, not its binary name - ([6ab3899](https://github.com/noirbizarre/secrets/commit/6ab38991cf04e2151bba74121526a5d4bbac0c62))
- **secrets-cli** Mark --verbose as reserved, not wired to anything - ([febaee6](https://github.com/noirbizarre/secrets/commit/febaee678e219baf2d9d019b65562991c7e8af3e))
- **secrets-core** Fix stale clippy::result_large_err comment - ([c3fb130](https://github.com/noirbizarre/secrets/commit/c3fb130a1548a4418a331ed58061b8f1ab7e14a2))
- Preserve release installation links - ([eae1e7d](https://github.com/noirbizarre/secrets/commit/eae1e7d542a4a2afbdc11e5f676e0f5595db8410))
- Fix four-digit ADR-number typos (ADR-0011/0008/0002/0005) - ([71d33ed](https://github.com/noirbizarre/secrets/commit/71d33ed4607d77943d17860ecfdd7b51b6665130))
- Undo the ADR-003/overview.md cross-reference now that the direct secrets-core edge is gone - ([1fed9dd](https://github.com/noirbizarre/secrets/commit/1fed9dd03c548ff552d0ca0da8c45a09a5730b97))
- Reconcile ADR-003 and overview.md with ADR-014's dependency change - ([1b4ad02](https://github.com/noirbizarre/secrets/commit/1b4ad0247df85767930dd62bfa7c1e4ec1d77c09))
- Reframe Secret Service as the standard contract, org.secrets.* as extensions - ([0d6814b](https://github.com/noirbizarre/secrets/commit/0d6814b03cdef1df31a8a01e0a42340cf2e996c0))
- Investigate feasibility of a Desktop-free 1Password cloud transport - ([46e2e1b](https://github.com/noirbizarre/secrets/commit/46e2e1b118fd3179365a6a3af552925440c2c432))
- Document secrets ecosystem architecture - ([f6c927d](https://github.com/noirbizarre/secrets/commit/f6c927d67180a8e27f7687ec0c47eebcfa8a2455))
- Align project roadmap with repository architecture - ([a90962a](https://github.com/noirbizarre/secrets/commit/a90962aee0c3af70c2e817d3d3613aede8eb9c37))
- Move ui and browser clients outside core repository - ([88c0713](https://github.com/noirbizarre/secrets/commit/88c0713c3784e8848802f83badd607e78cae474b))
- Update workspace architecture adr - ([8732bf3](https://github.com/noirbizarre/secrets/commit/8732bf35590ca56d114e7f3319da5d3a301726d3))
- Establish dbus as the secrets protocol boundary - ([f19670d](https://github.com/noirbizarre/secrets/commit/f19670de3396619949bc50f3591d06dcdf260287))
- Clarify secrets core library boundary - ([a1b0e28](https://github.com/noirbizarre/secrets/commit/a1b0e28cf085441721a7d5208a54c706289b0efe))
- Audit repository architecture boundaries - ([54ed4d4](https://github.com/noirbizarre/secrets/commit/54ed4d4e0f0ed15dbb7dc3bed71498762712020b))
- Document 1password desktop poc results - ([532fa6f](https://github.com/noirbizarre/secrets/commit/532fa6f45f494a1b1b97bad36e529ce96caff92c))
- Document 1password desktop integration approach - ([ac530ff](https://github.com/noirbizarre/secrets/commit/ac530ffbfda05aba7cad1acb3cb8c31af3d7f96e))
- Add architecture, ADRs, D-Bus and security documentation - ([b401326](https://github.com/noirbizarre/secrets/commit/b401326034f6340104c0b831b8d7af533224faf5))

### 🧪 Tests

- **secrets-cli** Add end-to-end CLI integration tests over a real secretsd - ([a29ea1f](https://github.com/noirbizarre/secrets/commit/a29ea1f6f9edf53e120d9567585c6e0196659f9a))
- **secretsd** Add automated Secret Service D-Bus integration harness - ([24df0a0](https://github.com/noirbizarre/secrets/commit/24df0a077a72bf4045907da5610ea3f91dbc7abc))
- Add backend integration coverage - ([850dc91](https://github.com/noirbizarre/secrets/commit/850dc91abd2554c5e10994ee61384dc9513773e3))
- Add 1password desktop integration probe - ([70da3b1](https://github.com/noirbizarre/secrets/commit/70da3b19e2891752d20a83bcc379d139665343d5))

### 🏗️ Build

- **deps** Update mise.lock - ([8009f11](https://github.com/noirbizarre/secrets/commit/8009f113892502e2bbc6f5487dcc4034284fefe3))

### 🔧 CI

- **docs** Disable docs publication until project visibility is public ([#19](https://github.com/noirbizarre/secrets/issues/19)) - ([53f5623](https://github.com/noirbizarre/secrets/commit/53f5623b966e48b1184934800f416c7263a33c68))
- **release** Simplify matrix - ([afffdf5](https://github.com/noirbizarre/secrets/commit/afffdf5f1f9fe2a83ee3840fdf9987ffec6a8d4c))
- Restrict the test matrix to Linux and fix codecov after_n_builds - ([b939106](https://github.com/noirbizarre/secrets/commit/b939106247277c1ca76d55e95b4417ce061a6a6b))

### 🧹 Chores

- **template** Update rust.tpl tooling and workflows ([#58](https://github.com/noirbizarre/secrets/issues/58)) - ([0287b0c](https://github.com/noirbizarre/secrets/commit/0287b0cdc2fb7e22a6bc346072b9afef7adf8bed))
- **template** Merge latest rust.tpl updates - ([6cd4693](https://github.com/noirbizarre/secrets/commit/6cd4693592eb81176b9ec95a595c42fd4e399275))
- **tpl** Attach the rust template - ([8d33142](https://github.com/noirbizarre/secrets/commit/8d33142703b6a9668a389f810c6e0fa7c02109e3))
- Remove accidental placeholder file - ([1ff9a94](https://github.com/noirbizarre/secrets/commit/1ff9a94a844678203af1d1bfdb2c0c166db1cc01))
- Remove accidental placeholder file - ([9fa01c1](https://github.com/noirbizarre/secrets/commit/9fa01c1914d21458206fdf405510a692d10ee297))
- Add the secretsd systemd user unit - ([202269a](https://github.com/noirbizarre/secrets/commit/202269adb090bba1c4b2ae6bc81019397b8a811d))

### Tpl

- Render rust at main - ([b0889e5](https://github.com/noirbizarre/secrets/commit/b0889e5fdff9a9c08371c4ed6cc1e68eb0751234))
- Render rust at main - ([f9af2d8](https://github.com/noirbizarre/secrets/commit/f9af2d858e5f24dd9af11b948b906e471441f649))

## ❤️ New Contributors

* @noirbizarre made their first contribution in [#58](https://github.com/noirbizarre/secrets/pull/58)
