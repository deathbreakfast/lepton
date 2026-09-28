# lepton-host-adapter

Axum-login session backend and token schemas for SSR hosts. Bridges
**lepton-identity** users to higgs via `Backend` and `session_snapshot_middleware`.

**Source of truth for teaching:** `cargo doc -p lepton-host-adapter --features ssr --open`.

```toml
lepton-host-adapter = { git = "https://github.com/unified-field-dev/lepton", package = "lepton-host-adapter", default-features = false, features = ["ssr"] }
```

## Features

- **Axum-login backend** — `Backend`, `Credentials`, `User`
- **Session snapshot** — `session_snapshot_middleware` into higgs
- **Photon WS auth** — `PhotonAuth` / `extract_user_key`
- **Token models** — reset / verification schemas in `generated`
- **Profile files** — `files_routes` for photo upload / serve; uploads wait in
  meson's quarantine store until a virus scan clears them

## Getting started

```bash
CARGO_BUILD_JOBS=1 cargo run -p lepton-host-adapter --example axum_session_snapshot --features ssr
```

Success stdout: `axum_session_snapshot: OK — login → SessionSnapshot`.

See also [`examples/README.md`](examples/README.md).

## Feature flags

| Feature | Effect |
|---------|--------|
| `ssr` | Backend, middleware, Photon auth, files, generated models |
| `db-sqlite` (default) | SQLite via `lepton-identity` |
| `db-hybrid` | Hybrid engine for host routers |

## Verify

```bash
export CARGO_BUILD_JOBS=1
cargo check -p lepton-host-adapter --features ssr
```

## License

MIT. See the workspace [LICENSE](../LICENSE).
