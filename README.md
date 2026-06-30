<div align="center">

# snowfinch

Authentication and sessions for Rust tower/axum servers.

[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/callum-hopkins-dev/snowfinch/build.yaml?branch=main&event=push&style=for-the-badge)](https://github.com/callum-hopkins-dev/snowfinch/actions/workflows/build.yaml)
[![Crates.io Version](https://img.shields.io/crates/v/snowfinch?style=for-the-badge)](https://crates.io/crates/snowfinch)
[![docs.rs](https://img.shields.io/docsrs/snowfinch?style=for-the-badge)](https://docs.rs/snowfinch/latest/snowfinch)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/snowfinch?style=for-the-badge)](https://crates.io/crates/snowfinch)
[![GitHub License](https://img.shields.io/github/license/callum-hopkins-dev/snowfinch?style=for-the-badge)](https://github.com/callum-hopkins-dev/snowfinch/blob/main/LICENSE)

</div>

## about 

`snowfinch` provides the building blocks for session-based authentication in
Tower-compatible HTTP stacks. It is designed to work naturally with Axum, but
the core middleware is implemented in terms of `tower::Layer` and
`tower::Service` so it can be used with other Tower HTTP frameworks too.

The crate centres around three traits:

- `User`, implemented by your application user type.
- `Backend`, implemented by the component that loads and authenticates
  users.
- `Store`, implemented by the component that persists sessions.

Add `ProvideAuthenticationLayer` to your service stack to make an
`Authentication` handle and, when a valid `session` cookie is present, the
current `Session` available through request extensions. The authorization
helpers in `authorization` can then reject unauthenticated users or require
custom permission checks.

The `scope!` macro defines compact bitmap-backed permission types. Generated
scopes support bitwise operations, lookup by name, iteration over active
flags, and optional `serde`/`sqlx` integration when those feature flags are
enabled.

### example

```rust
use snowfinch::{Backend, ProvideAuthenticationLayer, Session, User, scope};

scope! {
    // Permissions granted to an application user.
    pub enum Permissions {
        Read = 0,
        Write = 1,
        Admin = Read && Write,
    }
}

#[derive(Clone)]
struct AppUser {
    id: i64,
    scope: Permissions,
}

impl User for AppUser {
    type Scope = Permissions;
    type Id = i64;
    type Credentials = (String, String);

    fn id(&self) -> Self::Id { self.id }
    fn scope(&self) -> Self::Scope { self.scope }
}

let layer = ProvideAuthenticationLayer::<AppUser>::new()
    .with_backend(MyBackend)
    .with_memory_store();
```

### feature flags

- `axum`: enables Axum extractors and response integration.
- `session-local`: keeps the current session in `tokio` task-local storage.
- `memory-store`: enables the moka-backed in-memory `store::MemoryStore`.
- `password`: enables the `Password` helper type.
- `serde`: enables serialization support for `Password` and generated
  scopes.
- `sqlx`: enables database encoding/decoding support for `Password` and
  generated scopes.

## license

`snowfinch` is licensed under the MIT License. See `LICENSE` for details.

## contributing

Contributions are welcome.

Please follow the existing code style and conventions used throughout the
project. If you're proposing a new feature or API, opening an issue first is
often the easiest way to discuss the design.
