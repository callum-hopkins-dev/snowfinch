<div align="center">

# snowfinch

Authentication and sessions for Rust tower/axum servers.

[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/callum-hopkins-dev/snowfinch/build.yaml?branch=main&event=push&style=for-the-badge)](https://github.com/callum-hopkins-dev/snowfinch/actions/workflows/build.yaml)
[![Crates.io Version](https://img.shields.io/crates/v/snowfinch?style=for-the-badge)](https://crates.io/crates/snowfinch)
[![docs.rs](https://img.shields.io/docsrs/snowfinch?style=for-the-badge)](https://docs.rs/snowfinch/latest/snowfinch)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/snowfinch?style=for-the-badge)](https://crates.io/crates/snowfinch)
[![GitHub License](https://img.shields.io/github/license/callum-hopkins-dev/snowfinch?style=for-the-badge)](https://github.com/callum-hopkins-dev/snowfinch/blob/main/LICENSE)

</div>

Snowfinch provides a small set of interfaces for session-based authentication
without prescribing an application database or user model. The core middleware
is built on [Tower](https://crates.io/crates/tower), while the optional `axum`
feature adds extractors, response integration, and router conveniences.

## Architecture

Applications provide three pieces:

- a `User` value containing a stable ID and permission `Scope`;
- a `Backend` which loads users and authenticates credentials;
- a `Store` which persists compact session records.

Stores retain only a session ID, expiry, and user ID. When a request carries a
valid `session` cookie, `ProvideAuthenticationLayer` loads that compact record,
rejects it if expired, and asks the backend for the current user. The resulting
`Session` and a cheaply cloned `Authentication` handle are inserted into the
request extensions.

This separation keeps large user values out of the session store and ensures
that restored sessions use current user data and permissions.

## Example

```rust
use std::convert::Infallible;

use snowfinch::{Backend, ProvideAuthenticationLayer, User, scope};

scope! {
    pub enum Permissions {
        Read = 0,
        Write = 1,
        Admin = Read && Write,
    }
}

struct AppUser {
    id: i64,
    scope: Permissions,
}

impl User for AppUser {
    type Scope = Permissions;
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn scope(&self) -> Self::Scope {
        self.scope
    }
}

struct AppBackend;

impl Backend for AppBackend {
    type Credentials = (String, String);
    type User = AppUser;
    type Error = Infallible;

    fn get(
        &self,
        _id: i64,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
        std::future::ready(Ok(None))
    }

    fn authenticate(
        &self,
        _credentials: Self::Credentials,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
        std::future::ready(Ok(None))
    }
}

// Without an explicit store, the layer uses NoopStore. Configure a custom
// Store or call with_memory_store() when sessions should survive requests.
let _layer = ProvideAuthenticationLayer::new().with_backend(AppBackend);
```

Backend and store methods use return-position `impl Future`, so implementations
do not need to name, box, or erase their futures. The authentication layer shares
backend and store values through `Arc`, therefore neither implementation needs
to be `Clone`.

## Login and logout

Request handlers obtain the `Authentication` handle from request extensions,
or as an Axum extractor when the `axum` feature is enabled.
`Authentication::authenticate` validates credentials, `Authentication::login`
creates and persists a session, and `Authentication::logout` revokes it.

A returned `Session` can be added to an Axum response. Its response-parts
implementation writes the secure, HTTP-only `session` cookie.

## Authorization

The `authorization` module provides Tower middleware for rejecting requests
without an acceptable authenticated session:

- `RequireAuthenticated` accepts any authenticated user;
- `RequireScope` requires a complete permission scope;
- `AuthorizeFn` adapts a closure;
- `RequireAuthorizationLayer` accepts a custom `Authorize` implementation.

Extension traits are provided for `tower::ServiceBuilder`, and for Axum routers
and method routers when the `axum` feature is enabled.

## Permission scopes

The `scope!` macro defines a compact, `u64`-backed permission type. Generated
scopes support compound scopes, lookup by name, iteration, set operations, raw `u64`
conversion, and optional Serde and SQLx integration. Unknown raw bits are
ignored when constructing or decoding a scope.

## Passwords

`Password` is a packed 64-byte salted SHA-256 value containing a 32-byte hash
followed by a 32-byte salt. Plaintext comparisons recompute the hash and compare
the packed representation in constant time. With `sqlx`, passwords are encoded
directly as binary blobs.

## Feature flags

The default feature set enables `memory-store` and `session-local`.

- `axum` enables extractors, response integration, and router extensions.
- `memory-store` enables the Moka-backed `store::MemoryStore`.
- `serde` enables serialization for `Password` and generated scopes.
- `session-local` exposes the current session through `session::current` and
  `session::try_current`.
- `sqlx` enables database encoding and decoding for `Password` and generated
  scopes.

## license

`snowfinch` is licensed under the MIT License. See `LICENSE` for details.

## contributing

Contributions are welcome.

Please follow the existing code style and conventions used throughout the
project. If you're proposing a new feature or API, opening an issue first is
often the easiest way to discuss the design.
