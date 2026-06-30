#![cfg_attr(docsrs, feature(doc_cfg))]

//! Authentication and sessions for Rust tower/axum servers.
//!
//! `snowfinch` provides the building blocks for session-based authentication in
//! Tower-compatible HTTP stacks. It is designed to work naturally with Axum, but
//! the core middleware is implemented in terms of [`tower::Layer`] and
//! [`tower::Service`] so it can be used with other Tower HTTP frameworks too.
//!
//! The crate centres around three traits:
//!
//! - [`User`], implemented by your application user type.
//! - [`Backend`], implemented by the component that loads and authenticates
//!   users.
//! - [`Store`], implemented by the component that persists sessions.
//!
//! Add [`ProvideAuthenticationLayer`] to your service stack to make an
//! [`Authentication`] handle and, when a valid `session` cookie is present, the
//! current [`Session`] available through request extensions. The authorization
//! helpers in [`authorization`] can then reject unauthenticated users or require
//! custom permission checks.
//!
//! The [`scope!`] macro defines compact bitmap-backed permission types. Generated
//! scopes support bitwise operations, lookup by name, iteration over active
//! flags, and optional `serde`/`sqlx` integration when those feature flags are
//! enabled.
//!
//! # example
//!
//! ```rust
//! use snowfinch::{Backend, ProvideAuthenticationLayer, Session, User, scope};
//!
//! scope! {
//!     // Permissions granted to an application user.
//!     pub enum Permissions {
//!         Read = 0,
//!         Write = 1,
//!         Admin = Read && Write,
//!     }
//! }
//!
//! #[derive(Clone)]
//! struct AppUser {
//!     id: i64,
//!     scope: Permissions,
//! }
//!
//! impl User for AppUser {
//!     type Scope = Permissions;
//!     type Id = i64;
//!     type Credentials = (String, String);
//!
//!     fn id(&self) -> Self::Id { self.id }
//!     fn scope(&self) -> Self::Scope { self.scope }
//! }
//!
//! # struct MyBackend;
//! # impl Backend for MyBackend {
//! #     type User = AppUser;
//! #     type Error = std::convert::Infallible;
//! #     type Get = std::future::Ready<Result<Option<AppUser>, Self::Error>>;
//! #     type Authenticate = std::future::Ready<Result<Option<AppUser>, Self::Error>>;
//! #     fn get(&self, _: i64) -> Self::Get { std::future::ready(Ok(None)) }
//! #     fn authenticate(&self, _: (String, String)) -> Self::Authenticate { std::future::ready(Ok(None)) }
//! # }
//! let layer = ProvideAuthenticationLayer::<AppUser>::new()
//!     .with_backend(MyBackend)
//!     .with_memory_store();
//! ```
//!
//! # feature flags
//!
//! - `axum`: enables Axum extractors and response integration.
//! - `session-local`: keeps the current session in [`tokio`] task-local storage.
//! - `memory-store`: enables the moka-backed in-memory [`store::MemoryStore`].
//! - `password`: enables the [`Password`] helper type.
//! - `serde`: enables serialization support for [`Password`] and generated
//!   scopes.
//! - `sqlx`: enables database encoding/decoding support for [`Password`] and
//!   generated scopes.

pub use crate::{
    authentication::{Authentication, ProvideAuthenticationLayer},
    backend::{Backend, User},
    error::Error,
    scope::Scope,
    session::Session,
    store::Store,
};

#[cfg(feature = "password")]
#[cfg_attr(docsrs, doc(cfg(feature = "password")))]
pub use password::Password;

/// A crate-wide result type using [`Error`] as the error variant.
pub type Result<T> = ::core::result::Result<T, crate::Error>;

/// User and backend traits used to load and authenticate application users.
pub mod backend;

/// Session store traits and built-in store implementations.
pub mod store;

/// Error types returned by snowfinch helpers.
pub mod error;

/// Password hashing and constant-time comparison utilities.
#[cfg(feature = "password")]
#[cfg_attr(docsrs, doc(cfg(feature = "password")))]
pub mod password;

/// Bitmap-backed permission scopes and the [`scope!`] macro.
pub mod scope;

/// Authenticated session values and Axum session extraction.
pub mod session;

/// Authentication middleware and login/logout helpers.
pub mod authentication;

/// Authorization middleware and Tower/Axum extension traits.
pub mod authorization;
