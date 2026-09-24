#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Authentication, sessions, and authorization for Tower and Axum services.
//!
//! Snowfinch provides a small set of interfaces for session-based
//! authentication without prescribing an application database or user model.
//! The core middleware is built on [Tower](tower), while the optional `axum`
//! feature adds extractors, response integration, and router conveniences.
//!
//! # Architecture
//!
//! Applications provide three pieces:
//!
//! - a [`User`] value containing a stable ID and permission [`Scope`];
//! - a [`Backend`] which loads users and authenticates credentials;
//! - a [`Store`] which persists compact session records.
//!
//! Stores retain only a session ID, expiry, and user ID. When a request carries
//! a valid `session` cookie, [`ProvideAuthenticationLayer`] loads that compact
//! record, rejects it if expired, and asks the backend for the current user.
//! The resulting [`Session`] and a cheaply cloned [`Authentication`] handle
//! are inserted into the request extensions.
//!
//! This separation keeps large user values out of the session store and ensures
//! that restored sessions use current user data and permissions.
//!
//! # Example
//!
//! ```
//! use std::convert::Infallible;
//!
//! use snowfinch::{Backend, ProvideAuthenticationLayer, User, scope};
//!
//! scope! {
//!     pub enum Permissions {
//!         Read = 0,
//!         Write = 1,
//!         Admin = Read && Write,
//!     }
//! }
//!
//! struct AppUser {
//!     id: i64,
//!     scope: Permissions,
//! }
//!
//! impl User for AppUser {
//!     type Scope = Permissions;
//!     type Id = i64;
//!
//!     fn id(&self) -> Self::Id {
//!         self.id
//!     }
//!
//!     fn scope(&self) -> Self::Scope {
//!         self.scope
//!     }
//! }
//!
//! struct AppBackend;
//!
//! impl Backend for AppBackend {
//!     type Credentials = (String, String);
//!     type User = AppUser;
//!     type Error = Infallible;
//!
//!     fn get(
//!         &self,
//!         _id: i64,
//!     ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
//!         std::future::ready(Ok(None))
//!     }
//!
//!     fn authenticate(
//!         &self,
//!         _credentials: Self::Credentials,
//!     ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
//!         std::future::ready(Ok(None))
//!     }
//! }
//!
//! // Without an explicit store, the layer uses NoopStore. Configure a custom
//! // Store or call with_memory_store() when sessions should survive requests.
//! let _layer = ProvideAuthenticationLayer::new().with_backend(AppBackend);
//! ```
//!
//! Backend and store methods use return-position `impl Future`, so
//! implementations do not need to name, box, or erase their futures. The
//! authentication layer shares backend and store values through [`Arc`],
//! therefore neither implementation needs to be [`Clone`].
//!
//! # Login and logout
//!
//! Request handlers obtain the [`Authentication`] handle from request
//! extensions, or as an Axum extractor when the `axum` feature is enabled.
//! [`Authentication::authenticate`] validates credentials,
//! [`Authentication::login`] creates and persists a session, and
//! [`Authentication::logout`] revokes it.
//!
//! A returned [`Session`] can be added to an Axum response. Its response-parts
//! implementation writes the secure, HTTP-only `session` cookie.
//!
//! # Authorization
//!
//! The [`authorization`] module provides Tower middleware for rejecting
//! requests without an acceptable authenticated session:
//!
//! - [`authorization::RequireAuthenticated`] accepts any authenticated user;
//! - [`authorization::RequireScope`] requires a complete permission scope;
//! - [`authorization::AuthorizeFn`] adapts a closure;
//! - [`authorization::RequireAuthorizationLayer`] accepts a custom
//!   [`authorization::Authorize`] implementation.
//!
//! Extension traits are provided for [`tower::ServiceBuilder`], and for Axum
//! routers and method routers when the `axum` feature is enabled.
//!
//! # Permission scopes
//!
//! The [`scope!`] macro defines a compact, `u64`-backed permission type.
//! Generated scopes support aliases, lookup by name, iteration, set operations,
//! raw `u64` conversion, and optional Serde and SQLx integration. Unknown raw
//! bits are ignored when constructing or decoding a scope.
//!
//! # Passwords
//!
//! [`Password`] is a packed 64-byte salted SHA-256 value containing a 32-byte
//! hash followed by a 32-byte salt. Plaintext comparisons recompute the hash and
//! compare the packed representation in constant time. With `sqlx`, passwords
//! are encoded directly as binary blobs.
//!
//! # Feature flags
//!
//! The default feature set enables `memory-store` and `session-local`.
//!
//! - `axum` enables extractors, response integration, and router extensions.
//! - `memory-store` enables the Moka-backed [`store::MemoryStore`].
//! - `serde` enables serialization for [`Password`] and generated scopes.
//! - `session-local` exposes the current session through
//!   [`session::current`] and [`session::try_current`].
//! - `sqlx` enables database encoding and decoding for [`Password`] and
//!   generated scopes.
//!
//! [`Arc`]: std::sync::Arc
//! [`Clone`]: std::clone::Clone

pub mod authentication;
pub mod authorization;
pub mod backend;
pub mod password;
pub mod scope;
pub mod session;
pub mod store;

pub use self::{
    authentication::{Authentication, AuthenticationError, ProvideAuthenticationLayer},
    backend::{Backend, User},
    password::Password,
    scope::Scope,
    session::Session,
    store::Store,
};
