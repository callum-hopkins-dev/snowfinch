//! Interfaces for application users and authentication backends.

use std::{future::Future, hash::Hash};

use crate::Scope;

/// A user that can be authenticated by Snowfinch.
///
/// The user ID is the only part of a user persisted in a session [Store], while
/// the full user is loaded from a [Backend] when that session is restored.
///
/// [Store]: crate::store::Store
pub trait User: Send + Sync + 'static {
    /// The permission scope carried by this user.
    type Scope: Scope;

    /// The stable identifier used to persist and reload this user.
    type Id: Clone + Eq + Hash + Send + Sync + 'static;

    /// Returns the user's stable identifier.
    fn id(&self) -> Self::Id;

    /// Returns the permissions granted to this user.
    fn scope(&self) -> Self::Scope;
}

/// Loads users and authenticates credentials.
///
/// Returned futures use return-position `impl Future`, so implementations can
/// expose their concrete futures without allocation or type erasure.
pub trait Backend: Send + Sync + 'static {
    /// Credentials accepted when authenticating this user.
    type Credentials;

    /// User managed by this backend.
    type User: User;

    /// Backend-specific failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Loads a user by their stable identifier.
    ///
    /// Returns `Ok(None)` when the identifier no longer belongs to a valid
    /// user.
    fn get(
        &self,
        id: <Self::User as User>::Id,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;

    /// Authenticates a set of credentials.
    ///
    /// Returns `Ok(Some(user))` when authentication succeeds, `Ok(None)` when
    /// the credentials are rejected, and `Err` for a backend failure.
    fn authenticate(
        &self,
        credentials: Self::Credentials,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;
}
