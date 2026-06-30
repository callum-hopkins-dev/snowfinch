//! Session store traits and implementations.

#[doc(hidden)]
pub mod erased_store;

#[cfg(feature = "memory-store")]
#[doc(hidden)]
pub mod memory_store;

use std::{convert::Infallible, future::Ready, marker::PhantomData};

/// Type-erased session store used by authentication middleware.
pub use erased_store::ErasedStore;

#[cfg(feature = "memory-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "memory-store")))]
/// Moka-backed in-memory session store.
pub use memory_store::MemoryStore;

use chrono::{DateTime, Utc};

use crate::User;

/// Store representation of a persisted session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Session<UserId> {
    /// Opaque session id encoded into the `session` cookie.
    pub id: u128,
    /// Expiration timestamp for the session.
    pub expires: DateTime<Utc>,
    /// Identifier of the authenticated user.
    pub user_id: UserId,
}

/// Persists, loads, and revokes sessions.
///
/// Custom stores can use any backing system as long as they preserve session ids
/// and user ids. Implementations should return `Ok(None)` from [`get`](Self::get)
/// when a session is absent or has already been expired and removed.
pub trait Store: Send + Sync + 'static {
    /// Errors produced by the store.
    type Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>;

    /// The user type whose ids are stored in sessions.
    type User: User;

    /// Future returned by [`Store::get`].
    type Get: Future<Output = Result<Option<Session<<Self::User as User>::Id>>, Self::Error>>
        + Send
        + 'static;

    /// Future returned by [`Store::create`].
    type Create: Future<Output = Result<(), CreateSessionError<Self::Error>>> + Send + 'static;

    /// Future returned by [`Store::revoke`].
    type Revoke: Future<Output = Result<(), Self::Error>> + Send + 'static;

    /// Loads the session with the given id.
    fn get(&self, id: u128) -> Self::Get;

    /// Persists a newly-created session.
    ///
    /// Return [`CreateSessionError::AlreadyExists`] when another session already
    /// uses the same id so the caller can retry with a different id.
    fn create(&self, session: Session<<Self::User as User>::Id>) -> Self::Create;

    /// Revokes a session so it can no longer authenticate requests.
    fn revoke(&self, session: Session<<Self::User as User>::Id>) -> Self::Revoke;
}

/// Error returned while creating a session in a store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, thiserror::Error)]
pub enum CreateSessionError<T> {
    /// A session with the generated id already exists.
    #[error("a session with the specified id already exists")]
    AlreadyExists,

    /// The store returned an implementation-specific error.
    #[error(transparent)]
    Other(#[from] T),
}

/// Store implementation that never persists sessions.
///
/// `NoopStore` accepts session creation and revocation but always returns
/// `Ok(None)` for lookups. It is useful as a placeholder and is the default store
/// used by [`ProvideAuthenticationLayer`](crate::ProvideAuthenticationLayer) when
/// no explicit store is configured.
pub struct NoopStore<User>(PhantomData<User>);

impl<User> std::fmt::Debug for NoopStore<User> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NoopStore")
            .field(&::core::any::type_name::<User>())
            .finish()
    }
}

impl<User> NoopStore<User> {
    /// Creates a no-op store.
    #[inline]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<User> Default for NoopStore<User> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<User> Store for NoopStore<User>
where
    User: crate::User,
{
    type Error = Infallible;

    type User = User;

    type Get = Ready<Result<Option<Session<User::Id>>, Infallible>>;

    type Create = Ready<Result<(), CreateSessionError<Infallible>>>;

    type Revoke = Ready<Result<(), Infallible>>;

    #[inline]
    fn get(&self, _id: u128) -> Self::Get {
        ::core::future::ready(Ok(None))
    }

    #[inline]
    fn create(&self, _session: Session<User::Id>) -> Self::Create {
        ::core::future::ready(Ok(()))
    }

    #[inline]
    fn revoke(&self, _session: Session<User::Id>) -> Self::Revoke {
        ::core::future::ready(Ok(()))
    }
}
