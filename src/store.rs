//! Session persistence interfaces and built-in stores.

use std::{convert::Infallible, future::Future, marker::PhantomData};

use chrono::{DateTime, Utc};

/// The compact session value persisted by a [Store].
///
/// Stores retain only the opaque session ID, its expiry, and the corresponding
/// user ID. The full user value is loaded separately by the authentication
/// backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Session<UserId> {
    /// Opaque session identifier.
    pub id: u128,

    /// Instant at which the session expires.
    pub expires: DateTime<Utc>,

    /// Identifier of the authenticated user.
    pub user_id: UserId,
}

/// Persists, loads, and revokes compact session records.
///
/// The returned futures use return-position `impl Future`, allowing each store
/// to expose its concrete future without allocation or type erasure.
pub trait Store: Send + Sync + 'static {
    /// User identifier retained by this store.
    type UserId: Send + Sync + 'static;

    /// Store-specific failure.
    type Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>;

    /// Loads a session by its opaque identifier.
    fn get(
        &self,
        id: u128,
    ) -> impl Future<Output = Result<Option<Session<Self::UserId>>, Self::Error>> + Send;

    /// Persists a new session.
    ///
    /// Returns [CreateSessionError::AlreadyExists] when `session.id` is already
    /// present, allowing the caller to generate another identifier and retry.
    fn create(
        &self,
        session: Session<Self::UserId>,
    ) -> impl Future<Output = Result<(), CreateSessionError<Self::Error>>> + Send;

    /// Revokes the session with the supplied opaque identifier.
    fn revoke(&self, id: u128) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Error returned while creating a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CreateSessionError<Error> {
    /// A session with the requested identifier already exists.
    AlreadyExists,

    /// The store returned an implementation-specific failure.
    Other(Error),
}

impl<Error> std::fmt::Display for CreateSessionError<Error>
where
    Error: std::fmt::Display,
{
    #[inline(always)]
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists => {
                formatter.write_str("a session with the specified ID already exists")
            }
            Self::Other(error) => error.fmt(formatter),
        }
    }
}

impl<Error> std::error::Error for CreateSessionError<Error>
where
    Error: std::error::Error + 'static,
{
    #[inline(always)]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AlreadyExists => None,
            Self::Other(error) => Some(error),
        }
    }
}

impl<Error> From<Error> for CreateSessionError<Error> {
    #[inline(always)]
    fn from(error: Error) -> Self {
        Self::Other(error)
    }
}

/// Store which accepts mutations but never persists a session.
pub struct NoopStore<UserId>(PhantomData<UserId>);

impl<UserId> NoopStore<UserId> {
    /// Creates an empty no-op store.
    #[inline(always)]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<UserId> Clone for NoopStore<UserId> {
    #[inline(always)]
    fn clone(&self) -> Self {
        *self
    }
}

impl<UserId> Copy for NoopStore<UserId> {}

impl<UserId> Default for NoopStore<UserId> {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<UserId> std::fmt::Debug for NoopStore<UserId> {
    #[inline(always)]
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("NoopStore")
            .field(&std::any::type_name::<UserId>())
            .finish()
    }
}

impl<UserId> Store for NoopStore<UserId>
where
    UserId: Send + Sync + 'static,
{
    type UserId = UserId;
    type Error = Infallible;

    #[inline(always)]
    fn get(
        &self,
        _id: u128,
    ) -> impl Future<Output = Result<Option<Session<Self::UserId>>, Self::Error>> + Send {
        std::future::ready(Ok(None))
    }

    #[inline(always)]
    fn create(
        &self,
        _session: Session<Self::UserId>,
    ) -> impl Future<Output = Result<(), CreateSessionError<Self::Error>>> + Send {
        std::future::ready(Ok(()))
    }

    #[inline(always)]
    fn revoke(&self, _id: u128) -> impl Future<Output = Result<(), Self::Error>> + Send {
        std::future::ready(Ok(()))
    }
}

/// In-memory session store.
///
/// The backing cache is an implementation detail. Entries expire according to
/// [Session::expires].
#[cfg(feature = "memory-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "memory-store")))]
pub struct MemoryStore<UserId>(moka::future::Cache<u128, Session<UserId>>);

#[cfg(feature = "memory-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "memory-store")))]
impl<UserId> MemoryStore<UserId>
where
    UserId: Clone + Send + Sync + 'static,
{
    /// Creates an empty in-memory store.
    #[inline(always)]
    pub fn new() -> Self {
        Self(
            moka::future::Cache::builder()
                .expire_after(SessionExpiry::<UserId>::new())
                .build(),
        )
    }
}

#[cfg(feature = "memory-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "memory-store")))]
impl<UserId> Default for MemoryStore<UserId>
where
    UserId: Clone + Send + Sync + 'static,
{
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "memory-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "memory-store")))]
impl<UserId> Clone for MemoryStore<UserId>
where
    UserId: Clone + Send + Sync + 'static,
{
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(feature = "memory-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "memory-store")))]
impl<UserId> std::fmt::Debug for MemoryStore<UserId>
where
    UserId: Clone + Send + Sync + 'static,
{
    #[inline(always)]
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("MemoryStore")
            .field(&std::any::type_name::<UserId>())
            .finish()
    }
}

#[cfg(feature = "memory-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "memory-store")))]
impl<UserId> Store for MemoryStore<UserId>
where
    UserId: Clone + Send + Sync + 'static,
{
    type UserId = UserId;
    type Error = Infallible;

    #[inline(always)]
    fn get(
        &self,
        id: u128,
    ) -> impl Future<Output = Result<Option<Session<Self::UserId>>, Self::Error>> + Send {
        let cache = self.0.clone();

        async move { Ok(cache.get(&id).await) }
    }

    #[inline(always)]
    fn create(
        &self,
        session: Session<Self::UserId>,
    ) -> impl Future<Output = Result<(), CreateSessionError<Self::Error>>> + Send {
        let cache = self.0.clone();

        async move {
            if cache.entry(session.id).or_insert(session).await.is_fresh() {
                Ok(())
            } else {
                Err(CreateSessionError::AlreadyExists)
            }
        }
    }

    #[inline(always)]
    fn revoke(&self, id: u128) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let cache = self.0.clone();

        async move {
            cache.invalidate(&id).await;
            Ok(())
        }
    }
}

#[cfg(feature = "memory-store")]
struct SessionExpiry<UserId>(PhantomData<fn() -> UserId>);

#[cfg(feature = "memory-store")]
impl<UserId> SessionExpiry<UserId> {
    #[inline(always)]
    const fn new() -> Self {
        Self(PhantomData)
    }
}

#[cfg(feature = "memory-store")]
impl<UserId> moka::Expiry<u128, Session<UserId>> for SessionExpiry<UserId>
where
    UserId: Clone + Send + Sync + 'static,
{
    #[inline(always)]
    fn expire_after_create(
        &self,
        _key: &u128,
        value: &Session<UserId>,
        _created_at: std::time::Instant,
    ) -> Option<std::time::Duration> {
        Some(
            (value.expires - Utc::now())
                .to_std()
                .unwrap_or(std::time::Duration::ZERO),
        )
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Days, Utc};

    use super::{NoopStore, Session, Store};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    #[test]
    fn noop_store_never_persists_sessions() {
        let store = NoopStore::<u64>::new();
        let session = Session {
            id: 42,
            expires: Utc::now() + Days::new(1),
            user_id: 7,
        };

        runtime().block_on(async {
            store.create(session).await.unwrap();
            assert_eq!(store.get(session.id).await.unwrap(), None);
            store.revoke(session.id).await.unwrap();
        });
    }

    #[cfg(feature = "memory-store")]
    #[test]
    fn memory_store_creates_loads_and_revokes_sessions() {
        let store = super::MemoryStore::<u64>::new();
        let session = Session {
            id: 42,
            expires: Utc::now() + Days::new(1),
            user_id: 7,
        };

        runtime().block_on(async {
            store.create(session).await.unwrap();
            assert_eq!(store.get(session.id).await.unwrap(), Some(session));
            assert_eq!(
                store.create(session).await.unwrap_err(),
                super::CreateSessionError::AlreadyExists,
            );

            store.revoke(session.id).await.unwrap();
            assert_eq!(store.get(session.id).await.unwrap(), None);
        });
    }

    #[cfg(feature = "memory-store")]
    #[test]
    fn memory_store_drops_expired_sessions() {
        let store = super::MemoryStore::<u64>::new();
        let session = Session {
            id: 42,
            expires: Utc::now() - Days::new(1),
            user_id: 7,
        };

        runtime().block_on(async {
            store.create(session).await.unwrap();
            assert_eq!(store.get(session.id).await.unwrap(), None);
        });
    }
}
