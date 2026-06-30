//! Traits for application users and authentication backends.

use std::{hash::Hash, pin::Pin, sync::Arc};

use crate::Scope;

/// A user type that can be authenticated by snowfinch.
///
/// Implement this trait for the user model used by your application. The
/// associated [`Scope`](Self::Scope) type describes the permissions granted to a
/// user, and [`Credentials`](Self::Credentials) is the value your backend needs
/// to authenticate a login attempt.
pub trait User: Send + Sync + 'static {
    /// The permission scope type carried by this user.
    type Scope: Scope;

    /// The stable identifier used to reload this user from a session.
    type Id: Clone + Eq + Hash + Send + Sync + 'static;

    /// Credentials accepted by the backend when authenticating a login attempt.
    type Credentials;

    /// Returns the stable identifier for this user.
    fn id(&self) -> Self::Id;

    /// Returns the permissions granted to this user.
    fn scope(&self) -> Self::Scope;
}

/// Loads users and authenticates credentials.
///
/// A backend is the application-specific bridge between snowfinch and your user
/// database or identity provider. It is used both to resolve a user id from an
/// existing session and to authenticate credentials during login.
pub trait Backend: Send + Sync + 'static {
    /// The user type managed by this backend.
    type User: User;

    /// Errors produced while loading or authenticating users.
    type Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>;

    /// Future returned by [`Backend::get`].
    type Get: Future<Output = Result<Option<Self::User>, Self::Error>> + Send + 'static;

    /// Future returned by [`Backend::authenticate`].
    type Authenticate: Future<Output = Result<Option<Self::User>, Self::Error>> + Send + 'static;

    /// Loads a user by id.
    ///
    /// Return `Ok(None)` when the id no longer belongs to a valid user.
    fn get(&self, id: <Self::User as User>::Id) -> Self::Get;

    /// Authenticates a set of credentials.
    ///
    /// Return `Ok(Some(user))` for a successful login, `Ok(None)` for rejected
    /// credentials, and `Err` for backend failures.
    fn authenticate(&self, credentials: <Self::User as User>::Credentials) -> Self::Authenticate;
}

/// Type-erased [`Backend`] used internally by authentication middleware.
pub struct ErasedBackend<User>(Arc<dyn DynBackend<User = User>>);

impl<User> ErasedBackend<User> {
    #[inline]
    pub(crate) fn new<D>(backend: D) -> Self
    where
        D: Backend<User = User> + 'static,
    {
        Self(Arc::new(backend))
    }
}

impl<User> Clone for ErasedBackend<User> {
    #[inline]
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<User> Backend for ErasedBackend<User>
where
    User: self::User,
{
    type User = User;

    type Error = BoxError;

    type Get = BoxFuture<Result<Option<Self::User>, BoxError>>;

    type Authenticate = BoxFuture<Result<Option<Self::User>, BoxError>>;

    #[inline]
    fn get(&self, id: User::Id) -> Self::Get {
        self.0.get(id)
    }

    #[inline]
    fn authenticate(&self, credentials: User::Credentials) -> Self::Authenticate {
        self.0.authenticate(credentials)
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

trait DynBackend: Send + Sync + 'static {
    type User: User;

    fn get(&self, id: <Self::User as User>::Id) -> BoxFuture<Result<Option<Self::User>, BoxError>>;

    fn authenticate(
        &self,
        credentials: <Self::User as User>::Credentials,
    ) -> BoxFuture<Result<Option<Self::User>, BoxError>>;
}

impl<T> DynBackend for T
where
    T: Backend,
{
    type User = T::User;

    #[inline]
    fn get(&self, id: <Self::User as User>::Id) -> BoxFuture<Result<Option<Self::User>, BoxError>> {
        let fut = self.get(id);
        Box::pin(async move { fut.await.map_err(Into::into) })
    }

    #[inline]
    fn authenticate(
        &self,
        credentials: <Self::User as User>::Credentials,
    ) -> BoxFuture<Result<Option<Self::User>, BoxError>> {
        let fut = self.authenticate(credentials);
        Box::pin(async move { fut.await.map_err(Into::into) })
    }
}
