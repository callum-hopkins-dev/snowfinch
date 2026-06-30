//! Type-erased session store support.

use std::{pin::Pin, sync::Arc};

use crate::User;

use super::{CreateSessionError, Session, Store};

/// Type-erased [`Store`] used by authentication middleware.
pub struct ErasedStore<User>(Arc<dyn DynStore<User = User>>);

impl<User> ErasedStore<User> {
    /// Wraps a concrete store in a type-erased handle.
    #[inline]
    pub fn new<S>(store: S) -> Self
    where
        S: Store<User = User> + 'static,
    {
        Self(Arc::new(store))
    }
}

impl<User> Clone for ErasedStore<User> {
    #[inline]
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<User> Store for ErasedStore<User>
where
    User: crate::User,
{
    type Error = BoxError;

    type User = User;

    type Get = BoxFuture<Result<Option<Session<User::Id>>, BoxError>>;

    type Create = BoxFuture<Result<(), CreateSessionError<BoxError>>>;

    type Revoke = BoxFuture<Result<(), BoxError>>;

    #[inline]
    fn get(&self, id: u128) -> Self::Get {
        self.0.get(id)
    }

    #[inline]
    fn create(&self, session: Session<User::Id>) -> Self::Create {
        self.0.create(session)
    }

    #[inline]
    fn revoke(&self, session: Session<User::Id>) -> Self::Revoke {
        self.0.revoke(session)
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

trait DynStore: Send + Sync + 'static {
    type User: User;

    #[allow(clippy::type_complexity)]
    fn get(
        &self,
        id: u128,
    ) -> BoxFuture<Result<Option<Session<<Self::User as User>::Id>>, BoxError>>;

    fn create(
        &self,
        session: Session<<Self::User as User>::Id>,
    ) -> BoxFuture<Result<(), CreateSessionError<BoxError>>>;

    fn revoke(&self, session: Session<<Self::User as User>::Id>)
    -> BoxFuture<Result<(), BoxError>>;
}

impl<T> DynStore for T
where
    T: Store,
{
    type User = T::User;

    #[inline]
    fn get(
        &self,
        id: u128,
    ) -> BoxFuture<Result<Option<Session<<Self::User as User>::Id>>, BoxError>> {
        let fut = self.get(id);
        Box::pin(async move { fut.await.map_err(Into::into) })
    }

    #[inline]
    fn create(
        &self,
        session: Session<<Self::User as User>::Id>,
    ) -> BoxFuture<Result<(), CreateSessionError<BoxError>>> {
        let fut = self.create(session);

        Box::pin(async move {
            match fut.await {
                Ok(x) => Ok(x),
                Err(CreateSessionError::AlreadyExists) => Err(CreateSessionError::AlreadyExists),
                Err(CreateSessionError::Other(err)) => Err(CreateSessionError::Other(err.into())),
            }
        })
    }

    #[inline]
    fn revoke(
        &self,
        session: Session<<Self::User as User>::Id>,
    ) -> BoxFuture<Result<(), BoxError>> {
        let fut = self.revoke(session);
        Box::pin(async move { fut.await.map_err(Into::into) })
    }
}
