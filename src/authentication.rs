//! Authentication state and Tower middleware.

use std::{marker::PhantomData, task::Poll};

use chrono::{Days, Utc};
use http::header::COOKIE;
use pin_project_lite::pin_project;
use tower::{Layer, Service};

use crate::{
    Backend, Session, Store,
    backend::ErasedBackend,
    store::{CreateSessionError, ErasedStore, NoopStore},
};

/// Request-scoped authentication handle.
///
/// This handle is inserted into each request by [`ProvideAuthenticationLayer`].
/// It can authenticate credentials, create a persisted session on login, and
/// revoke the current session on logout.
pub struct Authentication<User> {
    backend: ErasedBackend<User>,
    store: ErasedStore<User>,
}

impl<User> std::fmt::Debug for Authentication<User> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Authentication")
            .field(&::core::any::type_name::<User>())
            .finish()
    }
}

impl<User> Clone for Authentication<User> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            store: self.store.clone(),
        }
    }
}

impl<User> Authentication<User>
where
    User: crate::User,
{
    /// Authenticates credentials using the configured backend.
    ///
    /// Returns `Ok(Some(user))` when the credentials are valid, `Ok(None)` when
    /// they are rejected, and `Err` if the backend fails.
    pub async fn authenticate(
        &self,
        credentials: User::Credentials,
    ) -> crate::Result<Option<User>> {
        self.backend
            .authenticate(credentials)
            .await
            .map_err(crate::Error::Other)
    }

    /// Creates a new session for `user`.
    ///
    /// The session is persisted in the configured store, made current for the
    /// active task when `session-local` is enabled, and returned so it can be
    /// attached to the HTTP response.
    pub async fn login(&self, user: User) -> crate::Result<Session<User>> {
        let expires = Utc::now() + Days::new(30);

        loop {
            let id: u128 = rand::random();

            match self
                .store
                .create(crate::store::Session {
                    id,
                    expires,
                    user_id: user.id(),
                })
                .await
            {
                Ok(_) => {
                    let session = Session::new(id, expires, user);

                    crate::session::insert(&session);

                    break Ok(session);
                }

                Err(CreateSessionError::AlreadyExists) => continue,
                Err(CreateSessionError::Other(err)) => return Err(crate::Error::Other(err)),
            }
        }
    }

    /// Revokes an existing session.
    ///
    /// The session is removed from the configured store and from task-local
    /// storage when the `session-local` feature is enabled.
    pub async fn logout(&self, session: Session<User>) -> crate::Result<()> {
        self.store
            .revoke(crate::store::Session {
                id: session.id(),
                expires: session.expires(),
                user_id: session.user().id(),
            })
            .await
            .map_err(crate::Error::Other)?;

        crate::session::remove::<User>();

        Ok(())
    }
}

#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<S, User> axum::extract::FromRequestParts<S> for Authentication<User>
where
    User: crate::User,
    S: Send + Sync,
{
    type Rejection = ::core::convert::Infallible;

    #[inline]
    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().unwrap().clone())
    }
}

/// A Tower layer that provides authentication state to requests.
///
/// Add this layer to a Tower service stack to insert an [`Authentication`] handle
/// into request extensions and to resolve an incoming `session` cookie into a
/// [`Session`] when possible.
///
/// A backend must be supplied with [`with_backend`](Self::with_backend). If no
/// store is supplied, [`crate::store::NoopStore`] is used and sessions are not persisted
/// between requests.
pub struct ProvideAuthenticationLayer<User, Database = ()> {
    backend: Option<ErasedBackend<User>>,
    store: Option<ErasedStore<User>>,
    _phantom: PhantomData<Database>,
}

impl<User> Default for ProvideAuthenticationLayer<User> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<User> ProvideAuthenticationLayer<User> {
    /// Creates a layer builder with no backend or store configured.
    #[inline]
    pub const fn new() -> Self {
        Self {
            backend: None,
            store: None,
            _phantom: PhantomData,
        }
    }
}

impl<User, Database> Clone for ProvideAuthenticationLayer<User, Database> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            store: self.store.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<User, Database> ProvideAuthenticationLayer<User, Database>
where
    User: crate::User,
{
    /// Configures the backend used to load and authenticate users.
    #[inline]
    pub fn with_backend<T>(self, backend: T) -> ProvideAuthenticationLayer<User, T>
    where
        T: crate::Backend<User = User> + 'static,
    {
        ProvideAuthenticationLayer {
            backend: Some(ErasedBackend::new(backend)),
            store: self.store,
            _phantom: PhantomData,
        }
    }

    /// Configures the session store used to persist logins.
    #[inline]
    pub fn with_store<T>(self, store: T) -> Self
    where
        T: crate::Store<User = User> + 'static,
    {
        Self {
            store: Some(ErasedStore::new(store)),
            ..self
        }
    }

    /// Configures the built-in moka-backed in-memory session store.
    #[cfg(feature = "memory-store")]
    #[cfg_attr(docsrs, doc(cfg(feature = "memory-store")))]
    #[inline]
    pub fn with_memory_store(self) -> Self {
        self.with_store(crate::store::MemoryStore::new())
    }
}

impl<S, User, Database> Layer<S> for ProvideAuthenticationLayer<User, Database>
where
    User: crate::User,
    Database: crate::Backend<User = User> + 'static,
{
    type Service = ProvideAuthentication<S, Database::User>;

    #[inline]
    fn layer(&self, inner: S) -> Self::Service {
        ProvideAuthentication {
            state: Authentication {
                backend: self.backend.as_ref().cloned().unwrap(),

                store: self
                    .store
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| ErasedStore::new(NoopStore::new())),
            },
            inner,
        }
    }
}

/// Service produced by [`ProvideAuthenticationLayer`].
pub struct ProvideAuthentication<S, User> {
    state: Authentication<User>,
    inner: S,
}

impl<S, User> Clone for ProvideAuthentication<S, User>
where
    S: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<S, Body, User> Service<http::Request<Body>> for ProvideAuthentication<S, User>
where
    S: Service<http::Request<Body>> + Clone + Send + 'static,
    User: crate::User,
{
    type Response = S::Response;

    type Error = S::Error;

    type Future = ProvideAuthenticationFuture<Body, S, User>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<Body>) -> Self::Future {
        req.extensions_mut().insert(self.state.clone());

        let session = req
            .headers()
            .get_all(COOKIE)
            .iter()
            .find_map(|x| {
                x.as_bytes()
                    .split(|&x| x == b';')
                    .find_map(|x| x.trim_ascii().strip_prefix(b"session="))
            })
            .and_then(|x| const_hex::decode_to_array(x).ok())
            .map(u128::from_be_bytes);

        ProvideAuthenticationFuture {
            inner: match session {
                Some(id) => ProvideAuthenticationFutureInner::Store {
                    future: self.state.store.get(id),
                    database: self.state.backend.clone(),
                    req: Some(req),
                    service: Some(self.inner.clone()),
                },

                None => ProvideAuthenticationFutureInner::Service {
                    future: self.inner.call(req),
                },
            },
        }
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct ProvideAuthenticationFuture<Body, S, User>
    where
        User: crate::User,
        S: Service<http::Request<Body>>,
    {
        #[pin] inner: ProvideAuthenticationFutureInner<Body, S, User>,
    }
}

pin_project! {
    #[project = ProvideAuthenticationFutureProj]
    enum ProvideAuthenticationFutureInner<Body, S, User>
    where
        User: crate::User,
        S: Service<http::Request<Body>>,
    {
        Store {
            #[pin] future: <ErasedStore<User> as Store>::Get,

            database: ErasedBackend<User>,
            req: Option<http::Request<Body>>,
            service: Option<S>,
        },

        Database {
            #[pin] future: <ErasedBackend<User> as Backend>::Get,

            session: crate::store::Session<User::Id>,
            req: Option<http::Request<Body>>,
            service: Option<S>,
        },

        Service {
            #[pin] future: S::Future,
        },
    }
}

impl<Body, S, User> Future for ProvideAuthenticationFuture<Body, S, User>
where
    User: crate::User,
    S: Service<http::Request<Body>>,
{
    type Output = <S::Future as Future>::Output;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        match this.inner.as_mut().project() {
            ProvideAuthenticationFutureProj::Store {
                future,
                req,
                service,
                database,
            } => match future.poll(cx) {
                Poll::Ready(result) => match result {
                    Ok(Some(session)) if session.expires > Utc::now() => {
                        let future = database.get(session.user_id.clone());
                        let req = Some(req.take().unwrap());
                        let service = Some(service.take().unwrap());

                        this.inner.set(ProvideAuthenticationFutureInner::Database {
                            future,
                            session,
                            req,
                            service,
                        });

                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }

                    _ => {
                        let future = service.take().unwrap().call(req.take().unwrap());

                        this.inner
                            .set(ProvideAuthenticationFutureInner::Service { future });

                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                },

                Poll::Pending => Poll::Pending,
            },

            ProvideAuthenticationFutureProj::Database {
                future,
                session,
                req,
                service,
            } => match future.poll(cx) {
                Poll::Ready(result) => {
                    let mut req = req.take().unwrap();

                    if let Ok(Some(user)) = result {
                        let session = Session::new(session.id, session.expires, user);

                        crate::session::insert(&session);
                        req.extensions_mut().insert(session);
                    }

                    let future = service.take().unwrap().call(req);

                    this.inner
                        .set(ProvideAuthenticationFutureInner::Service { future });

                    cx.waker().wake_by_ref();
                    Poll::Pending
                }

                Poll::Pending => Poll::Pending,
            },

            ProvideAuthenticationFutureProj::Service { future } => future.poll(cx),
        }
    }
}
