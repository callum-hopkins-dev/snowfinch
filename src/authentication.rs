//! Authentication state and Tower middleware.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use chrono::{Days, Utc};
use http::header::COOKIE;
use tower::{Layer, Service};

use crate::{Session, User, store::CreateSessionError};

/// A failure returned while authenticating credentials or mutating a session.
#[derive(thiserror::Error)]
pub enum AuthenticationError<Backend, Store>
where
    Backend: crate::Backend,
    Store: crate::Store,
{
    /// The authentication backend failed.
    #[error(transparent)]
    Backend(Backend::Error),

    /// The session store failed.
    #[error(transparent)]
    Store(Store::Error),
}

impl<Backend, Store> std::fmt::Debug for AuthenticationError<Backend, Store>
where
    Backend: crate::Backend,
    Store: crate::Store,
{
    #[inline(always)]
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(error) => formatter.debug_tuple("Backend").field(error).finish(),
            Self::Store(error) => formatter.debug_tuple("Store").field(error).finish(),
        }
    }
}

/// A cheaply cloned handle for authenticating users and managing sessions.
///
/// Backend and store types remain concrete. Only the handle's shared inner
/// state is reference counted.
pub struct Authentication<Backend, Store>(Arc<Inner<Backend, Store>>);

impl<Backend, Store> Authentication<Backend, Store>
where
    Backend: crate::Backend,
    Store: crate::Store<UserId = <Backend::User as crate::User>::Id>,
{
    /// Creates an authentication handle using `backend` and `store`.
    #[inline(always)]
    pub fn new(backend: Backend, store: Store) -> Self {
        Self::from_shared(Arc::new(backend), Arc::new(store))
    }

    #[inline(always)]
    fn from_shared(backend: Arc<Backend>, store: Arc<Store>) -> Self {
        Self(Arc::new(Inner { backend, store }))
    }

    /// Returns the configured authentication backend.
    #[inline(always)]
    pub fn backend(&self) -> &Backend {
        self.0.backend.as_ref()
    }

    /// Returns the configured session store.
    #[inline(always)]
    pub fn store(&self) -> &Store {
        self.0.store.as_ref()
    }

    /// Authenticates credentials using the configured backend.
    #[inline(always)]
    pub async fn authenticate(
        &self,
        credentials: Backend::Credentials,
    ) -> Result<Option<Backend::User>, AuthenticationError<Backend, Store>> {
        self.0
            .backend
            .authenticate(credentials)
            .await
            .map_err(AuthenticationError::Backend)
    }

    /// Creates and persists a session for `user`.
    ///
    /// Session identifiers are regenerated if the store reports a collision.
    #[inline(always)]
    pub async fn login(
        &self,
        user: Backend::User,
    ) -> Result<Session<Backend::User>, AuthenticationError<Backend, Store>> {
        let expires = Utc::now() + Days::new(30);

        loop {
            let id = rand::random();

            match self
                .0
                .store
                .create(crate::store::Session {
                    id,
                    expires,
                    user_id: user.id(),
                })
                .await
            {
                Ok(()) => {
                    let session = Session::new(id, expires, user);
                    crate::session::insert(&session);

                    return Ok(session);
                }
                Err(CreateSessionError::AlreadyExists) => {}
                Err(CreateSessionError::Other(error)) => {
                    return Err(AuthenticationError::Store(error));
                }
            }
        }
    }

    /// Revokes `session` and clears it from the session-local context.
    #[inline(always)]
    pub async fn logout(
        &self,
        session: Session<Backend::User>,
    ) -> Result<(), AuthenticationError<Backend, Store>> {
        self.0
            .store
            .revoke(session.id())
            .await
            .map_err(AuthenticationError::Store)?;

        crate::session::remove::<Backend::User>();

        Ok(())
    }
}

impl<Backend, Store> Clone for Authentication<Backend, Store> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<Backend, Store> std::fmt::Debug for Authentication<Backend, Store> {
    #[inline(always)]
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Authentication")
            .field("backend", &std::any::type_name::<Backend>())
            .field("store", &std::any::type_name::<Store>())
            .finish()
    }
}

struct Inner<Backend, Store> {
    backend: Arc<Backend>,
    store: Arc<Store>,
}

#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<State, Backend, Store> axum::extract::FromRequestParts<State>
    for Authentication<Backend, Store>
where
    State: Send + Sync,
    Backend: crate::Backend,
    Store: crate::Store<UserId = <Backend::User as crate::User>::Id>,
{
    type Rejection = std::convert::Infallible;

    #[inline(always)]
    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &State,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<Self>()
            .expect("ProvideAuthenticationLayer is not installed")
            .clone())
    }
}

/// A Tower layer that provides authentication state to requests.
///
/// If no store is explicitly configured, sessions use [crate::store::NoopStore]
/// and therefore do not survive beyond the response that created them.
pub struct ProvideAuthenticationLayer<Backend = (), Store = ()> {
    backend: Arc<Backend>,
    store: Arc<Store>,
}

impl ProvideAuthenticationLayer<(), ()> {
    /// Creates a layer builder with no backend or store configured.
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            backend: Arc::new(()),
            store: Arc::new(()),
        }
    }
}

impl Default for ProvideAuthenticationLayer<(), ()> {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<Backend, Store> ProvideAuthenticationLayer<Backend, Store> {
    /// Configures the backend used to load and authenticate users.
    #[inline(always)]
    pub fn with_backend<T>(self, backend: T) -> ProvideAuthenticationLayer<T, Store> {
        ProvideAuthenticationLayer {
            backend: Arc::new(backend),
            store: self.store,
        }
    }

    /// Configures the store used to persist sessions.
    #[inline(always)]
    pub fn with_store<T>(self, store: T) -> ProvideAuthenticationLayer<Backend, T> {
        ProvideAuthenticationLayer {
            backend: self.backend,
            store: Arc::new(store),
        }
    }

    /// Configures a no-op store.
    #[inline(always)]
    pub fn with_noop_store(
        self,
    ) -> ProvideAuthenticationLayer<
        Backend,
        crate::store::NoopStore<<Backend::User as crate::User>::Id>,
    >
    where
        Backend: crate::Backend,
    {
        self.with_store(crate::store::NoopStore::new())
    }

    /// Configures the built-in in-memory store.
    #[cfg(feature = "memory-store")]
    #[cfg_attr(docsrs, doc(cfg(feature = "memory-store")))]
    #[inline(always)]
    pub fn with_memory_store(
        self,
    ) -> ProvideAuthenticationLayer<
        Backend,
        crate::store::MemoryStore<<Backend::User as crate::User>::Id>,
    >
    where
        Backend: crate::Backend,
        <Backend::User as crate::User>::Id: Clone,
    {
        self.with_store(crate::store::MemoryStore::new())
    }
}

impl<Backend, Store> Clone for ProvideAuthenticationLayer<Backend, Store> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            backend: Arc::clone(&self.backend),
            store: Arc::clone(&self.store),
        }
    }
}

impl<Backend, Store, InnerService> Layer<InnerService>
    for ProvideAuthenticationLayer<Backend, Store>
where
    Backend: crate::Backend,
    Store: crate::Store<UserId = <Backend::User as crate::User>::Id>,
{
    type Service = ProvideAuthentication<Backend, Store, InnerService>;

    #[inline(always)]
    fn layer(&self, inner: InnerService) -> Self::Service {
        ProvideAuthentication {
            authentication: Authentication::from_shared(
                Arc::clone(&self.backend),
                Arc::clone(&self.store),
            ),
            inner,
        }
    }
}

impl<Backend, InnerService> Layer<InnerService> for ProvideAuthenticationLayer<Backend, ()>
where
    Backend: crate::Backend,
{
    type Service = ProvideAuthentication<
        Backend,
        crate::store::NoopStore<<Backend::User as crate::User>::Id>,
        InnerService,
    >;

    #[inline(always)]
    fn layer(&self, inner: InnerService) -> Self::Service {
        ProvideAuthentication {
            authentication: Authentication::from_shared(
                Arc::clone(&self.backend),
                Arc::new(crate::store::NoopStore::new()),
            ),
            inner,
        }
    }
}

/// Service produced by [ProvideAuthenticationLayer].
pub struct ProvideAuthentication<Backend, Store, InnerService> {
    authentication: Authentication<Backend, Store>,
    inner: InnerService,
}

impl<Backend, Store, InnerService> Clone for ProvideAuthentication<Backend, Store, InnerService>
where
    InnerService: Clone,
{
    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            authentication: self.authentication.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<Backend, Store, InnerService, Body> Service<http::Request<Body>>
    for ProvideAuthentication<Backend, Store, InnerService>
where
    Backend: crate::Backend,
    Store: crate::Store<UserId = <Backend::User as crate::User>::Id>,
    InnerService: Service<http::Request<Body>> + Clone + Send + 'static,
    InnerService::Future: Send + 'static,
    Body: Send + 'static,
{
    type Response = InnerService::Response;
    type Error = InnerService::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    #[inline(always)]
    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    #[inline(always)]
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let replacement = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, replacement);
        let authentication = self.authentication.clone();
        let future = provide_authentication(authentication, inner, request);

        #[cfg(feature = "session-local")]
        return Box::pin(crate::session::with_session_local(future));

        #[cfg(not(feature = "session-local"))]
        Box::pin(future)
    }
}

async fn provide_authentication<Backend, Store, InnerService, Body>(
    authentication: Authentication<Backend, Store>,
    mut inner: InnerService,
    mut request: http::Request<Body>,
) -> Result<InnerService::Response, InnerService::Error>
where
    Backend: crate::Backend,
    Store: crate::Store<UserId = <Backend::User as crate::User>::Id>,
    InnerService: Service<http::Request<Body>>,
{
    request.extensions_mut().insert(authentication.clone());

    if let Some(id) = session_id(&request)
        && let Ok(Some(stored)) = authentication.store().get(id).await
        && stored.expires > Utc::now()
        && let Ok(Some(user)) = authentication.backend().get(stored.user_id).await
    {
        let session = Session::new(stored.id, stored.expires, user);
        crate::session::insert(&session);
        request.extensions_mut().insert(session);
    }

    inner.call(request).await
}

#[inline(always)]
fn session_id<Body>(request: &http::Request<Body>) -> Option<u128> {
    request
        .headers()
        .get_all(COOKIE)
        .iter()
        .find_map(|header| {
            header
                .as_bytes()
                .split(|byte| *byte == b';')
                .find_map(|cookie| cookie.trim_ascii().strip_prefix(b"session="))
        })
        .and_then(|value| const_hex::decode_to_array::<_, 16>(value).ok())
        .map(u128::from_be_bytes)
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use chrono::{Days, Utc};
    use tower::{Layer, ServiceExt, service_fn};

    use crate::{
        Backend, Store, User,
        store::{CreateSessionError, Session as StoredSession},
    };

    use super::{Authentication, AuthenticationError, ProvideAuthenticationLayer, session_id};

    crate::scope! {
        enum Permissions {
            Read = 0,
        }
    }

    #[derive(Debug)]
    struct Account {
        id: u64,
    }

    impl User for Account {
        type Scope = Permissions;
        type Id = u64;

        #[inline(always)]
        fn id(&self) -> Self::Id {
            self.id
        }

        #[inline(always)]
        fn scope(&self) -> Self::Scope {
            Permissions::Read
        }
    }

    #[derive(Debug, Clone, Copy, thiserror::Error)]
    #[error("{0}")]
    struct TestError(&'static str);

    #[derive(Default)]
    struct Accounts {
        get_calls: Arc<AtomicUsize>,
        fail_get: bool,
        fail_authenticate: bool,
        missing: bool,
    }

    impl Backend for Accounts {
        type Credentials = ();
        type User = Account;
        type Error = TestError;

        #[inline(always)]
        fn get(
            &self,
            id: u64,
        ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
            self.get_calls.fetch_add(1, Ordering::Relaxed);

            std::future::ready(if self.fail_get {
                Err(TestError("get"))
            } else if self.missing {
                Ok(None)
            } else {
                Ok(Some(Account { id }))
            })
        }

        #[inline(always)]
        fn authenticate(
            &self,
            _credentials: Self::Credentials,
        ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
            std::future::ready(if self.fail_authenticate {
                Err(TestError("authenticate"))
            } else {
                Ok(None)
            })
        }
    }

    #[derive(Default)]
    struct StoreState {
        session: Option<StoredSession<u64>>,
        create_attempts: usize,
    }

    #[derive(Default)]
    struct Sessions {
        state: Arc<Mutex<StoreState>>,
        collide_once: Arc<AtomicBool>,
        fail_get: bool,
        fail_create: bool,
        fail_revoke: bool,
    }

    impl Sessions {
        #[inline(always)]
        fn with_session(session: StoredSession<u64>) -> Self {
            Self {
                state: Arc::new(Mutex::new(StoreState {
                    session: Some(session),
                    create_attempts: 0,
                })),
                ..Self::default()
            }
        }

        #[inline(always)]
        fn stored(&self) -> Option<StoredSession<u64>> {
            self.state.lock().unwrap().session
        }

        #[inline(always)]
        fn create_attempts(&self) -> usize {
            self.state.lock().unwrap().create_attempts
        }
    }

    impl Store for Sessions {
        type UserId = u64;
        type Error = TestError;

        #[inline(always)]
        fn get(
            &self,
            id: u128,
        ) -> impl Future<Output = Result<Option<StoredSession<Self::UserId>>, Self::Error>> + Send
        {
            std::future::ready(if self.fail_get {
                Err(TestError("get"))
            } else {
                Ok(self
                    .state
                    .lock()
                    .unwrap()
                    .session
                    .filter(|session| session.id == id))
            })
        }

        #[inline(always)]
        fn create(
            &self,
            session: StoredSession<Self::UserId>,
        ) -> impl Future<Output = Result<(), CreateSessionError<Self::Error>>> + Send {
            let mut state = self.state.lock().unwrap();
            state.create_attempts += 1;

            let result = if self.fail_create {
                Err(CreateSessionError::Other(TestError("create")))
            } else if self.collide_once.swap(false, Ordering::Relaxed)
                || state.session.is_some_and(|stored| stored.id == session.id)
            {
                Err(CreateSessionError::AlreadyExists)
            } else {
                state.session = Some(session);
                Ok(())
            };

            std::future::ready(result)
        }

        #[inline(always)]
        fn revoke(&self, id: u128) -> impl Future<Output = Result<(), Self::Error>> + Send {
            if self.fail_revoke {
                return std::future::ready(Err(TestError("revoke")));
            }

            let mut state = self.state.lock().unwrap();

            if state.session.is_some_and(|session| session.id == id) {
                state.session = None;
            }

            std::future::ready(Ok(()))
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    #[test]
    fn parses_only_well_formed_session_cookies() {
        let mut request = http::Request::new(());

        assert_eq!(session_id(&request), None);

        request.headers_mut().append(
            http::header::COOKIE,
            "session_id=00000000000000000000000000000001"
                .parse()
                .unwrap(),
        );
        request.headers_mut().append(
            http::header::COOKIE,
            "first=value; session=0000000000000000000000000000002a; last=value"
                .parse()
                .unwrap(),
        );

        assert_eq!(session_id(&request), Some(42));

        request.headers_mut().clear();
        request.headers_mut().insert(
            http::header::COOKIE,
            "session=00000000000000000000000000002a".parse().unwrap(),
        );

        assert_eq!(session_id(&request), None);

        request
            .headers_mut()
            .insert(http::header::COOKIE, "session=invalid".parse().unwrap());

        assert_eq!(session_id(&request), None);
    }

    #[test]
    fn login_retries_collisions_and_logout_revokes() {
        runtime().block_on(async {
            let store = Sessions::default();
            store.collide_once.store(true, Ordering::Relaxed);
            let authentication = Authentication::new(Accounts::default(), store);

            let minimum_expiry = Utc::now() + Days::new(30);
            let session = authentication.login(Account { id: 7 }).await.unwrap();
            let maximum_expiry = Utc::now() + Days::new(30);
            let stored = authentication.store().stored().unwrap();

            assert_eq!(authentication.store().create_attempts(), 2);
            assert_eq!(stored.id, session.id());
            assert_eq!(stored.user_id, 7);
            assert_eq!(stored.expires, session.expires());
            assert!(session.expires() >= minimum_expiry);
            assert!(session.expires() <= maximum_expiry);

            authentication.logout(session).await.unwrap();
            assert!(authentication.store().stored().is_none());
        });
    }

    #[test]
    fn maps_backend_and_store_failures() {
        runtime().block_on(async {
            let backend = Accounts {
                fail_authenticate: true,
                ..Accounts::default()
            };
            let authentication = Authentication::new(backend, Sessions::default());

            assert!(matches!(
                authentication.authenticate(()).await,
                Err(AuthenticationError::Backend(TestError("authenticate"))),
            ));

            let store = Sessions {
                fail_create: true,
                ..Sessions::default()
            };
            let authentication = Authentication::new(Accounts::default(), store);

            assert!(matches!(
                authentication.login(Account { id: 7 }).await,
                Err(AuthenticationError::Store(TestError("create"))),
            ));

            let store = Sessions {
                fail_revoke: true,
                ..Sessions::default()
            };
            let authentication = Authentication::new(Accounts::default(), store);
            let session = crate::Session::new(42, Utc::now() + Days::new(1), Account { id: 7 });

            assert!(matches!(
                authentication.logout(session).await,
                Err(AuthenticationError::Store(TestError("revoke"))),
            ));
        });
    }

    #[test]
    fn backend_only_layer_inserts_noop_authentication() {
        runtime().block_on(async {
            let layer = ProvideAuthenticationLayer::new().with_backend(Accounts::default());
            let layer = layer.clone();
            let service = layer.layer(service_fn(|request: http::Request<()>| async move {
                Ok::<_, Infallible>(
                    request
                        .extensions()
                        .get::<Authentication<Accounts, crate::store::NoopStore<u64>>>()
                        .is_some(),
                )
            }));

            assert!(service.oneshot(http::Request::new(())).await.unwrap());
        });
    }

    async fn restored_session(
        backend: Accounts,
        store: Sessions,
        id: u128,
    ) -> (bool, Option<(u128, u64)>, Option<u128>) {
        let layer = ProvideAuthenticationLayer::new()
            .with_backend(backend)
            .with_store(store);

        let layer = layer.clone();
        let service = layer.layer(service_fn(|request: http::Request<()>| async move {
            let authentication = request
                .extensions()
                .get::<Authentication<Accounts, Sessions>>()
                .is_some();
            let session = request
                .extensions()
                .get::<crate::Session<Account>>()
                .map(|session| (session.id(), session.user().id()));

            #[cfg(feature = "session-local")]
            let local = crate::session::try_current::<Account>().map(|session| session.id());

            #[cfg(not(feature = "session-local"))]
            let local = None;

            Ok::<_, Infallible>((authentication, session, local))
        }));

        let request = http::Request::builder()
            .header(
                http::header::COOKIE,
                format!("session={}", const_hex::encode(id.to_be_bytes())),
            )
            .body(())
            .unwrap();

        service.oneshot(request).await.unwrap()
    }

    #[test]
    fn middleware_restores_valid_sessions() {
        runtime().block_on(async {
            let backend = Accounts::default();
            let calls = Arc::clone(&backend.get_calls);
            let store = Sessions::with_session(StoredSession {
                id: 42,
                expires: Utc::now() + Days::new(1),
                user_id: 7,
            });

            let restored = restored_session(backend, store, 42).await;

            assert!(restored.0);
            assert_eq!(restored.1, Some((42, 7)));
            assert_eq!(calls.load(Ordering::Relaxed), 1);

            #[cfg(feature = "session-local")]
            {
                assert_eq!(restored.2, Some(42));
                assert!(crate::session::try_current::<Account>().is_none());
            }
        });
    }

    #[test]
    fn middleware_treats_invalid_or_failed_lookups_as_anonymous() {
        runtime().block_on(async {
            let expired_backend = Accounts::default();
            let calls = Arc::clone(&expired_backend.get_calls);
            let expired = Sessions::with_session(StoredSession {
                id: 1,
                expires: Utc::now() - Days::new(1),
                user_id: 7,
            });

            assert_eq!(restored_session(expired_backend, expired, 1).await.1, None,);
            assert_eq!(calls.load(Ordering::Relaxed), 0);

            let failed_store = Sessions {
                fail_get: true,
                ..Sessions::default()
            };
            assert_eq!(
                restored_session(Accounts::default(), failed_store, 2)
                    .await
                    .1,
                None,
            );

            let failed_backend = Accounts {
                fail_get: true,
                ..Accounts::default()
            };
            let stored = Sessions::with_session(StoredSession {
                id: 3,
                expires: Utc::now() + Days::new(1),
                user_id: 7,
            });
            assert_eq!(restored_session(failed_backend, stored, 3).await.1, None,);

            let missing_backend = Accounts {
                missing: true,
                ..Accounts::default()
            };
            let stored = Sessions::with_session(StoredSession {
                id: 4,
                expires: Utc::now() + Days::new(1),
                user_id: 7,
            });
            assert_eq!(restored_session(missing_backend, stored, 4).await.1, None,);
        });
    }
}
