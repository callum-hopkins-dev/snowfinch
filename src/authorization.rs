//! Authorization middleware and extension traits.

use std::{marker::PhantomData, sync::Arc, task::Poll};

use pin_project_lite::pin_project;
use tower::{Layer, Service, ServiceBuilder, layer::util::Stack};

use crate::{Scope, Session, User};

/// A predicate that decides whether a user may access a service.
///
/// Implement this trait to plug custom authorization logic into
/// [`RequireAuthorizationLayer`].
pub trait Authorize: Send + Sync + 'static {
    /// The user type inspected by this authorizer.
    type User: User;

    /// Returns `true` when `user` is authorized.
    fn authorize(&self, user: &Self::User) -> bool;
}

/// A Tower layer that rejects requests without an authorized session.
pub struct RequireAuthorizationLayer<A>(Arc<A>);

impl<A> RequireAuthorizationLayer<A>
where
    A: Authorize,
{
    /// Creates a new authorization layer from an authorizer.
    #[inline]
    pub fn new(authorize: A) -> Self {
        Self(Arc::new(authorize))
    }
}

impl<A> Clone for RequireAuthorizationLayer<A> {
    #[inline]
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<S, A> Layer<S> for RequireAuthorizationLayer<A>
where
    A: Authorize,
{
    type Service = RequireAuthorization<S, A>;

    #[inline]
    fn layer(&self, inner: S) -> Self::Service {
        RequireAuthorization {
            inner,
            authorize: Arc::clone(&self.0),
        }
    }
}

/// Service produced by [`RequireAuthorizationLayer`].
pub struct RequireAuthorization<S, A> {
    inner: S,
    authorize: Arc<A>,
}

impl<S, A> Clone for RequireAuthorization<S, A>
where
    S: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            authorize: Arc::clone(&self.authorize),
        }
    }
}

impl<Body, S, A> Service<http::Request<Body>> for RequireAuthorization<S, A>
where
    S: Service<http::Request<Body>> + Send + Clone + 'static,
    A: Authorize,
{
    type Response = RequireAuthorizationResponse<S::Response>;

    type Error = S::Error;

    type Future = RequireAuthorizationFuture<S::Future>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        RequireAuthorizationFuture {
            inner: match req.extensions().get::<Session<A::User>>() {
                Some(session) if self.authorize.authorize(session.user()) => {
                    RequireAuthorizationFutureInner::Authorized {
                        future: self.inner.call(req),
                    }
                }

                _ => RequireAuthorizationFutureInner::NotAuthorized,
            },
        }
    }
}

/// Response wrapper returned by [`RequireAuthorization`].
///
/// With the `axum` feature enabled, `NotAuthorized` converts to `401
/// Unauthorized`, while `Authorized` delegates to the inner response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RequireAuthorizationResponse<R> {
    /// The request did not contain an authorized session.
    NotAuthorized,

    /// The inner service accepted the authorized request.
    Authorized(R),
}

#[cfg(feature = "axum")]
impl<R> axum::response::IntoResponse for RequireAuthorizationResponse<R>
where
    R: axum::response::IntoResponse,
{
    #[inline]
    fn into_response(self) -> axum::response::Response {
        match self {
            RequireAuthorizationResponse::NotAuthorized => {
                http::StatusCode::UNAUTHORIZED.into_response()
            }

            RequireAuthorizationResponse::Authorized(x) => x.into_response(),
        }
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct RequireAuthorizationFuture<F> {
        #[pin] inner: RequireAuthorizationFutureInner<F>,
    }
}

pin_project! {
    #[project = RequireAuthorizationFutureProj]
    enum RequireAuthorizationFutureInner<F> {
        NotAuthorized,

        Authorized {
            #[pin] future: F,
        },
    }
}

impl<F, T, E> Future for RequireAuthorizationFuture<F>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<RequireAuthorizationResponse<T>, E>;

    #[inline]
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match self.project().inner.project() {
            RequireAuthorizationFutureProj::NotAuthorized => {
                Poll::Ready(Ok(RequireAuthorizationResponse::NotAuthorized))
            }

            RequireAuthorizationFutureProj::Authorized { future } => future
                .poll(cx)
                .map_ok(|x| RequireAuthorizationResponse::Authorized(x)),
        }
    }
}

/// An [`Authorize`] implementation backed by a closure.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizeFn<User, F>(F, PhantomData<User>)
where
    User: crate::User;

impl<User, F> AuthorizeFn<User, F>
where
    User: crate::User,
    F: Fn(&User) -> bool,
{
    /// Wraps a closure as an authorizer.
    #[inline]
    pub const fn new(f: F) -> Self {
        Self(f, PhantomData)
    }
}

impl<User, F> Authorize for AuthorizeFn<User, F>
where
    User: crate::User,
    F: Fn(&User) -> bool + Send + Sync + 'static,
{
    type User = User;

    #[inline]
    fn authorize(&self, user: &Self::User) -> bool {
        (self.0)(user)
    }
}

/// Authorizer that allows any authenticated user.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequireAuthenticated<User>(PhantomData<User>)
where
    User: crate::User;

impl<User> RequireAuthenticated<User>
where
    User: crate::User,
{
    /// Creates an authorizer that requires only an authenticated session.
    #[inline]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<User> Authorize for RequireAuthenticated<User>
where
    User: crate::User,
{
    type User = User;

    #[inline]
    fn authorize(&self, _user: &Self::User) -> bool {
        true
    }
}

/// Authorizer that requires the current user to contain a scope.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequireScope<User>(User::Scope)
where
    User: crate::User;

impl<User> RequireScope<User>
where
    User: crate::User,
{
    /// Creates an authorizer requiring `scope`.
    #[inline]
    pub const fn new(scope: User::Scope) -> Self {
        Self(scope)
    }
}

impl<User> Authorize for RequireScope<User>
where
    User: crate::User,
{
    type User = User;

    #[inline]
    fn authorize(&self, user: &Self::User) -> bool {
        user.scope().contains(&self.0)
    }
}

/// Extension methods for [`tower::ServiceBuilder`].
pub trait ServiceBuilderExt<L> {
    /// Adds a custom authorization layer to the service builder.
    fn require_authorization<A>(
        self,
        authorize: A,
    ) -> ServiceBuilder<Stack<RequireAuthorizationLayer<A>, L>>
    where
        A: Authorize;

    /// Adds an authorization layer backed by a closure.
    #[inline]
    fn require_authorization_fn<User, F>(
        self,
        f: F,
    ) -> ServiceBuilder<Stack<RequireAuthorizationLayer<AuthorizeFn<User, F>>, L>>
    where
        User: crate::User,
        F: Fn(&User) -> bool + Send + Sync + 'static,
        Self: Sized,
    {
        self.require_authorization(AuthorizeFn::new(f))
    }

    /// Requires requests to include an authenticated session.
    #[inline]
    fn require_authenticated<User>(
        self,
    ) -> ServiceBuilder<Stack<RequireAuthorizationLayer<RequireAuthenticated<User>>, L>>
    where
        User: crate::User,
        Self: Sized,
    {
        self.require_authorization(RequireAuthenticated::<User>::new())
    }

    /// Requires the authenticated user to contain `scope`.
    #[inline]
    fn require_scope<User>(
        self,
        scope: User::Scope,
    ) -> ServiceBuilder<Stack<RequireAuthorizationLayer<RequireScope<User>>, L>>
    where
        User: crate::User,
        Self: Sized,
    {
        self.require_authorization(RequireScope::new(scope))
    }
}

impl<L> ServiceBuilderExt<L> for ServiceBuilder<L> {
    #[inline]
    fn require_authorization<A>(
        self,
        authorize: A,
    ) -> ServiceBuilder<Stack<RequireAuthorizationLayer<A>, L>>
    where
        A: Authorize,
    {
        self.layer(RequireAuthorizationLayer::new(authorize))
    }
}

/// Extension methods for `axum::Router`.
pub trait RouterExt {
    /// Adds a custom authorization layer to every route in the router.
    fn require_authorization<A>(self, authorize: A) -> Self
    where
        A: Authorize;

    /// Adds a closure-backed authorization layer to every route in the router.
    #[inline]
    fn require_authorization_fn<User, F>(self, f: F) -> Self
    where
        User: crate::User,
        F: Fn(&User) -> bool + Send + Sync + 'static,
        Self: Sized,
    {
        self.require_authorization(AuthorizeFn::new(f))
    }

    /// Requires every route in the router to have an authenticated session.
    #[inline]
    fn require_authenticated<User>(self) -> Self
    where
        User: crate::User,
        Self: Sized,
    {
        self.require_authorization(RequireAuthenticated::<User>::new())
    }

    /// Requires every route in the router to contain `scope`.
    #[inline]
    fn require_scope<User>(self, scope: User::Scope) -> Self
    where
        User: crate::User,
        Self: Sized,
    {
        self.require_authorization(RequireScope::<User>::new(scope))
    }
}

#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<S> RouterExt for axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    #[inline]
    fn require_authorization<A>(self, authorize: A) -> Self
    where
        A: Authorize,
    {
        self.layer(RequireAuthorizationLayer::new(authorize))
    }
}

/// Extension methods for `axum::routing::MethodRouter`.
pub trait MethodRouterExt {
    /// Adds a custom authorization layer to this method router.
    fn require_authorization<A>(self, authorize: A) -> Self
    where
        A: Authorize;

    /// Adds a closure-backed authorization layer to this method router.
    #[inline]
    fn require_authorization_fn<User, F>(self, f: F) -> Self
    where
        User: crate::User,
        F: Fn(&User) -> bool + Send + Sync + 'static,
        Self: Sized,
    {
        self.require_authorization(AuthorizeFn::new(f))
    }

    /// Requires this method router to have an authenticated session.
    #[inline]
    fn require_authenticated<User>(self) -> Self
    where
        User: crate::User,
        Self: Sized,
    {
        self.require_authorization(RequireAuthenticated::<User>::new())
    }

    /// Requires this method router to contain `scope`.
    #[inline]
    fn require_scope<User>(self, scope: User::Scope) -> Self
    where
        User: crate::User,
        Self: Sized,
    {
        self.require_authorization(RequireScope::<User>::new(scope))
    }
}

#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<S> MethodRouterExt for axum::routing::MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    #[inline]
    fn require_authorization<A>(self, authorize: A) -> Self
    where
        A: Authorize,
    {
        self.layer(RequireAuthorizationLayer::new(authorize))
    }
}
