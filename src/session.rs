//! Authenticated session values.

use std::sync::Arc;

use chrono::{DateTime, Utc};

/// An authenticated session for a user.
///
/// Sessions are created by [`Authentication::login`](crate::Authentication::login),
/// inserted into request extensions by the authentication middleware, and can be
/// extracted by Axum handlers when the `axum` feature is enabled.
#[derive(Debug)]
pub struct Session<User> {
    id: u128,
    expires: DateTime<Utc>,
    user: Arc<User>,
}

impl<User> Clone for Session<User> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            expires: self.expires,
            user: self.user.clone(),
        }
    }
}

impl<User> Session<User> {
    /// Returns the opaque session id.
    #[inline]
    pub const fn id(&self) -> u128 {
        self.id
    }

    /// Returns the instant at which this session expires.
    #[inline]
    pub const fn expires(&self) -> DateTime<Utc> {
        self.expires
    }

    /// Returns the authenticated user associated with this session.
    #[inline]
    pub fn user(&self) -> &User {
        &self.user
    }

    /// Returns the authenticated user's scope.
    #[inline]
    pub fn scope(&self) -> User::Scope
    where
        User: crate::User,
    {
        self.user().scope()
    }
}

impl<User> Session<User>
where
    User: Send + 'static,
{
    #[inline]
    pub(crate) fn new(id: u128, expires: DateTime<Utc>, user: User) -> Self {
        Self {
            id,
            expires,
            user: Arc::new(user),
        }
    }
}

impl<User> PartialEq for Session<User> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.expires == other.expires && Arc::ptr_eq(&self.user, &other.user)
    }
}

impl<User> Eq for Session<User> {}

#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<S, User> axum::extract::FromRequestParts<S> for Session<User>
where
    User: crate::User,
    S: Send + Sync,
{
    type Rejection = http::StatusCode;

    #[inline]
    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(http::StatusCode::UNAUTHORIZED)
    }
}

#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<S, User> axum::extract::OptionalFromRequestParts<S> for Session<User>
where
    User: crate::User,
    S: Send + Sync,
{
    type Rejection = ::core::convert::Infallible;

    #[inline]
    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned())
    }
}

#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<User> axum::response::IntoResponseParts for Session<User> {
    type Error = ::core::convert::Infallible;

    #[inline]
    fn into_response_parts(
        self,
        mut res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        res.headers_mut().insert(
            http::header::SET_COOKIE,
            http::HeaderValue::from_maybe_shared(format!(
                "session={}; expires={}; httponly; samesite=strict; path=/; secure",
                const_hex::Buffer::<_, false>::new().format(&self.id().to_be_bytes()),
                self.expires().to_rfc2822(),
            ))
            .unwrap(),
        );

        Ok(res)
    }
}

#[cfg(feature = "session-local")]
#[inline]
pub(crate) fn insert<User>(session: &Session<User>)
where
    User: crate::User,
{
    session_local::insert(session);
}

#[cfg(not(feature = "session-local"))]
#[inline]
pub(crate) fn insert<User>(_session: &Session<User>)
where
    User: crate::User,
{
}

#[inline]
pub(crate) fn remove<User>()
where
    User: crate::User,
{
    #[cfg(feature = "session-local")]
    session_local::remove::<User>();
}

/// Returns the task-local current session, if one has been inserted.
///
/// This is available only with the `session-local` feature.
#[cfg(feature = "session-local")]
#[cfg_attr(docsrs, doc(cfg(feature = "session-local")))]
#[inline]
pub fn try_current<User>() -> Option<Session<User>>
where
    User: crate::User,
{
    session_local::try_current()
}

/// Returns the task-local current session.
///
/// # Panics
///
/// Panics if no current session is available. Prefer [`try_current`] when the
/// absence of a session is expected.
#[cfg(feature = "session-local")]
#[cfg_attr(docsrs, doc(cfg(feature = "session-local")))]
#[inline]
pub fn current<User>() -> Session<User>
where
    User: crate::User,
{
    session_local::try_current().unwrap()
}

#[cfg(feature = "session-local")]
mod session_local {
    use std::{
        any::{Any, TypeId},
        cell::RefCell,
        collections::HashMap,
        sync::Arc,
    };

    use chrono::{DateTime, Utc};

    use super::Session;

    tokio::task_local! {
        static CONTEXT: RefCell<HashMap<TypeId, ErasedSession>>;
    }

    #[derive(Clone)]
    struct ErasedSession {
        id: u128,
        expires: DateTime<Utc>,
        user: Arc<dyn Any + Send + Sync>,
    }

    pub fn insert<User>(session: &Session<User>)
    where
        User: crate::User,
    {
        let _ = CONTEXT.try_with(|context| {
            let user = Arc::clone(&session.user);

            context.borrow_mut().insert(
                TypeId::of::<User>(),
                ErasedSession {
                    id: session.id,
                    expires: session.expires,
                    user,
                },
            );
        });
    }

    pub fn remove<User>()
    where
        User: crate::User,
    {
        let _ = CONTEXT.try_with(|context| {
            context.borrow_mut().remove(&TypeId::of::<User>());
        });
    }

    pub fn try_current<User>() -> Option<Session<User>>
    where
        User: crate::User,
    {
        CONTEXT
            .try_with(|context| context.borrow().get(&TypeId::of::<User>()).cloned())
            .ok()
            .flatten()
            .map(|x| Session {
                id: x.id,
                expires: x.expires,
                user: x.user.downcast().unwrap(),
            })
    }
}
