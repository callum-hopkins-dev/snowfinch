//! Authenticated session values and optional session-local access.

use std::sync::Arc;

use chrono::{DateTime, Utc};

/// An authenticated session for a user.
///
/// Cloning a session is inexpensive because the user is shared through an
/// [Arc].
#[derive(Debug)]
pub struct Session<User> {
    id: u128,
    expires: DateTime<Utc>,
    user: Arc<User>,
}

impl<User> Session<User> {
    #[allow(dead_code)]
    #[inline(always)]
    pub(crate) fn new(id: u128, expires: DateTime<Utc>, user: User) -> Self {
        Self {
            id,
            expires,
            user: Arc::new(user),
        }
    }

    /// Returns the opaque session identifier.
    #[inline(always)]
    pub const fn id(&self) -> u128 {
        self.id
    }

    /// Returns the instant at which this session expires.
    #[inline(always)]
    pub const fn expires(&self) -> DateTime<Utc> {
        self.expires
    }

    /// Returns the authenticated user associated with this session.
    #[inline(always)]
    pub fn user(&self) -> &User {
        &self.user
    }
}

impl<User> Session<User>
where
    User: crate::User,
{
    /// Returns the permissions granted to the authenticated user.
    #[inline(always)]
    pub fn scope(&self) -> User::Scope {
        <User as crate::User>::scope(&self.user)
    }
}

impl<User> Clone for Session<User> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            expires: self.expires,
            user: Arc::clone(&self.user),
        }
    }
}

impl<User> PartialEq for Session<User> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.expires == other.expires && Arc::ptr_eq(&self.user, &other.user)
    }
}

impl<User> Eq for Session<User> {}

#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<State, User> axum::extract::FromRequestParts<State> for Session<User>
where
    State: Send + Sync,
    User: Send + Sync + 'static,
{
    type Rejection = http::StatusCode;

    #[inline(always)]
    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &State,
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
impl<State, User> axum::extract::OptionalFromRequestParts<State> for Session<User>
where
    State: Send + Sync,
    User: Send + Sync + 'static,
{
    type Rejection = std::convert::Infallible;

    #[inline(always)]
    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &State,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned())
    }
}

#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
impl<User> axum::response::IntoResponseParts for Session<User> {
    type Error = std::convert::Infallible;

    #[inline(always)]
    fn into_response_parts(
        self,
        mut response: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        response.headers_mut().insert(
            http::header::SET_COOKIE,
            http::HeaderValue::from_maybe_shared(format!(
                "session={}; expires={}; httponly; samesite=strict; path=/; secure",
                const_hex::Buffer::<_, false>::new().format(&self.id().to_be_bytes()),
                self.expires().to_rfc2822(),
            ))
            .expect("a generated session cookie is always a valid header value"),
        );

        Ok(response)
    }
}

#[cfg(feature = "session-local")]
#[cfg_attr(docsrs, doc(cfg(feature = "session-local")))]
/// Runs a future with an initialized session-local context.
///
/// Authentication middleware uses this to isolate the current session for each
/// request. Custom integrations can use it when they need [current] and
/// [try_current] outside that middleware.
#[inline(always)]
pub async fn with_session_local<Future>(future: Future) -> Future::Output
where
    Future: std::future::Future,
{
    session_local::scope(future).await
}

/// Returns the current session from the session-local context, if one is available.
#[cfg(feature = "session-local")]
#[cfg_attr(docsrs, doc(cfg(feature = "session-local")))]
#[inline(always)]
pub fn try_current<User>() -> Option<Session<User>>
where
    User: Send + Sync + 'static,
{
    session_local::try_current()
}

/// Returns the current session from the session-local context.
///
/// # Panics
///
/// Panics when called outside a session-local context or when the context
/// does not contain a session for User.
#[cfg(feature = "session-local")]
#[cfg_attr(docsrs, doc(cfg(feature = "session-local")))]
#[inline(always)]
pub fn current<User>() -> Session<User>
where
    User: Send + Sync + 'static,
{
    try_current().expect("no current session is available for this user type")
}

#[inline(always)]
#[allow(dead_code)]
pub(crate) fn insert<User>(session: &Session<User>)
where
    User: Send + Sync + 'static,
{
    #[cfg(feature = "session-local")]
    session_local::insert(session);

    #[cfg(not(feature = "session-local"))]
    let _ = session;
}

#[inline(always)]
#[allow(dead_code)]
pub(crate) fn remove<User>()
where
    User: Send + Sync + 'static,
{
    #[cfg(feature = "session-local")]
    session_local::remove::<User>();
}

#[cfg(feature = "session-local")]
#[allow(dead_code)]
mod session_local {
    use std::{
        any::{Any, TypeId},
        cell::RefCell,
        collections::HashMap,
    };

    use super::Session;

    type Sessions = RefCell<HashMap<TypeId, Box<dyn Any + Send + Sync>>>;

    tokio::task_local! {
        static SESSIONS: Sessions;
    }

    #[inline(always)]
    pub async fn scope<Future>(future: Future) -> Future::Output
    where
        Future: std::future::Future,
    {
        SESSIONS.scope(RefCell::new(HashMap::new()), future).await
    }

    #[inline(always)]
    pub fn insert<User>(session: &Session<User>)
    where
        User: Send + Sync + 'static,
    {
        let _ = SESSIONS.try_with(|sessions| {
            sessions
                .borrow_mut()
                .insert(TypeId::of::<User>(), Box::new(session.clone()));
        });
    }

    #[inline(always)]
    pub fn remove<User>()
    where
        User: Send + Sync + 'static,
    {
        let _ = SESSIONS.try_with(|sessions| {
            sessions.borrow_mut().remove(&TypeId::of::<User>());
        });
    }

    #[inline(always)]
    pub fn try_current<User>() -> Option<Session<User>>
    where
        User: Send + Sync + 'static,
    {
        SESSIONS
            .try_with(|sessions| {
                sessions
                    .borrow()
                    .get(&TypeId::of::<User>())
                    .and_then(|session| session.downcast_ref::<Session<User>>())
                    .cloned()
            })
            .ok()
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::Session;

    #[derive(Debug)]
    struct User {
        id: u64,
    }

    #[test]
    fn exposes_session_values_and_clones_cheaply() {
        let expires = Utc.with_ymd_and_hms(2030, 1, 2, 3, 4, 5).unwrap();
        let session = Session::new(42, expires, User { id: 7 });
        let clone = session.clone();

        assert_eq!(session.id(), 42);
        assert_eq!(session.expires(), expires);
        assert_eq!(session.user().id, 7);
        assert_eq!(session, clone);
    }

    #[test]
    #[cfg(feature = "session-local")]
    fn session_local_context_is_initialized_and_isolated() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        runtime.block_on(super::with_session_local(async {
            assert!(super::try_current::<User>().is_none());

            let expires = Utc.with_ymd_and_hms(2030, 1, 2, 3, 4, 5).unwrap();
            let session = Session::new(42, expires, User { id: 7 });
            super::insert(&session);

            assert_eq!(super::current::<User>(), session);

            super::with_session_local(async {
                assert!(super::try_current::<User>().is_none());
            })
            .await;

            assert_eq!(super::current::<User>(), session);
            super::remove::<User>();
            assert!(super::try_current::<User>().is_none());
        }));

        assert!(super::try_current::<User>().is_none());
    }
}
