//! Moka-backed in-memory session store.

use std::{convert::Infallible, marker::PhantomData, task::Poll, time::Duration};

use chrono::Utc;
use moka::future::Cache;
use pin_project_lite::pin_project;
use tokio::task::JoinHandle;

use super::{CreateSessionError, Session, Store};

/// In-memory session store backed by a moka future cache.
///
/// Entries expire according to the session expiration timestamp. This store is
/// convenient for development, tests, or single-process deployments.
pub struct MemoryStore<User>(Cache<u128, Session<User::Id>>)
where
    User: crate::User;

impl<User> Default for MemoryStore<User>
where
    User: crate::User,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<User> MemoryStore<User>
where
    User: crate::User,
{
    /// Creates an empty memory store.
    #[inline]
    pub fn new() -> Self {
        Self(Cache::builder().expire_after(Expiry::<User>::new()).build())
    }
}

impl<User> Store for MemoryStore<User>
where
    User: crate::User,
{
    type Error = Infallible;

    type User = User;

    type Get = GetFuture<User>;

    type Create = CreateFuture;

    type Revoke = RevokeFuture;

    fn get(&self, id: u128) -> Self::Get {
        let cache = self.0.clone();

        GetFuture {
            task: tokio::spawn(async move { cache.get(&id).await }),
        }
    }

    fn create(&self, session: Session<<Self::User as crate::User>::Id>) -> Self::Create {
        let cache = self.0.clone();

        CreateFuture {
            task: tokio::spawn(async move {
                if cache.entry(session.id).or_insert(session).await.is_fresh() {
                    Ok(())
                } else {
                    Err(CreateSessionError::AlreadyExists)
                }
            }),
        }
    }

    fn revoke(&self, session: Session<<Self::User as crate::User>::Id>) -> Self::Revoke {
        let cache = self.0.clone();

        RevokeFuture {
            task: tokio::spawn(async move { cache.invalidate(&session.id).await }),
        }
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct GetFuture<User>
    where
        User: crate::User
    {
        #[pin] task: JoinHandle<Option<Session<User::Id>>>
    }
}

impl<User> Future for GetFuture<User>
where
    User: crate::User,
{
    type Output = Result<Option<Session<User::Id>>, Infallible>;

    #[inline]
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.project().task.poll(cx).map(|x| Ok(x.unwrap()))
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct CreateFuture {
        #[pin] task: JoinHandle<Result<(), CreateSessionError<Infallible>>>
    }
}

impl Future for CreateFuture {
    type Output = Result<(), CreateSessionError<Infallible>>;

    #[inline]
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.project().task.poll(cx).map(|x| x.unwrap())
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct RevokeFuture {
        #[pin] task: JoinHandle<()>
    }
}

impl Future for RevokeFuture {
    type Output = Result<(), Infallible>;

    #[inline]
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.project().task.poll(cx).map(|x| {
            let _: () = x.unwrap();
            Ok(())
        })
    }
}

struct Expiry<User>(PhantomData<User>);

impl<User> Expiry<User> {
    #[inline]
    const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<User> moka::Expiry<u128, Session<User::Id>> for Expiry<User>
where
    User: crate::User,
{
    fn expire_after_create(
        &self,
        _key: &u128,
        value: &Session<User::Id>,
        _created_at: std::time::Instant,
    ) -> Option<std::time::Duration> {
        Some(
            (value.expires - Utc::now())
                .to_std()
                .unwrap_or(Duration::ZERO),
        )
    }
}
