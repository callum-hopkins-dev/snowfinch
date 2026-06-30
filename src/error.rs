/// Errors returned by [`snowfinch`](crate).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A hexadecimal value could not be decoded.
    #[error(transparent)]
    FromHex(#[from] const_hex::FromHexError),

    /// An error returned by a user-provided backend or store.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}
