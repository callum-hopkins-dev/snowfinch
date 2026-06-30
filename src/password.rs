//! Password hashing and verification helpers.

use sha2::{Digest, Sha256};

/// A salted SHA-256 password hash.
///
/// `Password` stores a 32-byte SHA-256 hash followed by the 32-byte salt used to
/// produce it. Equality between two [`Password`] values, and comparisons against
/// plaintext byte strings or strings, use constant-time comparison for the final
/// stored value.
///
/// New passwords should usually be created with [`Password::new`], which
/// generates a random salt. Use [`Password::with_salt`] when you need
/// deterministic hashing, for example in tests.
#[derive(Clone, Copy, Eq, Hash)]
#[repr(transparent)]
#[allow(clippy::derived_hash_with_manual_eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Password(#[cfg_attr(feature = "serde", serde(with = "const_hex::serde"))] [u8; 64]);

impl std::fmt::Debug for Password {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Password")
            .field(&const_hex::Buffer::<_, true>::new().const_format(self.as_bytes()))
            .finish()
    }
}

impl Password {
    /// Hashes a plaintext password with a random salt.
    #[inline]
    pub fn new(bytes: &[u8]) -> Self {
        Self::with_salt(bytes, rand::random())
    }

    /// Hashes a plaintext password with the provided salt.
    ///
    /// This is useful when recreating the hash for verification or producing
    /// deterministic values in tests.
    #[inline]
    pub fn with_salt(bytes: &[u8], salt: [u8; 32]) -> Self {
        let mut sha256 = Sha256::new();

        sha256.update(salt);
        sha256.update(bytes);

        Self::from_raw_parts(sha256.finalize().into(), salt)
    }

    /// Builds a password from a hash and salt.
    #[inline]
    pub const fn from_raw_parts(hash: [u8; 32], salt: [u8; 32]) -> Self {
        let mut bytes = [0u8; 64];

        *bytes.first_chunk_mut().unwrap() = hash;
        *bytes.last_chunk_mut().unwrap() = salt;

        Self(bytes)
    }

    /// Returns the stored 32-byte hash.
    #[inline]
    pub const fn hash(&self) -> [u8; 32] {
        *self.0.first_chunk().unwrap()
    }

    /// Returns the 32-byte salt used to create the hash.
    #[inline]
    pub const fn salt(&self) -> [u8; 32] {
        *self.0.last_chunk().unwrap()
    }

    /// Returns the raw 64-byte `hash || salt` representation.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Converts this value into its raw 64-byte `hash || salt` representation.
    #[inline]
    pub const fn to_bytes(self) -> [u8; 64] {
        self.0
    }

    /// Builds a password from the raw 64-byte `hash || salt` representation.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl PartialEq for Password {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq::constant_time_eq_64(self.as_bytes(), other.as_bytes())
    }
}

impl PartialEq<[u8]> for Password {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self == &Password::with_salt(other, self.salt())
    }
}

impl PartialEq<str> for Password {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self == other.as_bytes()
    }
}

impl PartialEq<&str> for Password {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self == other.as_bytes()
    }
}

impl PartialEq<Box<str>> for Password {
    #[inline]
    fn eq(&self, other: &Box<str>) -> bool {
        self == other.as_bytes()
    }
}

impl PartialEq<String> for Password {
    #[inline]
    fn eq(&self, other: &String) -> bool {
        self == other.as_bytes()
    }
}

#[cfg(feature = "sqlx")]
impl<D> sqlx::Type<D> for Password
where
    D: sqlx::Database,
    String: sqlx::Type<D>,
{
    #[inline]
    fn type_info() -> <D as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<D>>::type_info()
    }
}

#[cfg(feature = "sqlx")]
impl<'q, D> sqlx::Encode<'q, D> for Password
where
    D: sqlx::Database,
    String: sqlx::Encode<'q, D>,
{
    fn encode_by_ref(
        &self,
        buf: &mut <D as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        const_hex::Buffer::<_, true>::new()
            .const_format(self.as_bytes())
            .as_str()
            .to_owned()
            .encode(buf)
    }
}

#[cfg(feature = "sqlx")]
impl<'r, D> sqlx::Decode<'r, D> for Password
where
    D: sqlx::Database,
    String: sqlx::Decode<'r, D>,
{
    fn decode(
        value: <D as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        String::decode(value)
            .and_then(|x| const_hex::decode_to_array(x).map_err(|x| Box::new(x).into()))
            .map(Self::from_bytes)
    }
}
