//! Password hashing and verification helpers.

use sha2::{Digest, Sha256};

/// A salted SHA-256 password hash packed into 64 bytes.
///
/// The first 32 bytes contain the hash and the final 32 bytes contain the salt.
/// Equality between password values, and comparisons with plaintext values, use
/// constant-time comparison for the packed representation.
#[derive(Clone, Copy, Eq, Hash)]
#[repr(transparent)]
#[allow(clippy::derived_hash_with_manual_eq)]
pub struct Password([u8; 64]);

impl std::fmt::Debug for Password {
    #[inline(always)]
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("Password")
            .field(&const_hex::Buffer::<_, true>::new().const_format(self.as_bytes()))
            .finish()
    }
}

impl Password {
    /// Hashes a plaintext password with a random 32-byte salt.
    #[inline(always)]
    pub fn new(bytes: &[u8]) -> Self {
        Self::with_salt(bytes, rand::random())
    }

    /// Hashes a plaintext password with a provided 32-byte salt.
    #[inline(always)]
    pub fn with_salt(bytes: &[u8], salt: [u8; 32]) -> Self {
        let mut sha256 = Sha256::new();

        sha256.update(salt);
        sha256.update(bytes);

        Self::from_raw_parts(sha256.finalize().into(), salt)
    }

    /// Builds a password from its hash and salt.
    #[inline(always)]
    pub const fn from_raw_parts(hash: [u8; 32], salt: [u8; 32]) -> Self {
        let mut bytes = [0u8; 64];

        *bytes.first_chunk_mut().unwrap() = hash;
        *bytes.last_chunk_mut().unwrap() = salt;

        Self(bytes)
    }

    /// Returns the stored 32-byte hash.
    #[inline(always)]
    pub const fn hash(&self) -> [u8; 32] {
        *self.0.first_chunk().unwrap()
    }

    /// Returns the 32-byte salt.
    #[inline(always)]
    pub const fn salt(&self) -> [u8; 32] {
        *self.0.last_chunk().unwrap()
    }

    /// Returns the packed 64-byte hash followed by salt representation.
    #[inline(always)]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Converts this value into its packed 64-byte representation.
    #[inline(always)]
    pub const fn to_bytes(self) -> [u8; 64] {
        self.0
    }

    /// Builds a password from its packed 64-byte representation.
    #[inline(always)]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl PartialEq for Password {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq::constant_time_eq_64(self.as_bytes(), other.as_bytes())
    }
}

impl PartialEq<[u8]> for Password {
    #[inline(always)]
    fn eq(&self, other: &[u8]) -> bool {
        self == &Self::with_salt(other, self.salt())
    }
}

impl PartialEq<str> for Password {
    #[inline(always)]
    fn eq(&self, other: &str) -> bool {
        self == other.as_bytes()
    }
}

impl PartialEq<&str> for Password {
    #[inline(always)]
    fn eq(&self, other: &&str) -> bool {
        self == other.as_bytes()
    }
}

impl PartialEq<Box<str>> for Password {
    #[inline(always)]
    fn eq(&self, other: &Box<str>) -> bool {
        self == other.as_bytes()
    }
}

impl PartialEq<String> for Password {
    #[inline(always)]
    fn eq(&self, other: &String) -> bool {
        self == other.as_bytes()
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl serde::Serialize for Password {
    #[inline(always)]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        <str as serde::Serialize>::serialize(
            const_hex::Buffer::<_, true>::new()
                .const_format(self.as_bytes())
                .as_str(),
            serializer,
        )
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for Password {
    #[inline(always)]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <String as serde::Deserialize>::deserialize(deserializer).and_then(|value| {
            const_hex::decode_to_array(value)
                .map(Self::from_bytes)
                .map_err(<D::Error as serde::de::Error>::custom)
        })
    }
}

#[cfg(feature = "sqlx")]
#[cfg_attr(docsrs, doc(cfg(feature = "sqlx")))]
impl<D> sqlx::Type<D> for Password
where
    D: sqlx::Database,
    Vec<u8>: sqlx::Type<D>,
{
    #[inline(always)]
    fn type_info() -> D::TypeInfo {
        <Vec<u8> as sqlx::Type<D>>::type_info()
    }

    #[inline(always)]
    fn compatible(ty: &D::TypeInfo) -> bool {
        <Vec<u8> as sqlx::Type<D>>::compatible(ty)
    }
}

#[cfg(feature = "sqlx")]
#[cfg_attr(docsrs, doc(cfg(feature = "sqlx")))]
impl<'q, D> sqlx::Encode<'q, D> for Password
where
    D: sqlx::Database,
    Vec<u8>: sqlx::Encode<'q, D>,
{
    #[inline(always)]
    fn encode_by_ref(
        &self,
        buffer: &mut D::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <Vec<u8> as sqlx::Encode<'q, D>>::encode(self.as_bytes().to_vec(), buffer)
    }

    #[inline(always)]
    fn size_hint(&self) -> usize {
        self.as_bytes().len()
    }
}

#[cfg(feature = "sqlx")]
#[cfg_attr(docsrs, doc(cfg(feature = "sqlx")))]
impl<'r, D> sqlx::Decode<'r, D> for Password
where
    D: sqlx::Database,
    Vec<u8>: sqlx::Decode<'r, D>,
{
    #[inline(always)]
    fn decode(value: D::ValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        <Vec<u8> as sqlx::Decode<'r, D>>::decode(value).and_then(|bytes| {
            bytes
                .try_into()
                .map(Self::from_bytes)
                .map_err(|_| -> sqlx::error::BoxDynError {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "expected a 64-byte password BLOB",
                    )
                    .into()
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Password;

    #[test]
    fn representation_is_exactly_64_bytes() {
        assert_eq!(std::mem::size_of::<Password>(), 64);
        assert_eq!(std::mem::align_of::<Password>(), 1);

        let password = Password::from_raw_parts([1; 32], [2; 32]);

        assert_eq!(password.hash(), [1; 32]);
        assert_eq!(password.salt(), [2; 32]);
        assert_eq!(&password.as_bytes()[..32], &[1; 32]);
        assert_eq!(&password.as_bytes()[32..], &[2; 32]);
        assert_eq!(Password::from_bytes(password.to_bytes()), password);
    }

    #[test]
    fn hashes_and_compares_plaintext() {
        let password = Password::with_salt(b"correct horse", [7; 32]);
        let owned = "correct horse".to_owned();
        let boxed = Box::<str>::from("correct horse");

        assert_eq!(password, Password::with_salt(b"correct horse", [7; 32]),);
        assert_ne!(password, Password::with_salt(b"wrong", [7; 32]));
        assert!(password == "correct horse");
        assert!(password != "wrong");
        assert!(password == owned);
        assert!(password == boxed);
        assert!(password.eq(b"correct horse".as_slice()));
    }

    #[test]
    fn random_passwords_use_distinct_salts_and_verify() {
        let password = Password::new(b"secret");
        let other = Password::new(b"secret");

        assert!(password == "secret");
        assert!(password != "not secret");
        assert!(other == "secret");
        assert_ne!(password.salt(), other.salt());
        assert_ne!(password, other);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_traits_are_available() {
        fn assert_serde<T>()
        where
            T: serde::Serialize + serde::de::DeserializeOwned,
        {
        }

        assert_serde::<Password>();
    }
}
