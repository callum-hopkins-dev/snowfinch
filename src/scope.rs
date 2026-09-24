//! Compact, bitmap-backed permission scopes.

use std::{
    iter::FusedIterator,
    ops::{BitAnd, BitOr, BitXor, Not},
};

/// Error returned when a hexadecimal scope value cannot be decoded.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ParseScopeError(#[from] const_hex::FromHexError);

/// A bitmap-backed set of up to 64 permissions.
///
/// Scope types are normally generated with [scope!](crate::scope!).
pub trait Scope:
    Copy
    + PartialEq
    + Eq
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + Not<Output = Self>
    + Sized
    + Send
    + Sync
    + 'static
{
    /// Number of bits in the underlying representation.
    const BITS: u32 = u64::BITS;

    /// The empty scope containing no flags.
    const EMPTY: Self;

    /// A scope containing every bit used by a declared scope.
    const ALL: Self;

    /// Metadata for every declared flag and compound scope.
    const FLAGS: &'static [Flag<Self>];

    /// Looks up a declared flag or compound scope by name.
    fn from_name(name: &str) -> Option<Self>;

    /// Returns true when no flags are set.
    fn is_empty(&self) -> bool;

    /// Returns true when all primitive flags are set.
    fn is_all(&self) -> bool;

    /// Returns true when the scopes have at least one flag in common.
    fn intersects(&self, other: &Self) -> bool;

    /// Returns true when this scope contains every flag in other.
    fn contains(&self, other: &Self) -> bool;

    /// Returns the flags present in both scopes.
    fn intersection(self, other: Self) -> Self;

    /// Returns the flags present in either scope.
    fn union(self, other: Self) -> Self;

    /// Returns the flags present in this scope but not in other.
    fn difference(self, other: Self) -> Self;

    /// Returns the flags present in exactly one of the two scopes.
    fn symmetric_difference(self, other: Self) -> Self;

    /// Iterates over the names contained in this scope.
    fn names(&self) -> Names<Self>;

    /// Iterates over the values contained in this scope.
    fn values(&self) -> Values<Self>;
}

/// Metadata for a declared scope flag or compound scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Flag<T> {
    name: &'static str,
    value: T,
}

impl<T> Flag<T> {
    /// Creates flag metadata from a name and value.
    #[inline(always)]
    pub const fn new(name: &'static str, value: T) -> Self {
        Self { name, value }
    }

    /// Returns the declared name of the flag or compound scope.
    #[inline(always)]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the scope value represented by this flag or compound scope.
    #[inline(always)]
    pub const fn value(&self) -> &T {
        &self.value
    }
}

/// Iterator over the names contained in a scope value.
#[derive(Debug, Clone)]
pub struct Names<T> {
    value: T,
    index: usize,
}

impl<T> Names<T> {
    /// Creates an iterator over the names contained in value.
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Self { value, index: 0 }
    }
}

impl<T: Scope> Iterator for Names<T> {
    type Item = &'static str;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < T::FLAGS.len() {
            let flag = T::FLAGS[self.index];
            self.index += 1;

            if self.value.contains(flag.value()) {
                return Some(flag.name());
            }
        }

        None
    }
}

impl<T: Scope> FusedIterator for Names<T> {}

/// Iterator over the values contained in a scope value.
#[derive(Debug, Clone)]
pub struct Values<T> {
    value: T,
    index: usize,
}

impl<T> Values<T> {
    /// Creates an iterator over the values contained in value.
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Self { value, index: 0 }
    }
}

impl<T: Scope> Iterator for Values<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < T::FLAGS.len() {
            let flag = T::FLAGS[self.index];
            self.index += 1;

            if self.value.contains(flag.value()) {
                return Some(*flag.value());
            }
        }

        None
    }
}

impl<T: Scope> FusedIterator for Values<T> {}

#[cfg(feature = "serde")]
#[doc(hidden)]
#[macro_export]
macro_rules! __scope_impl_serde {
    ($scope:ident) => {
        impl $crate::scope::__private::serde::Serialize for $scope {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: $crate::scope::__private::serde::Serializer,
            {
                <str as $crate::scope::__private::serde::Serialize>::serialize(
                    $crate::scope::__private::const_hex::Buffer::<_, true>::new()
                        .const_format(&self.to_raw().to_le_bytes())
                        .as_str(),
                    serializer,
                )
            }
        }

        impl<'de> $crate::scope::__private::serde::Deserialize<'de> for $scope {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
            where
                D: $crate::scope::__private::serde::Deserializer<'de>,
            {
                <&str as $crate::scope::__private::serde::Deserialize>::deserialize(deserializer)
                    .and_then(|value| {
                        <Self as ::core::str::FromStr>::from_str(value).map_err(
                            <D::Error as $crate::scope::__private::serde::de::Error>::custom,
                        )
                    })
            }
        }
    };
}

#[cfg(not(feature = "serde"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __scope_impl_serde {
    ($scope:ident) => {};
}

#[cfg(feature = "sqlx")]
#[doc(hidden)]
#[macro_export]
macro_rules! __scope_impl_sqlx {
    ($scope:ident) => {
        impl<D> $crate::scope::__private::sqlx::Type<D> for $scope
        where
            D: $crate::scope::__private::sqlx::Database,
            i64: $crate::scope::__private::sqlx::Type<D>,
        {
            #[inline(always)]
            fn type_info() -> <D as $crate::scope::__private::sqlx::Database>::TypeInfo {
                <i64 as $crate::scope::__private::sqlx::Type<D>>::type_info()
            }

            #[inline(always)]
            fn compatible(ty: &D::TypeInfo) -> bool {
                <i64 as $crate::scope::__private::sqlx::Type<D>>::compatible(ty)
            }
        }

        impl<'q, D> $crate::scope::__private::sqlx::Encode<'q, D> for $scope
        where
            D: $crate::scope::__private::sqlx::Database,
            i64: $crate::scope::__private::sqlx::Encode<'q, D>,
        {
            #[inline(always)]
            fn encode_by_ref(
                &self,
                buffer: &mut D::ArgumentBuffer<'q>,
            ) -> ::core::result::Result<
                $crate::scope::__private::sqlx::encode::IsNull,
                $crate::scope::__private::sqlx::error::BoxDynError,
            > {
                <i64 as $crate::scope::__private::sqlx::Encode<'q, D>>::encode_by_ref(
                    &(self.to_raw() as i64),
                    buffer,
                )
            }

            #[inline(always)]
            fn produces(&self) -> Option<D::TypeInfo> {
                <i64 as $crate::scope::__private::sqlx::Encode<'q, D>>::produces(
                    &(self.to_raw() as i64),
                )
            }

            #[inline(always)]
            fn size_hint(&self) -> usize {
                <i64 as $crate::scope::__private::sqlx::Encode<'q, D>>::size_hint(
                    &(self.to_raw() as i64),
                )
            }
        }

        impl<'r, D> $crate::scope::__private::sqlx::Decode<'r, D> for $scope
        where
            D: $crate::scope::__private::sqlx::Database,
            i64: $crate::scope::__private::sqlx::Decode<'r, D>,
        {
            #[inline(always)]
            fn decode(
                value: D::ValueRef<'r>,
            ) -> ::core::result::Result<Self, $crate::scope::__private::sqlx::error::BoxDynError>
            {
                <i64 as $crate::scope::__private::sqlx::Decode<'r, D>>::decode(value)
                    .map(|raw| Self::from_raw(raw as u64))
            }
        }
    };
}

#[cfg(not(feature = "sqlx"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __scope_impl_sqlx {
    ($scope:ident) => {};
}

/// Defines one or more bitmap-backed permission scope types.
///
/// Individual scopes use bit positions from 0 through 63. Compound scopes combine
/// existing scopes and/or bit positions with `&&`.
///
/// ```
/// use snowfinch::{Scope, scope};
///
/// scope! {
///     pub enum Permissions {
///         Read = 0,
///         Write = 1,
///         ReadWrite = Read && 1,
///     }
/// }
///
/// let permissions = Permissions::Read | Permissions::Write;
/// assert!(permissions.contains(&Permissions::ReadWrite));
/// assert_eq!(Permissions::from_name("Read"), Some(Permissions::Read));
/// assert_eq!(
///     permissions.names().collect::<Vec<_>>(),
///     ["Read", "Write", "ReadWrite"],
/// );
/// ```
#[macro_export]
macro_rules! scope {
    (@component $scope:ident, $member:ident) => {
        $scope::$member.0
    };

    (@component $scope:ident, $position:literal) => {
        match 1u64.checked_shl($position) {
            Some(bits) => bits,
            None => panic!(concat!(
                "scope bit `",
                ::core::stringify!($position),
                "` is outside 0..64",
            )),
        }
    };

    (@field $scope:ident, $(#[$meta:meta])* $name:ident, $position:literal) => {
        $(#[$meta])*
        #[doc = concat!("The `", ::core::stringify!($name), "` scope flag.")]
        pub const $name: Self = Self($crate::scope!(@component $scope, $position));
    };

    (@field $scope:ident, $(#[$meta:meta])* $name:ident, $($member:tt)&&+) => {
        $(#[$meta])*
        #[doc = concat!("The `", ::core::stringify!($name), "` compound scope.")]
        pub const $name: Self = Self(
            0 $(| $crate::scope!(@component $scope, $member))+
        );
    };

    (
        $(
            $(#[$scope_meta:meta])*
            $visibility:vis enum $scope:ident {
                $(
                    $(#[$field_meta:meta])*
                    $field:ident = $($member:tt)&&+
                ),* $(,)?
            }
        )+
    ) => {
        $(
            #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
            $(#[$scope_meta])*
            #[repr(transparent)]
            $visibility struct $scope(u64);

            #[allow(non_upper_case_globals)]
            impl $scope {
                $(
                    $crate::scope!(
                        @field
                        $scope,
                        $(#[$field_meta])*
                        $field,
                        $($member)&&+
                    );
                )*

                /// Number of bits in the underlying representation.
                pub const BITS: u32 = u64::BITS;

                /// Empty scope value containing no flags.
                pub const EMPTY: Self = Self(0);

                /// Scope value containing every bit used by a declared scope.
                pub const ALL: Self = Self(
                    0 $(| $scope::$field.0)*
                );

                /// Metadata for every declared flag and compound scope.
                pub const FLAGS: &'static [$crate::scope::Flag<Self>] = &[
                    $(
                        $crate::scope::Flag::new(
                            ::core::stringify!($field),
                            Self::$field,
                        )
                    ),*
                ];

                /// Returns the raw bitmap backing this scope.
                #[inline(always)]
                pub const fn to_raw(self) -> u64 {
                    self.0
                }

                /// Builds a scope from a raw bitmap.
                ///
                /// Bits which do not belong to a declared scope are ignored.
                #[inline(always)]
                pub const fn from_raw(raw: u64) -> Self {
                    Self(raw & Self::ALL.0)
                }

                /// Looks up a declared flag or compound scope by name.
                #[inline(always)]
                pub const fn from_name(name: &str) -> Option<Self> {
                    $(
                        const $field: &'static [u8] = ::core::stringify!($field).as_bytes();
                    )*

                    match name.as_bytes() {
                        $($field => Some(Self::$field),)*
                        _ => None,
                    }
                }

                /// Returns true when this scope contains no flags.
                #[inline(always)]
                pub const fn is_empty(&self) -> bool {
                    self.0 == 0
                }

                /// Returns true when this scope contains every bit used by a declared scope.
                #[inline(always)]
                pub const fn is_all(&self) -> bool {
                    self.0 == Self::ALL.0
                }

                /// Returns true when the scopes share at least one flag.
                #[inline(always)]
                pub const fn intersects(&self, other: &Self) -> bool {
                    self.0 & other.0 != 0
                }

                /// Returns true when this scope contains every flag in other.
                #[inline(always)]
                pub const fn contains(&self, other: &Self) -> bool {
                    self.0 & other.0 == other.0
                }

                /// Returns the flags present in both scopes.
                #[inline(always)]
                pub const fn intersection(self, other: Self) -> Self {
                    Self(self.0 & other.0)
                }

                /// Returns the flags present in either scope.
                #[inline(always)]
                pub const fn union(self, other: Self) -> Self {
                    Self(self.0 | other.0)
                }

                /// Returns the flags present in this scope but not in other.
                #[inline(always)]
                pub const fn difference(self, other: Self) -> Self {
                    Self(self.0 & !other.0)
                }

                /// Returns the flags present in exactly one of the two scopes.
                #[inline(always)]
                pub const fn symmetric_difference(self, other: Self) -> Self {
                    Self(self.0 ^ other.0)
                }

                /// Iterates over the names contained in this scope.
                #[inline(always)]
                pub const fn names(&self) -> $crate::scope::Names<Self> {
                    $crate::scope::Names::new(*self)
                }

                /// Iterates over the values contained in this scope.
                #[inline(always)]
                pub const fn values(&self) -> $crate::scope::Values<Self> {
                    $crate::scope::Values::new(*self)
                }
            }

            impl $crate::scope::Scope for $scope {
                const EMPTY: Self = Self::EMPTY;
                const ALL: Self = Self::ALL;
                const FLAGS: &'static [$crate::scope::Flag<Self>] = Self::FLAGS;

                #[inline(always)]
                fn from_name(name: &str) -> Option<Self> {
                    Self::from_name(name)
                }

                #[inline(always)]
                fn is_empty(&self) -> bool {
                    self.is_empty()
                }

                #[inline(always)]
                fn is_all(&self) -> bool {
                    self.is_all()
                }

                #[inline(always)]
                fn intersects(&self, other: &Self) -> bool {
                    self.intersects(other)
                }

                #[inline(always)]
                fn contains(&self, other: &Self) -> bool {
                    self.contains(other)
                }

                #[inline(always)]
                fn intersection(self, other: Self) -> Self {
                    self.intersection(other)
                }

                #[inline(always)]
                fn union(self, other: Self) -> Self {
                    self.union(other)
                }

                #[inline(always)]
                fn difference(self, other: Self) -> Self {
                    self.difference(other)
                }

                #[inline(always)]
                fn symmetric_difference(self, other: Self) -> Self {
                    self.symmetric_difference(other)
                }

                #[inline(always)]
                fn names(&self) -> $crate::scope::Names<Self> {
                    self.names()
                }

                #[inline(always)]
                fn values(&self) -> $crate::scope::Values<Self> {
                    self.values()
                }
            }

            impl ::core::ops::BitAnd for $scope {
                type Output = Self;

                #[inline(always)]
                fn bitand(self, other: Self) -> Self {
                    self.intersection(other)
                }
            }

            impl ::core::ops::BitOr for $scope {
                type Output = Self;

                #[inline(always)]
                fn bitor(self, other: Self) -> Self {
                    self.union(other)
                }
            }

            impl ::core::ops::BitXor for $scope {
                type Output = Self;

                #[inline(always)]
                fn bitxor(self, other: Self) -> Self {
                    self.symmetric_difference(other)
                }
            }

            impl ::core::ops::Not for $scope {
                type Output = Self;

                #[inline(always)]
                fn not(self) -> Self {
                    Self::ALL.difference(self)
                }
            }

            impl ::core::fmt::Debug for $scope {
                fn fmt(
                    &self,
                    formatter: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    formatter.write_str(::core::stringify!($scope))?;
                    formatter.write_str("(")?;

                    for (index, name) in self.names().enumerate() {
                        if index != 0 {
                            formatter.write_str(" && ")?;
                        }
                        formatter.write_str(name)?;
                    }

                    formatter.write_str(")")
                }
            }

            impl ::core::str::FromStr for $scope {
                type Err = $crate::scope::ParseScopeError;

                fn from_str(value: &str) -> ::core::result::Result<Self, Self::Err> {
                    $crate::scope::__private::const_hex::decode_to_array(value.as_bytes())
                        .map(u64::from_le_bytes)
                        .map(Self::from_raw)
                        .map_err($crate::scope::ParseScopeError::from)
                }
            }

            $crate::__scope_impl_serde!($scope);
            $crate::__scope_impl_sqlx!($scope);
        )+
    };
}

#[doc(hidden)]
pub mod __private {
    pub use const_hex;

    #[cfg(feature = "serde")]
    pub use serde;

    #[cfg(feature = "sqlx")]
    pub use sqlx;
}

#[cfg(test)]
mod tests {
    use super::ParseScopeError;

    crate::scope! {
        enum Permissions {
            Read = 0,
            Write = 1,
            Audit = 63,
            ReadWrite = Read && Write,
        }

        enum Secondary {
            Enabled = 4,
        }

        enum Compound {
            Read = 0,
            Mixed = Read && 2,
            LiteralOnly = 3 && 4,
        }
    }

    #[test]
    fn constants_and_metadata() {
        assert_eq!(Permissions::BITS, 64);
        assert!(Permissions::EMPTY.is_empty());
        assert!(Permissions::ALL.is_all());
        assert_eq!(Permissions::FLAGS.len(), 4);
        assert_eq!(Permissions::FLAGS[3].name(), "ReadWrite");
        assert_eq!(Permissions::FLAGS[3].value(), &Permissions::ReadWrite);
        assert_eq!(Permissions::from_name("Audit"), Some(Permissions::Audit));
        assert_eq!(Permissions::from_name("missing"), None);
        assert_eq!(Secondary::from_name("Enabled"), Some(Secondary::Enabled));
        assert_eq!(Secondary::BITS, 64);
        assert_eq!(Secondary::Enabled.to_raw(), 16);
    }

    #[test]
    fn compound_scopes_accept_identifiers_and_literals() {
        assert_eq!(Compound::BITS, 64);
        assert_eq!(Compound::Mixed.to_raw(), (1 << 0) | (1 << 2));
        assert_eq!(Compound::LiteralOnly.to_raw(), (1 << 3) | (1 << 4));
        assert_eq!(
            Compound::ALL.to_raw(),
            (1 << 0) | (1 << 2) | (1 << 3) | (1 << 4),
        );
    }

    #[test]
    fn set_operations_and_operators() {
        let read_write = Permissions::Read | Permissions::Write;

        assert!(read_write.contains(&Permissions::ReadWrite));
        assert!(read_write.intersects(&Permissions::Read));
        assert!(!read_write.intersects(&Permissions::Audit));
        assert_eq!(read_write & Permissions::Read, Permissions::Read);
        assert_eq!(read_write.difference(Permissions::Write), Permissions::Read,);
        assert_eq!(read_write ^ Permissions::Read, Permissions::Write);
        assert_eq!(!Permissions::Audit, Permissions::ReadWrite);
    }

    #[test]
    fn raw_and_hex_round_trip() {
        let value = Permissions::Read | Permissions::Audit;
        let raw = (1 << 0) | (1 << 63);

        assert_eq!(value.to_raw(), raw);
        assert_eq!(Permissions::from_raw(raw), value);
        assert_eq!("0100000000000080".parse::<Permissions>().unwrap(), value);
        let error: ParseScopeError = "not hex".parse::<Permissions>().unwrap_err();
        assert!(!error.to_string().is_empty());
        assert_eq!(Permissions::from_raw(u64::MAX), Permissions::ALL);
    }

    #[test]
    fn iteration_and_debug_include_compound_scopes() {
        let value = Permissions::ReadWrite;

        assert_eq!(
            value.names().collect::<Vec<_>>(),
            ["Read", "Write", "ReadWrite"],
        );
        assert_eq!(
            value.values().collect::<Vec<_>>(),
            [
                Permissions::Read,
                Permissions::Write,
                Permissions::ReadWrite,
            ],
        );
        assert_eq!(
            format!("{value:?}"),
            "Permissions(Read && Write && ReadWrite)",
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_traits_are_available() {
        fn assert_serde<T>()
        where
            T: serde::Serialize + serde::de::DeserializeOwned,
        {
        }

        assert_serde::<Permissions>();
    }
}
