//! Bitmap-backed permission scopes.

use std::{
    iter::FusedIterator,
    ops::{BitAnd, BitOr, BitXor, Not},
};

/// A bitmap-backed set of permissions.
///
/// Types implementing `Scope` are usually generated with the [`scope!`](crate::scope!) macro.
/// Scope values are copyable, support bitwise set operations, and can be
/// converted to and from a stable byte representation.
pub trait Scope:
    Copy + PartialEq + Eq + BitAnd + BitOr + BitXor + Not + Sized + Send + Sync + 'static
{
    /// Number of bitmap bits used by this scope type.
    const BITS: u32;

    /// The empty scope containing no flags.
    const EMPTY: Self;

    /// A scope containing every primitive flag declared for this type.
    const ALL: Self;

    /// Metadata for every declared flag and alias.
    const FLAGS: &'static [Flag<Self>];

    /// Looks up a declared flag or alias by name.
    fn from_name(x: &str) -> Option<Self>;

    /// Returns `true` when no flags are set.
    fn is_empty(&self) -> bool;

    /// Returns `true` when all primitive flags are set.
    fn is_all(&self) -> bool;

    /// Returns `true` when `self` and `other` have at least one flag in common.
    fn intersects(&self, other: &Self) -> bool;

    /// Returns `true` when `self` contains every flag in `other`.
    fn contains(&self, other: &Self) -> bool;

    /// Returns the flags present in both `self` and `other`.
    fn intersection(self, other: Self) -> Self;

    /// Returns the flags present in either `self` or `other`.
    fn union(self, other: Self) -> Self;

    /// Returns the flags present in `self` but not in `other`.
    fn difference(self, other: Self) -> Self;

    /// Returns the flags present in exactly one of `self` or `other`.
    fn symmetric_difference(self, other: Self) -> Self;

    /// Iterates over the names of flags contained in this scope.
    fn names(&self) -> Names<Self>;

    /// Iterates over the flag values contained in this scope.
    fn values(&self) -> Values<Self>;
}

/// Metadata for a declared scope flag or alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Flag<T> {
    name: &'static str,
    value: T,
}

impl<T> Flag<T> {
    /// Creates flag metadata from a name and value.
    #[inline]
    pub const fn new(name: &'static str, value: T) -> Self {
        Self { name, value }
    }

    /// Returns the declared name of the flag or alias.
    #[inline]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the scope value represented by this flag or alias.
    #[inline]
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
    /// Creates an iterator over the names contained in `value`.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self { value, index: 0 }
    }
}

impl<T> Iterator for Names<T>
where
    T: Scope,
{
    type Item = &'static str;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < T::FLAGS.len() {
            let other = T::FLAGS[self.index];
            self.index += 1;

            if self.value.contains(other.value()) {
                return Some(other.name());
            }
        }

        None
    }
}

impl<T> FusedIterator for Names<T> where T: Scope {}

/// Iterator over the individual flag values contained in a scope value.
#[derive(Debug, Clone)]
pub struct Values<T> {
    value: T,
    index: usize,
}

impl<T> Values<T> {
    /// Creates an iterator over the values contained in `value`.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self { value, index: 0 }
    }
}

impl<T> Iterator for Values<T>
where
    T: Scope,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < T::FLAGS.len() {
            let other = T::FLAGS[self.index];
            self.index += 1;

            if self.value.contains(other.value()) {
                return Some(*other.value());
            }
        }

        None
    }
}

impl<T> FusedIterator for Values<T> where T: Scope {}

/// Defines one or more bitmap-backed permission scope types.
///
/// The syntax resembles an enum declaration, but the macro generates a newtype
/// struct with associated constants and set-like operations. Each primitive flag
/// is declared with a numeric bit position, while aliases can be declared as a
/// combination of other flags with `&&`.
///
/// # Example
///
/// ```rust
/// use snowfinch::scope;
///
/// scope! {
///     // Permissions for an example service.
///     pub enum Permissions {
///         // Permission to read data.
///         Read = 0,
///
///         // Permission to write data.
///         Write = 1,
///
///         // Read and write permissions.
///         ReadWrite = Read && Write,
///     }
/// }
///
/// let scope = Permissions::Read | Permissions::Write;
/// assert!(scope.contains(&Permissions::ReadWrite));
/// assert_eq!(Permissions::from_name("Read"), Some(Permissions::Read));
/// ```
///
/// The generated type implements [`Scope`], [`core::fmt::Debug`],
/// [`core::str::FromStr`], bitwise set operators, and optional `serde`/`sqlx`
/// traits when those crate features are enabled.
#[macro_export]
macro_rules! scope {
    (
        $(
            $(#[$struct_meta:meta])*
            $struct_vis:vis enum $struct_ident:ident {
                $(
                    $(#[$field_meta:meta])*
                    $field_ident:ident = $($field_literal:literal)? $($field_idents:ident)&&*
                ),* $(,)?
            }
        )+
    ) => {
        $(
            #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
            #[repr(transparent)]
            $(#[$struct_meta])*
            $struct_vis struct $struct_ident([usize; { Self::BITS.div_ceil(usize::BITS) as usize }]);

            $crate::__scope_impl_fields!($struct_ident, { $($(#[$field_meta])* $field_ident = $($field_literal)? $($field_idents)&&*),* });

            $crate::__scope_impl_consts!($struct_ident, { $($field_ident = $($field_literal)? $($field_idents)&&*),* });

            $crate::__scope_impl_methods!($struct_ident, { $($field_ident = $($field_literal)? $($field_idents)&&*),* });

            $crate::__scope_impl_traits!($struct_ident);
         )+
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_field {
    ($(#[$field_meta:meta])* $struct_ident:ident, $ident:ident, $literal:literal) => {
        $(#[$field_meta])*
        #[doc = concat!("The `", ::core::stringify!($ident), "` scope flag.")]
        pub const $ident: Self = {
            let mut x = [0usize; _];
            x[$literal / usize::BITS as usize] |= 1 << ($literal % usize::BITS as usize);
            Self(x)
        };
    };

    ($(#[$field_meta:meta])* $struct_ident:ident, $ident:ident, $($field_idents:ident)&&*) => {
        $(#[$field_meta])*
        #[doc = concat!("The `", ::core::stringify!($ident), "` scope alias.")]
        pub const $ident: Self = {
            let mut x = [0usize; _];
            let mut i = 0;

            while i < x.len() {
                $(
                    x[i] |= $struct_ident::$field_idents.0[i];
                )*

                i += 1;
            }

            Self(x)
        };
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_fields {
    ($struct_ident:ident, { $($(#[$field_meta:meta])* $field_ident:ident = $($field_literal:literal)? $($field_idents:ident)&&*),* }) => {
        impl $struct_ident {
            $(
                $crate::__scope_impl_field!($(#[$field_meta])* $struct_ident, $field_ident, $($field_literal)? $($field_idents)&&*);
            )*
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_bits {
    ($struct_ident:ident, { $($field_ident:ident = $($field_literal:literal)? $($field_idents:ident)&&*),* }) => {
        impl $struct_ident {
            /// Number of bitmap bits used by this scope type.
            pub const BITS: u32 = {
                let k = [
                    $($crate::__scope_impl_bits_size!(
                        $($field_literal)?
                        $($field_idents)&&*
                    )),*
                ];

                let mut x = 0;
                let mut i = 0;

                while i < k.len() {
                    x = if x > k[i] { x } else { k[i] };
                    i += 1;
                }

                x
            };
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_bits_size {
    ($literal:literal) => {
        $literal as u32
    };

    ($($field_idents:ident)&&*) => {
        0u32
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_all {
    ($struct_ident:ident, { $($field_ident:ident = $($field_literal:literal)? $($field_idents:ident)&&*),* }) => {
        impl $struct_ident {
            /// Scope value containing every primitive flag declared for this type.
            pub const ALL: Self = {
                let mut x = [0usize; _];
                let mut i = 0;

                while i < x.len() {
                    $(
                        x[i] |= $crate::__scope_impl_all_bits!(
                            $struct_ident,
                            i,
                            $field_ident,
                            $($field_literal)? $($field_idents)&&*
                        );
                    )*

                    i += 1;
                }

                Self(x)
            };
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_all_bits {
    ($struct_ident:ident, $i:expr, $ident:ident, $literal:literal) => {
        $struct_ident::$ident.0[$i]
    };

    ($struct_ident:ident, $i:expr, $ident:ident, $($field_idents:ident)&&*) => {
        0usize
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_empty {
    ($struct_ident:ident, $tt:tt) => {
        impl $struct_ident {
            /// Empty scope value containing no flags.
            pub const EMPTY: Self = Self([0usize; _]);
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_flags {
    ($struct_ident:ident, { $($field_ident:ident = $($field_literal:literal)? $($field_idents:ident)&&*),* }) => {
        impl $struct_ident {
            /// Metadata for every declared flag and alias.
            pub const FLAGS: &'static [$crate::scope::Flag<Self>] = &[
                $(
                    $crate::scope::Flag::new(
                        ::core::stringify!($field_ident),
                        Self::$field_ident,
                    )
                ),*
            ];
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_consts {
    ($($tt:tt)*) => {
        $crate::__scope_impl_bits!($($tt)*);
        $crate::__scope_impl_empty!($($tt)*);
        $crate::__scope_impl_all!($($tt)*);
        $crate::__scope_impl_flags!($($tt)*);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_from_bytes {
    ($struct_ident:ident, $tt:tt) => {
        impl $struct_ident {
            /// Builds a scope from its little-endian byte representation.
            ///
            /// Bits that are not part of [`Self::ALL`] are ignored.
            #[inline]
            pub const fn from_bytes(x: [u8; { ::core::mem::size_of::<Self>() }]) -> Self {
                let mut k = [0usize; _];
                let mut i = 0;

                let c = x.as_chunks().0;

                while i < k.len() {
                    k[i] = Self::ALL.0[i] & usize::from_le_bytes(c[i]);
                    i += 1;
                }

                Self(k)
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_to_bytes {
    ($struct_ident:ident, $tt:tt) => {
        impl $struct_ident {
            /// Converts this scope to its little-endian byte representation.
            #[inline]
            pub const fn to_bytes(self) -> [u8; { ::core::mem::size_of::<Self>() }] {
                let mut x = [0u8; _];
                let mut i = 0;

                let c = x.as_chunks_mut().0;

                while i < c.len() {
                    c[i] = self.0[i].to_le_bytes();
                    i += 1;
                }

                x
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_from_name {
    ($struct_ident:ident, { $($field_ident:ident = $($field_literal:literal)? $($field_idents:ident)&&*),* }) => {
        impl $struct_ident {
            /// Looks up a declared flag or alias by name.
            #[inline]
            pub const fn from_name(x: &str) -> Option<Self> {
                $(
                    const $field_ident: &'static [u8] = ::core::stringify!($field_ident).as_bytes();
                )*

                match x.as_bytes() {
                    $(
                        $field_ident => Some(Self::$field_ident),
                    )*

                    _ => None,
                }
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_cmp {
    ($struct_ident:ident, $tt:tt) => {
        impl $struct_ident {
            /// Returns `true` when `self` and `other` contain the same flags.
            #[inline]
            pub const fn eq(&self, other: &Self) -> bool {
                let mut i = 0;
                let mut x = true;

                while i < self.0.len() {
                    x = x && self.0[i] == other.0[i];
                    i += 1;
                }

                x
            }

            /// Returns `true` when this scope contains no flags.
            #[inline]
            pub const fn is_empty(&self) -> bool {
                self.eq(&Self::EMPTY)
            }

            /// Returns `true` when this scope contains every primitive flag.
            #[inline]
            pub const fn is_all(&self) -> bool {
                self.eq(&Self::ALL)
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_boolean {
    ($struct_ident:ident, $tt:tt) => {
        impl $struct_ident {
            /// Returns `true` when `self` and `other` share at least one flag.
            #[inline]
            pub const fn intersects(&self, other: &Self) -> bool {
                let mut i = 0;
                let mut x = false;

                while i < self.0.len() {
                    x = x || self.0[i] & other.0[i] != 0;
                    i += 1;
                }

                x
            }

            /// Returns `true` when this scope contains every flag in `other`.
            #[inline]
            pub const fn contains(&self, other: &Self) -> bool {
                let mut i = 0;
                let mut x = true;

                while i < self.0.len() {
                    x = x && self.0[i] & other.0[i] == other.0[i];
                    i += 1;
                }

                x
            }

            /// Returns the flags present in both scopes.
            #[inline]
            pub const fn intersection(self, other: Self) -> Self {
                let mut x = Self::EMPTY;
                let mut i = 0;

                while i < self.0.len() {
                    x.0[i] = self.0[i] & other.0[i];
                    i += 1;
                }

                x
            }

            /// Returns the flags present in either scope.
            #[inline]
            pub const fn union(self, other: Self) -> Self {
                let mut x = Self::EMPTY;
                let mut i = 0;

                while i < self.0.len() {
                    x.0[i] = self.0[i] | other.0[i];
                    i += 1;
                }

                x
            }

            /// Returns the flags present in `self` but not in `other`.
            #[inline]
            pub const fn difference(self, other: Self) -> Self {
                let mut x = Self::EMPTY;
                let mut i = 0;

                while i < self.0.len() {
                    x.0[i] = self.0[i] & !other.0[i];
                    i += 1;
                }

                x
            }

            /// Returns the flags present in exactly one of the two scopes.
            #[inline]
            pub const fn symmetric_difference(self, other: Self) -> Self {
                let mut x = Self::EMPTY;
                let mut i = 0;

                while i < self.0.len() {
                    x.0[i] = self.0[i] ^ other.0[i];
                    i += 1;
                }

                x
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_iter {
    ($struct_ident:ident, $tt:tt) => {
        impl $struct_ident {
            /// Iterates over the names of flags contained in this scope.
            #[inline]
            pub const fn names(&self) -> $crate::scope::Names<Self> {
                $crate::scope::Names::new(*self)
            }

            /// Iterates over the flag values contained in this scope.
            #[inline]
            pub const fn values(&self) -> $crate::scope::Values<Self> {
                $crate::scope::Values::new(*self)
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_methods {
    ($($tt:tt)*) => {
        $crate::__scope_impl_to_bytes!($($tt)*);

        $crate::__scope_impl_from_bytes!($($tt)*);
        $crate::__scope_impl_from_name!($($tt)*);

        $crate::__scope_impl_cmp!($($tt)*);
        $crate::__scope_impl_boolean!($($tt)*);
        $crate::__scope_impl_iter!($($tt)*);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_debug {
    ($struct_ident:ident) => {
        impl ::core::fmt::Debug for $struct_ident {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(::core::stringify!($struct_ident))?;
                f.write_str("(")?;

                for (index, name) in self.names().enumerate() {
                    if index != 0 {
                        f.write_str(" && ")?;
                    }

                    f.write_str(name)?;
                }

                f.write_str(")")?;

                Ok(())
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_from_str {
    ($struct_ident:ident) => {
        impl ::core::str::FromStr for $struct_ident {
            type Err = $crate::Error;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                $crate::scope::__macro::const_hex::decode_to_array(s.as_bytes())
                    .map(Self::from_bytes)
                    .map_err($crate::Error::from)
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_ops {
    ($struct_ident:ident) => {
        impl ::core::ops::BitAnd for $struct_ident {
            type Output = Self;

            #[inline]
            fn bitand(self, rhs: Self) -> Self::Output {
                self.intersection(rhs)
            }
        }

        impl ::core::ops::BitOr for $struct_ident {
            type Output = Self;

            #[inline]
            fn bitor(self, rhs: Self) -> Self::Output {
                self.union(rhs)
            }
        }

        impl ::core::ops::BitXor for $struct_ident {
            type Output = Self;

            #[inline]
            fn bitxor(self, rhs: Self) -> Self::Output {
                self.symmetric_difference(rhs)
            }
        }

        impl ::core::ops::Not for $struct_ident {
            type Output = Self;

            #[inline]
            fn not(self) -> Self::Output {
                Self::ALL.difference(self)
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_scope {
    ($struct_ident:ident) => {
        impl $crate::scope::Scope for $struct_ident {
            const BITS: u32 = Self::BITS;

            const EMPTY: Self = Self::EMPTY;

            const ALL: Self = Self::ALL;

            const FLAGS: &'static [$crate::scope::Flag<Self>] = Self::FLAGS;

            #[inline]
            fn from_name(x: &str) -> Option<Self> {
                Self::from_name(x)
            }

            #[inline]
            fn is_empty(&self) -> bool {
                self.is_empty()
            }

            #[inline]
            fn is_all(&self) -> bool {
                self.is_all()
            }

            #[inline]
            fn intersects(&self, other: &Self) -> bool {
                self.intersects(other)
            }

            #[inline]
            fn contains(&self, other: &Self) -> bool {
                self.contains(other)
            }

            #[inline]
            fn intersection(self, other: Self) -> Self {
                self.intersection(other)
            }

            #[inline]
            fn union(self, other: Self) -> Self {
                self.union(other)
            }

            #[inline]
            fn difference(self, other: Self) -> Self {
                self.difference(other)
            }

            #[inline]
            fn symmetric_difference(self, other: Self) -> Self {
                self.symmetric_difference(other)
            }

            #[inline]
            fn names(&self) -> $crate::scope::Names<Self> {
                self.names()
            }

            #[inline]
            fn values(&self) -> $crate::scope::Values<Self> {
                self.values()
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
#[cfg(feature = "serde")]
macro_rules! __scope_impl_serde {
    ($struct_ident:ident) => {
        impl $crate::scope::__macro::serde::Serialize for $struct_ident {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: $crate::scope::__macro::serde::Serializer,
            {
                <str as $crate::scope::__macro::serde::Serialize>::serialize(
                    $crate::scope::__macro::const_hex::Buffer::<_, true>::new()
                        .const_format(&self.to_bytes())
                        .as_str(),
                    serializer,
                )
            }
        }

        impl<'de> $crate::scope::__macro::serde::Deserialize<'de> for $struct_ident {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
            where
                D: $crate::scope::__macro::serde::Deserializer<'de>,
            {
                <&str as $crate::scope::__macro::serde::Deserialize>::deserialize(deserializer)
                    .and_then(|x| {
                        <Self as ::core::str::FromStr>::from_str(x).map_err(|err| {
                            <D::Error as $crate::scope::__macro::serde::de::Error>::custom(err)
                        })
                    })
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
#[cfg(not(feature = "serde"))]
macro_rules! __scope_impl_serde {
    ($struct_ident:ident) => {};
}

#[macro_export]
#[doc(hidden)]
#[cfg(feature = "sqlx")]
macro_rules! __scope_impl_sqlx {
    ($struct_ident:ident) => {
        impl<D> $crate::scope::__macro::sqlx::Type<D> for $struct_ident
        where
            D: $crate::scope::__macro::sqlx::Database,
            ::std::string::String: $crate::scope::__macro::sqlx::Type<D>,
        {
            #[inline]
            fn type_info() -> <D as $crate::scope::__macro::sqlx::Database>::TypeInfo {
                <::std::string::String as $crate::scope::__macro::sqlx::Type<D>>::type_info()
            }
        }

        impl<'q, D> $crate::scope::__macro::sqlx::Encode<'q, D> for $struct_ident
        where
            D: $crate::scope::__macro::sqlx::Database,
            ::std::string::String: $crate::scope::__macro::sqlx::Encode<'q, D>,
        {
            fn encode_by_ref(
                &self,
                buf: &mut D::ArgumentBuffer,
            ) -> ::core::result::Result<
                $crate::scope::__macro::sqlx::encode::IsNull,
                $crate::scope::__macro::sqlx::error::BoxDynError,
            > {
                $crate::scope::__macro::const_hex::Buffer::<_, false>::new()
                    .const_format(&self.to_bytes())
                    .as_str()
                    .to_owned()
                    .encode(buf)
            }
        }

        impl<'r, D> $crate::scope::__macro::sqlx::Decode<'r, D> for $struct_ident
        where
            D: $crate::scope::__macro::sqlx::Database,
            ::std::string::String: $crate::scope::__macro::sqlx::Decode<'r, D>,
        {
            fn decode(
                value: D::ValueRef<'r>,
            ) -> ::core::result::Result<Self, $crate::scope::__macro::sqlx::error::BoxDynError>
            {
                <::std::string::String as $crate::scope::__macro::sqlx::Decode<'r, D>>::decode(
                    value,
                )
                .and_then(|x| {
                    <Self as ::core::str::FromStr>::from_str(&x).map_err(|err| Box::new(err).into())
                })
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
#[cfg(not(feature = "sqlx"))]
macro_rules! __scope_impl_sqlx {
    ($struct_ident:ident) => {};
}

#[macro_export]
#[doc(hidden)]
macro_rules! __scope_impl_traits {
    ($struct_ident:ident) => {
        $crate::__scope_impl_scope!($struct_ident);
        $crate::__scope_impl_ops!($struct_ident);
        $crate::__scope_impl_debug!($struct_ident);
        $crate::__scope_impl_from_str!($struct_ident);

        $crate::__scope_impl_serde!($struct_ident);
        $crate::__scope_impl_sqlx!($struct_ident);
    };
}

#[doc(hidden)]
pub mod __macro {
    #[cfg(feature = "serde")]
    pub use serde;

    #[cfg(feature = "sqlx")]
    pub use sqlx;

    pub use const_hex;
}
