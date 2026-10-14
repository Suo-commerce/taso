//! Canonical encoding.
//!
//! Every byte that enters the hash chain is produced here. The encoding is
//! deliberately dumb so that it can be specified in a paragraph and
//! re-implemented anywhere:
//!
//! - integers are fixed-width little-endian (`u8`, `u32`, `u64`);
//! - a byte string is a `u64` length followed by the bytes;
//! - an enum is a `u8` tag followed by the fields of that variant;
//! - `Option<T>` is tag `0` (none) or tag `1` followed by `T`;
//! - a sequence is a `u64` count followed by its elements;
//! - a set is encoded as a sequence in ascending order of its elements'
//!   encodings, so equal sets always encode to equal bytes.
//!
//! There is no framing, no field names and no version byte: the schema is
//! the code, and the domain-separation string used when hashing (see the
//! envelope) carries the version. Changing any encoding is a new domain.

use std::collections::{BTreeMap, BTreeSet};

/// A growable buffer of canonical bytes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Canon {
    bytes: Vec<u8>,
}

impl Canon {
    /// An empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// The bytes encoded so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the buffer.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Append one byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes.push(v);
        self
    }

    /// Append a `u32`, little-endian.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append a `u64`, little-endian.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append a boolean as a single byte, `0` or `1`.
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }

    /// Append a length-prefixed byte string.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u64(v.len() as u64);
        self.bytes.extend_from_slice(v);
        self
    }

    /// Append a length-prefixed UTF-8 string.
    pub fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }

    /// Append a fixed-width array without a length prefix.
    ///
    /// Use only where the width is fixed by the type (hashes, ids); a
    /// variable-length value must go through [`Canon::bytes`].
    pub fn fixed<const N: usize>(&mut self, v: &[u8; N]) -> &mut Self {
        self.bytes.extend_from_slice(v);
        self
    }

    /// Append a variant tag.
    pub fn tag(&mut self, t: u8) -> &mut Self {
        self.u8(t)
    }

    /// Append an optional value: tag `0`, or tag `1` then the value.
    pub fn option<T: Canonical>(&mut self, v: Option<&T>) -> &mut Self {
        match v {
            None => self.tag(0),
            Some(x) => {
                self.tag(1);
                x.canon(self);
                self
            }
        }
    }

    /// Append a sequence: count, then each element in the given order.
    pub fn seq<'a, T, I>(&mut self, items: I) -> &mut Self
    where
        T: Canonical + 'a,
        I: IntoIterator<Item = &'a T>,
        I::IntoIter: ExactSizeIterator,
    {
        let it = items.into_iter();
        self.u64(it.len() as u64);
        for x in it {
            x.canon(self);
        }
        self
    }

    /// Append a set: count, then each element in ascending order of its own
    /// canonical encoding, regardless of the iteration order supplied.
    pub fn set<'a, T, I>(&mut self, items: I) -> &mut Self
    where
        T: Canonical + 'a,
        I: IntoIterator<Item = &'a T>,
    {
        let mut encoded: Vec<Vec<u8>> = items
            .into_iter()
            .map(|x| x.canon_bytes())
            .collect();
        encoded.sort();
        self.u64(encoded.len() as u64);
        for e in encoded {
            self.bytes.extend_from_slice(&e);
        }
        self
    }
}

/// A value with exactly one canonical byte encoding.
pub trait Canonical {
    /// Append this value's canonical encoding to `out`.
    fn canon(&self, out: &mut Canon);

    /// This value's canonical encoding as a fresh byte vector.
    fn canon_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new();
        self.canon(&mut c);
        c.into_bytes()
    }
}

impl Canonical for u8 {
    fn canon(&self, out: &mut Canon) {
        out.u8(*self);
    }
}

impl Canonical for u32 {
    fn canon(&self, out: &mut Canon) {
        out.u32(*self);
    }
}

impl Canonical for u64 {
    fn canon(&self, out: &mut Canon) {
        out.u64(*self);
    }
}

impl Canonical for bool {
    fn canon(&self, out: &mut Canon) {
        out.bool(*self);
    }
}

impl Canonical for str {
    fn canon(&self, out: &mut Canon) {
        out.str(self);
    }
}

impl Canonical for String {
    fn canon(&self, out: &mut Canon) {
        out.str(self);
    }
}

impl Canonical for [u8] {
    fn canon(&self, out: &mut Canon) {
        out.bytes(self);
    }
}

impl Canonical for Vec<u8> {
    fn canon(&self, out: &mut Canon) {
        out.bytes(self);
    }
}

impl<const N: usize> Canonical for [u8; N] {
    fn canon(&self, out: &mut Canon) {
        out.fixed(self);
    }
}

impl<T: Canonical> Canonical for Option<T> {
    fn canon(&self, out: &mut Canon) {
        out.option(self.as_ref());
    }
}

impl<T: Canonical> Canonical for BTreeSet<T> {
    fn canon(&self, out: &mut Canon) {
        out.set(self.iter());
    }
}

impl<K: Canonical, V: Canonical> Canonical for BTreeMap<K, V> {
    /// A map is a set of `(key, value)` pairs; keys are unique, so ordering
    /// by the pair's encoding orders by key.
    fn canon(&self, out: &mut Canon) {
        let pairs: Vec<Pair<'_, K, V>> = self.iter().map(|(k, v)| Pair(k, v)).collect();
        out.set(pairs.iter());
    }
}

/// A borrowed `(key, value)` pair, encoded as key then value.
struct Pair<'a, K, V>(&'a K, &'a V);

impl<K: Canonical, V: Canonical> Canonical for Pair<'_, K, V> {
    fn canon(&self, out: &mut Canon) {
        self.0.canon(out);
        self.1.canon(out);
    }
}

impl<T: Canonical + ?Sized> Canonical for &T {
    fn canon(&self, out: &mut Canon) {
        (**self).canon(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_fixed_width_little_endian() {
        let mut c = Canon::new();
        c.u8(0x01).u32(0x0403_0201).u64(0x0807_0605_0403_0201);
        assert_eq!(
            c.as_bytes(),
            &[1, 1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn byte_strings_are_length_prefixed() {
        let mut c = Canon::new();
        c.bytes(b"ab");
        assert_eq!(c.as_bytes(), &[2, 0, 0, 0, 0, 0, 0, 0, b'a', b'b']);

        let mut e = Canon::new();
        e.bytes(b"");
        assert_eq!(e.as_bytes(), &[0u8; 8]);
    }

    #[test]
    fn length_prefix_prevents_boundary_ambiguity() {
        // ("a", "bc") and ("ab", "c") must not collide.
        let mut x = Canon::new();
        x.str("a").str("bc");
        let mut y = Canon::new();
        y.str("ab").str("c");
        assert_ne!(x, y);
    }

    #[test]
    fn fixed_arrays_have_no_prefix() {
        let mut c = Canon::new();
        c.fixed(&[9u8; 4]);
        assert_eq!(c.as_bytes(), &[9, 9, 9, 9]);
    }

    #[test]
    fn option_is_tagged() {
        assert_eq!(None::<u8>.canon_bytes(), vec![0]);
        assert_eq!(Some(7u8).canon_bytes(), vec![1, 7]);
    }

    #[test]
    fn seq_keeps_order_and_counts() {
        let v = [3u8, 1, 2];
        let mut c = Canon::new();
        c.seq(v.iter());
        assert_eq!(c.as_bytes(), &[3, 0, 0, 0, 0, 0, 0, 0, 3, 1, 2]);
    }

    #[test]
    fn set_is_order_independent() {
        let mut a = Canon::new();
        a.set([3u8, 1, 2].iter());
        let mut b = Canon::new();
        b.set([2u8, 3, 1].iter());
        assert_eq!(a, b);
        assert_eq!(a.as_bytes(), &[3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3]);
    }

    #[test]
    fn set_orders_by_encoding_not_by_value_width() {
        // Strings sort by their length-prefixed encoding: shorter first,
        // then bytewise. "b" (len 1) precedes "aa" (len 2).
        let s: BTreeSet<String> = ["aa", "b"].iter().map(|s| s.to_string()).collect();
        let mut c = Canon::new();
        c.set(s.iter());
        let mut expect = Canon::new();
        expect.u64(2).str("b").str("aa");
        assert_eq!(c, expect);
    }

    #[test]
    fn map_is_a_set_of_pairs() {
        let mut m = BTreeMap::new();
        m.insert(2u8, 20u8);
        m.insert(1u8, 10u8);
        let mut expect = Canon::new();
        expect.u64(2).u8(1).u8(10).u8(2).u8(20);
        assert_eq!(m.canon_bytes(), expect.into_bytes());
    }
}
