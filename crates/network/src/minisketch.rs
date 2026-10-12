//! BIP330's 32-bit PinSketch, with bounded, set-independent decoding.
//!
//! The field modulus is x^32 + x^7 + x^3 + x^2 + 1. Only odd power sums
//! are retained; serialization is exactly four little-endian bytes per slot.
//! No original set, cardinality, or sender-local state is kept here.
//!
//! The decoding algorithms are adapted from Pieter Wuille's MIT-licensed
//! minisketch reference (tests/pyminisketch.py at a12f5de1c96e21d76f64bc647ae4f65e4fc1b636).
//! Copyright (c) 2020 Pieter Wuille
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in
//! all copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//! THE SOFTWARE.

/// Local work limit, not a BIP330 protocol limit. Larger sketches are unsupported.
pub const MAX_CAPACITY: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SketchError {
    #[error("sketch capacity exceeds the local limit of 64")]
    Capacity,
    #[error("sketch must contain exactly four bytes per slot")]
    Encoding,
    #[error("zero is not a valid sketch element")]
    ZeroElement,
    #[error("sketch capacities differ")]
    CapacityMismatch,
    #[error("sketch could not be decoded within capacity")]
    Decode,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Minisketch {
    odd_sums: Vec<u32>,
}

impl Minisketch {
    pub fn new(capacity: usize) -> Result<Self, SketchError> {
        if capacity > MAX_CAPACITY {
            return Err(SketchError::Capacity);
        }
        Ok(Self {
            odd_sums: vec![0; capacity],
        })
    }

    pub fn capacity(&self) -> usize {
        self.odd_sums.len()
    }

    /// Toggle an element. Adding it twice cancels it, as required for XOR merge.
    pub fn add(&mut self, mut element: u32) -> Result<(), SketchError> {
        if element == 0 {
            return Err(SketchError::ZeroElement);
        }
        let squared = mul(element, element);
        for sum in &mut self.odd_sums {
            *sum ^= element;
            element = mul(element, squared);
        }
        Ok(())
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.odd_sums
            .iter()
            .flat_map(|sum| sum.to_le_bytes())
            .collect()
    }

    /// Capacity is inferred from the BIP330 skdata byte array's exact length.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, SketchError> {
        if bytes.len() % 4 != 0 {
            return Err(SketchError::Encoding);
        }
        let mut sketch = Self::new(bytes.len() / 4)?;
        for (sum, bytes) in sketch.odd_sums.iter_mut().zip(bytes.chunks_exact(4)) {
            *sum = u32::from_le_bytes(bytes.try_into().expect("four-byte chunk"));
        }
        Ok(sketch)
    }

    /// Atomic on mismatched capacities; no invented padding or capacity growth.
    pub fn merge(&mut self, other: &Self) -> Result<(), SketchError> {
        if self.capacity() != other.capacity() {
            return Err(SketchError::CapacityMismatch);
        }
        for (sum, other) in self.odd_sums.iter_mut().zip(&other.odd_sums) {
            *sum ^= other;
        }
        Ok(())
    }

    pub fn is_zero(&self) -> bool {
        self.odd_sums.iter().all(|sum| *sum == 0)
    }

    pub fn decode_differences(&self, other: &Self) -> Result<Vec<u32>, SketchError> {
        let mut difference = self.clone();
        difference.merge(other)?;
        difference.decode()
    }

    /// Recover sorted nonzero elements from the syndromes alone.
    ///
    /// Guaranteed only when the actual difference fits capacity. Oversized sets
    /// can alias smaller sets (even an empty set); success does not prove that
    /// the sender's original set was recovered. BIP330 requires normal INV/tx
    /// validation and flooding fallback, not a consensus claim from this result.
    pub fn decode(&self) -> Result<Vec<u32>, SketchError> {
        if self.is_zero() {
            return Ok(Vec::new());
        }
        let mut syndromes = vec![0; 2 * self.capacity()];
        for (i, &sum) in self.odd_sums.iter().enumerate() {
            syndromes[2 * i] = sum;
            syndromes[2 * i + 1] = mul(syndromes[i], syndromes[i]);
        }
        let mut polynomial = berlekamp_massey(&syndromes);
        if polynomial.len() <= 1 || polynomial.len() > self.capacity() + 1 {
            return Err(SketchError::Decode);
        }
        // Reverse the error locator: its roots become elements, not inverses.
        polynomial.reverse();
        let mut roots = find_roots(polynomial).ok_or(SketchError::Decode)?;
        roots.sort_unstable();
        if roots.contains(&0) || roots.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(SketchError::Decode);
        }
        // Never return factors that fail to reproduce ALL received syndromes.
        let mut check = Self::new(self.capacity())?;
        for &root in &roots {
            check.add(root)?;
        }
        if check != *self {
            return Err(SketchError::Decode);
        }
        Ok(roots)
    }
}

fn mul(mut a: u32, mut b: u32) -> u32 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        a = (a << 1) ^ if a & 0x8000_0000 != 0 { 0x8d } else { 0 };
        b >>= 1;
    }
    product
}

fn inverse(value: u32) -> u32 {
    debug_assert_ne!(value, 0);
    // value^(2^32-2), a fixed 31-step addition chain.
    let mut result = value;
    for _ in 0..30 {
        result = mul(mul(result, result), value);
    }
    mul(result, result)
}

fn berlekamp_massey(syndromes: &[u32]) -> Vec<u32> {
    let mut current = vec![1];
    let mut previous = vec![1];
    let mut previous_inverse = 1;
    for (n, &sum) in syndromes.iter().enumerate() {
        let mut discrepancy = sum;
        for i in 1..current.len() {
            discrepancy ^= mul(syndromes[n - i], current[i]);
        }
        if discrepancy == 0 {
            continue;
        }
        let shift = n + 3 - current.len() - previous.len();
        let grows = 2 * (current.len() - 1) <= n;
        let saved = grows.then(|| current.clone());
        let scale = mul(discrepancy, previous_inverse);
        current.resize(current.len().max(previous.len() + shift), 0);
        for (i, &coefficient) in previous.iter().enumerate() {
            current[i + shift] ^= mul(scale, coefficient);
        }
        if let Some(saved) = saved {
            previous = saved;
            previous_inverse = inverse(discrepancy);
        }
    }
    current
}

fn trim(poly: &mut Vec<u32>) {
    while poly.last() == Some(&0) {
        poly.pop();
    }
}

fn monic(mut poly: Vec<u32>) -> Vec<u32> {
    let scale = inverse(*poly.last().expect("nonzero polynomial"));
    for coefficient in &mut poly {
        *coefficient = mul(*coefficient, scale);
    }
    poly
}

/// Polynomial long division by a monic modulus; coefficients are low to high.
fn divide(mut poly: Vec<u32>, modulus: &[u32]) -> (Vec<u32>, Vec<u32>) {
    debug_assert_eq!(modulus.last(), Some(&1));
    let mut quotient = vec![0; (poly.len() + 1).saturating_sub(modulus.len())];
    while poly.len() >= modulus.len() {
        let offset = poly.len() - modulus.len();
        let coefficient = poly.pop().expect("nonzero modulus length");
        quotient[offset] = coefficient;
        for i in 0..modulus.len() - 1 {
            poly[offset + i] ^= mul(coefficient, modulus[i]);
        }
        trim(&mut poly);
    }
    trim(&mut quotient);
    (quotient, poly)
}

fn square_mod(poly: &[u32], modulus: &[u32]) -> Vec<u32> {
    if poly.is_empty() {
        return Vec::new();
    }
    let mut squared = vec![0; 2 * poly.len() - 1];
    for (i, &coefficient) in poly.iter().enumerate() {
        squared[2 * i] = mul(coefficient, coefficient);
    }
    divide(squared, modulus).1
}

fn gcd(mut a: Vec<u32>, mut b: Vec<u32>) -> Vec<u32> {
    while !b.is_empty() {
        b = monic(b);
        let remainder = divide(a, &b).1;
        a = b;
        b = remainder;
    }
    monic(a)
}

fn trace_mod(poly: &[u32], parameter: u32) -> Vec<u32> {
    let mut trace = vec![0, parameter];
    for _ in 0..31 {
        trace = square_mod(&trace, poly);
        trace.resize(trace.len().max(2), 0);
        trace[1] ^= parameter;
        trim(&mut trace);
    }
    trace
}

fn find_roots(poly: Vec<u32>) -> Option<Vec<u32>> {
    let degree = poly.len().checked_sub(1)?;
    if degree == 0 || poly.last() != Some(&1) {
        return None;
    }
    if degree > 1 {
        // x^(2^32) - x contains every field element exactly once. Divisibility
        // rejects repeated roots and irreducible factors before splitting.
        let mut frobenius = vec![0, 1];
        for _ in 0..32 {
            frobenius = square_mod(&frobenius, &poly);
        }
        if frobenius != [0, 1] {
            return None;
        }
    }
    let mut pending = vec![poly];
    let mut roots = Vec::with_capacity(degree);
    while let Some(poly) = pending.pop() {
        if poly.len() == 2 {
            roots.push(poly[0]);
            continue;
        }
        let mut split = None;
        // The 32 basis traces separate every pair of distinct field elements.
        // A deterministic bounded search avoids retry loops driven by input.
        for bit in 0..32 {
            let factor = gcd(poly.clone(), trace_mod(&poly, 1 << bit));
            if factor.len() > 1 && factor.len() < poly.len() {
                let (other, remainder) = divide(poly.clone(), &factor);
                if !remainder.is_empty() {
                    return None;
                }
                split = Some((factor, other));
                break;
            }
        }
        let (factor, other) = split?;
        pending.push(factor);
        pending.push(other);
    }
    (roots.len() == degree).then_some(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_field_arithmetic() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/bip330-sketches.json")).unwrap();
        for case in fixture["arithmetic"].as_array().unwrap() {
            let a = case["a"].as_u64().unwrap() as u32;
            let b = case["b"].as_u64().unwrap() as u32;
            assert_eq!(mul(a, b), case["product"].as_u64().unwrap() as u32);
            assert_eq!(inverse(a), case["inverse"].as_u64().unwrap() as u32);
            assert_eq!(mul(a, inverse(a)), 1);
        }
    }
}
