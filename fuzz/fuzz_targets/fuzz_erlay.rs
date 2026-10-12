#![no_main]

use std::collections::HashSet;

use btc_network::erlay::{Minisketch, SketchError, MAX_CAPACITY};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_CAPACITY * 4 + 4 {
        return;
    }
    // Arbitrary received bytes, including all reference successes and failures.
    if let Ok(received) = Minisketch::deserialize(data) {
        assert_eq!(received.serialize(), data);
        if let Ok(elements) = received.decode() {
            assert!(elements.len() <= received.capacity());
            assert!(elements.iter().all(|element| *element != 0));
            assert!(elements.windows(2).all(|pair| pair[0] < pair[1]));
            let mut reconstructed = Minisketch::new(received.capacity()).unwrap();
            for element in elements {
                reconstructed.add(element).unwrap();
            }
            assert_eq!(reconstructed, received);
        }
        let mut zero = received.clone();
        zero.merge(&received).unwrap();
        assert!(zero.is_zero());
        assert_eq!(zero.decode().unwrap(), Vec::<u32>::new());
    }
    // A separate parity oracle for constructed, within-capacity differences.
    // This checks complete recovery, rather than accepting any self-roundtrip.
    let mut expected = HashSet::new();
    let mut elements = Vec::new();
    for bytes in data.chunks_exact(4).take(16) {
        let element = u32::from_le_bytes(bytes.try_into().unwrap());
        if element != 0 {
            elements.push(element);
            if !expected.insert(element) {
                expected.remove(&element);
            }
        }
    }
    let capacity = expected.len().max(1);
    let mut left = Minisketch::new(capacity).unwrap();
    let mut right = Minisketch::new(capacity).unwrap();
    for (i, element) in elements.into_iter().enumerate() {
        if i & 1 == 0 {
            left.add(element).unwrap();
        } else {
            right.add(element).unwrap();
        }
    }
    let right = Minisketch::deserialize(&right.serialize()).unwrap();
    let mut expected = expected.into_iter().collect::<Vec<_>>();
    expected.sort_unstable();
    assert_eq!(left.decode_differences(&right).unwrap(), expected);
    let saved = left.clone();
    assert_eq!(left.add(0), Err(SketchError::ZeroElement));
    assert_eq!(left, saved);
    let other = Minisketch::new(capacity + 1).unwrap();
    assert_eq!(left.merge(&other), Err(SketchError::CapacityMismatch));
    assert_eq!(left, saved);
});
