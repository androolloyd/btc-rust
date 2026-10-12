/// SipHash-2-4 implementation (used for compact block short IDs)
pub(crate) fn siphash_2_4(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v0: u64 = k0 ^ 0x736f6d6570736575;
    let mut v1: u64 = k1 ^ 0x646f72616e646f6d;
    let mut v2: u64 = k0 ^ 0x6c7967656e657261;
    let mut v3: u64 = k1 ^ 0x7465646279746573;

    let blocks = data.len() / 8;
    let remainder = data.len() % 8;

    for i in 0..blocks {
        let m = u64::from_le_bytes(data[i * 8..(i + 1) * 8].try_into().unwrap());
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    let mut last: u64 = (data.len() as u64) << 56;
    for i in 0..remainder {
        last |= (data[blocks * 8 + i] as u64) << (i * 8);
    }

    v3 ^= last;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[inline]
pub(crate) fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[cfg(all(test, feature = "erlay"))]
mod tests {
    use super::*;

    #[test]
    fn unchanged_core_siphash_lengths_zero_through_sixty_three() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/bip330-sketches.json")).unwrap();
        for case in fixture["siphash"].as_array().unwrap() {
            assert_eq!(
                siphash_2_4(
                    case["k0"].as_u64().unwrap(),
                    case["k1"].as_u64().unwrap(),
                    &hex::decode(case["data"].as_str().unwrap()).unwrap()
                ),
                case["hash"].as_u64().unwrap()
            );
        }
    }
}
