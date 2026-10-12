#![no_main]
use btc_primitives::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use btc_primitives::{Address, Network};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 {
        return;
    }
    let text = std::str::from_utf8(data).ok();
    if let Some(text) = text {
        for network in [Network::Mainnet, Network::Regtest] {
            if let Ok(address) = Address::from_base58(text, network) {
                assert_eq!(address.to_base58().unwrap(), text);
            }
        }
    }
    let public_text = text.and_then(|text| ExtendedPubKey::from_base58(text).ok());
    let private_text = text.and_then(|text| ExtendedPrivKey::from_base58(text).ok());
    let raw = data.get(..78);
    let index = data
        .get(78..82)
        .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
        .unwrap_or(0);
    let children = [
        ChildNumber(index),
        ChildNumber(0x7fffffff),
        ChildNumber(0x80000000),
    ];
    if let Some(public) =
        public_text.or_else(|| raw.and_then(|raw| ExtendedPubKey::deserialize(raw).ok()))
    {
        if let Some(text) = text.filter(|text| ExtendedPubKey::from_base58(text).is_ok()) {
            assert_eq!(public.to_base58(), text);
        } else {
            assert_eq!(public.serialize().as_slice(), raw.unwrap());
        }
        let before = public.serialize();
        for child in children {
            if let Ok(derived) = public.derive_child(child) {
                assert!(!child.is_hardened());
                assert_eq!(derived.depth, public.depth + 1);
                assert_eq!(derived.child_number, child);
                assert_eq!(
                    ExtendedPubKey::deserialize(&derived.serialize())
                        .unwrap()
                        .serialize(),
                    derived.serialize()
                );
            }
        }
        assert_eq!(public.serialize(), before);
    }
    if let Some(private) =
        private_text.or_else(|| raw.and_then(|raw| ExtendedPrivKey::deserialize(raw).ok()))
    {
        if let Some(text) = text.filter(|text| ExtendedPrivKey::from_base58(text).is_ok()) {
            assert_eq!(private.to_base58(), text);
        } else {
            assert_eq!(private.serialize().as_slice(), raw.unwrap());
        }
        let before = private.serialize();
        for child in children {
            let result = private.derive_child(child);
            if !child.is_hardened() {
                let public = private.to_extended_pub_key().derive_child(child);
                assert_eq!(result.is_ok(), public.is_ok());
                if let (Ok(private), Ok(public)) = (&result, public) {
                    assert_eq!(
                        private.to_extended_pub_key().serialize(),
                        public.serialize()
                    );
                }
            }
            if let Ok(derived) = result {
                assert_eq!(derived.depth, private.depth + 1);
                assert_eq!(derived.child_number, child);
                assert_eq!(
                    ExtendedPrivKey::deserialize(&derived.serialize())
                        .unwrap()
                        .serialize(),
                    derived.serialize()
                );
            }
        }
        assert_eq!(private.serialize(), before);
    }
});
