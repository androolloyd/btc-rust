//! Bounded descriptor expansion. Origin annotations are unauthenticated.
use super::{Descriptor, DescriptorError, TapTree};
use crate::{
    bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey},
    hash160, sha256, taproot, Address, Network, Opcode, ScriptBuf,
};
use secp256k1::{PublicKey, XOnlyPublicKey};

#[derive(Debug, Clone)]
pub struct ExpandedTapLeaf {
    pub script: ScriptBuf,
    pub leaf_hash: [u8; 32],
    pub control_block: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DescriptorExpansion {
    pub script_pubkey: ScriptBuf,
    pub address: Option<Address>,
    pub redeem_script: Option<ScriptBuf>,
    pub witness_script: Option<ScriptBuf>,
    pub internal_key: Option<[u8; 32]>,
    pub merkle_root: Option<[u8; 32]>,
    pub tap_leaves: Vec<ExpandedTapLeaf>,
    pub is_ranged: bool,
    pub derivation_steps: usize,
}

/// A single resolved output, with a fixed public descriptor. This is not a
/// ranged descriptor export or an authenticated key-origin/ownership proof.
#[derive(Debug, Clone)]
pub struct PrivateDescriptorExpansion {
    pub expansion: DescriptorExpansion,
    pub public_descriptor: Descriptor,
}

#[derive(Clone, Copy, PartialEq)]
enum Context {
    Top,
    Sh,
    Wsh,
    Tap,
}

struct Expansion {
    private: bool,
    public_keys: Vec<String>,
    index: Option<u32>,
    network: Network,
    ranged: bool,
    steps: usize,
    keys: usize,
    redeem: Option<ScriptBuf>,
    witness: Option<ScriptBuf>,
    internal: Option<[u8; 32]>,
    root: Option<[u8; 32]>,
    leaves: Vec<ExpandedTapLeaf>,
}

fn error(message: &'static str) -> DescriptorError {
    DescriptorError::Expansion(message)
}
fn key_error(message: &'static str) -> DescriptorError {
    DescriptorError::InvalidKey(message.to_owned())
}

fn child(component: &str) -> Result<u32, DescriptorError> {
    let number = component.trim_end_matches(['h', '\'']);
    let hardened = number.len() != component.len();
    if number.is_empty()
        || !number.bytes().all(|b| b.is_ascii_digit())
        || component.len() - number.len() > 1
    {
        return Err(key_error("invalid derivation component"));
    }
    let index: u32 = number
        .parse()
        .map_err(|_| key_error("invalid derivation component"))?;
    if index >= 0x80000000 {
        return Err(key_error("child index exceeds BIP32 range"));
    }
    Ok(index | if hardened { 0x80000000 } else { 0 })
}

impl Descriptor {
    /// Expand a public descriptor at one wildcard index. This derives public
    /// scripts, not signing keys, authenticated origins or active-chain state.
    pub fn expand(
        &self,
        index: Option<u32>,
        network: Network,
    ) -> Result<DescriptorExpansion, DescriptorError> {
        self.expand_inner(index, network, false)
            .map(|result| result.0)
    }

    /// Resolve WIF/xprv/tprv and public keys at one index, including hardened
    /// private derivations. Returned data contains only public keys/scripts;
    /// origin annotations are omitted from the fixed resolved descriptor.
    pub fn expand_private(
        &self,
        index: Option<u32>,
        network: Network,
    ) -> Result<PrivateDescriptorExpansion, DescriptorError> {
        let (expansion, keys) = self.expand_inner(index, network, true)?;
        let mut keys = keys.into_iter();
        let public_descriptor = resolved_descriptor(self, &mut keys)?;
        if keys.next().is_some() {
            return Err(error("inconsistent resolved public keys"));
        }
        Ok(PrivateDescriptorExpansion {
            expansion,
            public_descriptor,
        })
    }

    fn expand_inner(
        &self,
        index: Option<u32>,
        network: Network,
        private: bool,
    ) -> Result<(DescriptorExpansion, Vec<String>), DescriptorError> {
        if index.is_some_and(|index| index >= 0x80000000) {
            return Err(error("wildcard index exceeds BIP32 range"));
        }
        let mut work = Expansion {
            private,
            public_keys: Vec::new(),
            index,
            network,
            ranged: false,
            steps: 0,
            keys: 0,
            redeem: None,
            witness: None,
            internal: None,
            root: None,
            leaves: Vec::new(),
        };
        let script_pubkey = work.script(self, Context::Top)?;
        if index.is_some() && !work.ranged {
            return Err(error("index supplied for a fixed descriptor"));
        }
        let address = address_for_script(&script_pubkey, network);
        Ok((
            DescriptorExpansion {
                script_pubkey,
                address,
                redeem_script: work.redeem,
                witness_script: work.witness,
                internal_key: work.internal,
                merkle_root: work.root,
                tap_leaves: work.leaves,
                is_ranged: work.ranged,
                derivation_steps: work.steps,
            },
            work.public_keys,
        ))
    }
}

impl Expansion {
    fn suffix(&mut self, parts: &[&str], depth: u8) -> Result<Vec<ChildNumber>, DescriptorError> {
        if depth as usize + parts.len() > 255 {
            return Err(key_error("derived depth exceeds BIP32 range"));
        }
        if self.steps + parts.len() > 10_000 {
            return Err(error("descriptor derivation work limit"));
        }
        let mut result = Vec::with_capacity(parts.len());
        for (position, component) in parts.iter().enumerate() {
            let number = if ["*", "*h", "*'"].contains(component) {
                if position + 1 != parts.len() {
                    return Err(key_error("wildcard must be final"));
                }
                self.ranged = true;
                self.index
                    .ok_or_else(|| error("ranged descriptor requires an index"))?
                    | if *component == "*" { 0 } else { 0x80000000 }
            } else {
                child(component)?
            };
            result.push(ChildNumber(number));
        }
        self.steps += parts.len();
        Ok(result)
    }

    fn key(&mut self, expression: &str, context: Context) -> Result<Vec<u8>, DescriptorError> {
        self.keys += 1;
        if self.keys > 1024 || expression.len() > 4096 {
            return Err(error("descriptor key limit"));
        }
        let mut expression = expression;
        if expression.starts_with('[') {
            let close = expression
                .find(']')
                .ok_or_else(|| key_error("unterminated origin"))?;
            let mut origin = expression[1..close].split('/');
            let fingerprint = origin.next().unwrap_or("");
            if fingerprint.len() != 8 || hex::decode(fingerprint).is_err() {
                return Err(key_error("invalid origin fingerprint"));
            }
            let path = origin.map(child).collect::<Result<Vec<_>, _>>()?;
            if path.len() > 255 {
                return Err(key_error("origin depth exceeds BIP32 range"));
            }
            expression = &expression[close + 1..];
        }
        let mut parts = expression.split('/');
        let base = parts.next().unwrap_or("");
        let bytes = if base.starts_with("xpub") || base.starts_with("tpub") {
            if base.len() > 112 {
                return Err(key_error("invalid extended public key length"));
            }
            let mut key = ExtendedPubKey::from_base58(base)
                .map_err(|_| key_error("invalid extended public key"))?;
            if (key.network == Network::Mainnet) != (self.network == Network::Mainnet) {
                return Err(key_error(
                    "extended public key version does not match selected network",
                ));
            }
            for number in self.suffix(&parts.collect::<Vec<_>>(), key.depth)? {
                if number.is_hardened() {
                    return Err(error(
                        "hardened derivation requires private keys and is unsupported",
                    ));
                }
                key = key
                    .derive_child(number)
                    .map_err(|_| key_error("invalid public child derivation"))?;
            }
            key.public_key.serialize().to_vec()
        } else if self.private && (base.starts_with("xprv") || base.starts_with("tprv")) {
            if base.len() > 112 {
                return Err(key_error("invalid extended private key length"));
            }
            let mut key = ExtendedPrivKey::from_base58(base)
                .map_err(|_| key_error("invalid extended private key"))?;
            if (key.network == Network::Mainnet) != (self.network == Network::Mainnet) {
                return Err(key_error(
                    "extended private key version does not match selected network",
                ));
            }
            for number in self.suffix(&parts.collect::<Vec<_>>(), key.depth)? {
                key = key
                    .derive_child(number)
                    .map_err(|_| key_error("invalid private child derivation"))?;
            }
            key.public_key().serialize().to_vec()
        } else if self.private && [51, 52].contains(&base.len()) {
            if parts.next().is_some() {
                return Err(key_error("suffix requires an extended key"));
            }
            crate::wif::WifPrivateKey::from_wif(base, self.network)
                .map_err(|_| key_error("invalid WIF private key or selected network"))?
                .public_key()
        } else {
            if parts.next().is_some() {
                return Err(key_error("suffix requires an extended public key"));
            }
            // Never echo possible private material in diagnostics.
            if ![64, 66, 130].contains(&base.len()) {
                return Err(key_error(
                    "only public hex keys or xpub/tpub keys are supported",
                ));
            }
            hex::decode(base)
                .map_err(|_| key_error("only public hex keys or xpub/tpub keys are supported"))?
        };
        if context == Context::Tap {
            let xonly = match bytes.len() {
                32 => XOnlyPublicKey::from_slice(&bytes)
                    .map_err(|_| key_error("invalid x-only public key"))?,
                33 => {
                    PublicKey::from_slice(&bytes)
                        .map_err(|_| key_error("invalid public key"))?
                        .x_only_public_key()
                        .0
                }
                _ => return Err(key_error("uncompressed keys are forbidden in Taproot")),
            };
            let bytes = xonly.serialize().to_vec();
            if self.private {
                self.public_keys.push(hex::encode(&bytes));
            }
            return Ok(bytes);
        }
        if bytes.len() != 33 && bytes.len() != 65 {
            return Err(key_error("invalid public key encoding"));
        }
        PublicKey::from_slice(&bytes).map_err(|_| key_error("invalid curve public key"))?;
        if context == Context::Wsh && bytes.len() != 33 {
            return Err(key_error("witness keys must be compressed"));
        }
        if self.private {
            self.public_keys.push(hex::encode(&bytes));
        }
        Ok(bytes)
    }

    fn script(
        &mut self,
        descriptor: &Descriptor,
        context: Context,
    ) -> Result<ScriptBuf, DescriptorError> {
        match descriptor {
            Descriptor::Pk(key) => {
                let key = self.key(key, context)?;
                let mut script = ScriptBuf::new();
                script.push_slice(&key);
                script.push_opcode(Opcode::OP_CHECKSIG);
                Ok(script)
            }
            Descriptor::Pkh(key) if context != Context::Tap => {
                Ok(ScriptBuf::p2pkh(&hash160(&self.key(key, context)?)))
            }
            Descriptor::Wpkh(key) if context == Context::Top || context == Context::Sh => {
                Ok(ScriptBuf::p2wpkh(&hash160(&self.key(key, Context::Wsh)?)))
            }
            Descriptor::Sh(inner) if context == Context::Top => {
                let script = self.script(inner, Context::Sh)?;
                if script.as_bytes().len() > 520 {
                    return Err(error("P2SH redeem script exceeds 520 bytes"));
                }
                let result = ScriptBuf::p2sh(&hash160(script.as_bytes()));
                self.redeem = Some(script);
                Ok(result)
            }
            Descriptor::Wsh(inner) if context == Context::Top || context == Context::Sh => {
                let script = self.script(inner, Context::Wsh)?;
                let result = ScriptBuf::p2wsh(&sha256(script.as_bytes()));
                self.witness = Some(script);
                Ok(result)
            }
            Descriptor::Multi(threshold, keys) | Descriptor::SortedMulti(threshold, keys)
                if context != Context::Tap =>
            {
                let maximum = if context == Context::Top { 3 } else { 20 };
                if *threshold == 0 || *threshold as usize > keys.len() || keys.len() > maximum {
                    return Err(error(
                        "invalid multisig threshold/key count for this context",
                    ));
                }
                let mut keys = keys
                    .iter()
                    .map(|key| self.key(key, context))
                    .collect::<Result<Vec<_>, _>>()?;
                if matches!(descriptor, Descriptor::SortedMulti(..)) {
                    keys.sort();
                }
                let mut script = ScriptBuf::new();
                push_number(&mut script, *threshold);
                for key in &keys {
                    script.push_slice(key);
                }
                push_number(&mut script, keys.len() as u32);
                script.push_opcode(Opcode::OP_CHECKMULTISIG);
                Ok(script)
            }
            Descriptor::MultiA(threshold, keys) | Descriptor::SortedMultiA(threshold, keys)
                if context == Context::Tap =>
            {
                // BIP387's cap leaves room for the first key push under
                // BIP342's 1000-element stack limit.
                if *threshold == 0 || *threshold as usize > keys.len() || keys.len() > 999 {
                    return Err(error(
                        "invalid Taproot threshold/key count (maximum 999 keys)",
                    ));
                }
                let mut keys = keys
                    .iter()
                    .map(|key| self.key(key, Context::Tap))
                    .collect::<Result<Vec<_>, _>>()?;
                if matches!(descriptor, Descriptor::SortedMultiA(..)) {
                    keys.sort();
                }
                let mut script = ScriptBuf::new();
                for (index, key) in keys.iter().enumerate() {
                    script.push_slice(key);
                    script.push_opcode(if index == 0 {
                        Opcode::OP_CHECKSIG
                    } else {
                        Opcode::OP_CHECKSIGADD
                    });
                }
                push_number(&mut script, *threshold);
                script.push_opcode(Opcode::OP_NUMEQUAL);
                Ok(script)
            }
            Descriptor::Tr(key, tree) if context == Context::Top => {
                let internal: [u8; 32] =
                    self.key(key, Context::Tap)?.try_into().expect("x-only key");
                let root = tree
                    .as_ref()
                    .map(|tree| self.tree(tree, 0).map(|value| value.0))
                    .transpose()?;
                let (output, parity) = taproot::output_key(&internal, root.as_ref())
                    .map_err(|_| key_error("invalid Taproot tweak"))?;
                self.internal = Some(internal);
                self.root = root;
                for leaf in &mut self.leaves {
                    let mut control = vec![0xc0 | parity];
                    control.extend_from_slice(&internal);
                    control.extend_from_slice(&leaf.control_block);
                    leaf.control_block = control;
                }
                Ok(ScriptBuf::p2tr(&output))
            }
            Descriptor::Addr(text) if context == Context::Top => {
                if text.len() > 128 {
                    return Err(error("invalid address length"));
                }
                let address = Address::from_base58(text, self.network)
                    .or_else(|_| Address::from_bech32(text, self.network))
                    .map_err(|_| {
                        error("invalid address for selected network or unsupported witness version")
                    })?;
                Ok(address.script_pubkey())
            }
            Descriptor::Raw(text) if context == Context::Top => {
                if text.len() > 20_000 {
                    return Err(error("raw script exceeds 10000 bytes"));
                }
                Ok(ScriptBuf::from_bytes(hex::decode(text).map_err(|_| {
                    DescriptorError::InvalidHex("invalid script hex".to_owned())
                })?))
            }
            _ => Err(DescriptorError::UnsupportedScriptPubkey),
        }
    }

    fn tree(
        &mut self,
        tree: &TapTree,
        depth: usize,
    ) -> Result<([u8; 32], std::ops::Range<usize>), DescriptorError> {
        if depth > 128 {
            return Err(error("Taproot tree exceeds depth 128"));
        }
        let start = self.leaves.len();
        let hash = match tree {
            TapTree::Leaf(expression) => {
                if self.leaves.len() >= 1024 {
                    return Err(error("Taproot leaf limit"));
                }
                if expression.contains('#') {
                    return Err(error("checksum is only permitted at descriptor top level"));
                }
                let descriptor = Descriptor::parse(expression)
                    .map_err(|_| error("invalid Taproot leaf descriptor"))?;
                // General Miniscript remains unsupported.
                if !matches!(
                    descriptor,
                    Descriptor::Pk(_) | Descriptor::MultiA(..) | Descriptor::SortedMultiA(..)
                ) {
                    return Err(DescriptorError::UnsupportedScriptPubkey);
                }
                let script = self.script(&descriptor, Context::Tap)?;
                let hash = taproot::tap_leaf_hash(0xc0, script.as_bytes());
                self.leaves.push(ExpandedTapLeaf {
                    script,
                    leaf_hash: hash,
                    control_block: Vec::new(),
                });
                hash
            }
            TapTree::Branch(left, right) => {
                let (left_hash, left_range) = self.tree(left, depth + 1)?;
                let (right_hash, right_range) = self.tree(right, depth + 1)?;
                for index in left_range {
                    self.leaves[index]
                        .control_block
                        .extend_from_slice(&right_hash);
                }
                for index in right_range {
                    self.leaves[index]
                        .control_block
                        .extend_from_slice(&left_hash);
                }
                taproot::tap_branch_hash(&left_hash, &right_hash)
            }
        };
        Ok((hash, start..self.leaves.len()))
    }
}

// Walk in precisely the compiler's key order: internal key before Taproot
// leaves and left subtree before right. No private expression is copied into
// the returned descriptor, including its leaf-expression strings.
fn resolved_descriptor(
    descriptor: &Descriptor,
    keys: &mut impl Iterator<Item = String>,
) -> Result<Descriptor, DescriptorError> {
    let mut next = || {
        keys.next()
            .ok_or_else(|| error("missing resolved public key"))
    };
    Ok(match descriptor {
        Descriptor::Pk(_) => Descriptor::Pk(next()?),
        Descriptor::Pkh(_) => Descriptor::Pkh(next()?),
        Descriptor::Wpkh(_) => Descriptor::Wpkh(next()?),
        Descriptor::Sh(inner) => Descriptor::Sh(Box::new(resolved_descriptor(inner, keys)?)),
        Descriptor::Wsh(inner) => Descriptor::Wsh(Box::new(resolved_descriptor(inner, keys)?)),
        Descriptor::Tr(_, tree) => Descriptor::Tr(
            next()?,
            tree.as_ref()
                .map(|tree| resolved_tree(tree, keys).map(Box::new))
                .transpose()?,
        ),
        Descriptor::Multi(k, old) => {
            Descriptor::Multi(*k, old.iter().map(|_| next()).collect::<Result<_, _>>()?)
        }
        Descriptor::SortedMulti(k, old) => {
            Descriptor::SortedMulti(*k, old.iter().map(|_| next()).collect::<Result<_, _>>()?)
        }
        Descriptor::MultiA(k, old) => {
            Descriptor::MultiA(*k, old.iter().map(|_| next()).collect::<Result<_, _>>()?)
        }
        Descriptor::SortedMultiA(k, old) => {
            Descriptor::SortedMultiA(*k, old.iter().map(|_| next()).collect::<Result<_, _>>()?)
        }
        Descriptor::Addr(text) => Descriptor::Addr(text.clone()),
        Descriptor::Raw(text) => Descriptor::Raw(text.clone()),
    })
}

fn resolved_tree(
    tree: &TapTree,
    keys: &mut impl Iterator<Item = String>,
) -> Result<TapTree, DescriptorError> {
    Ok(match tree {
        TapTree::Leaf(text) => TapTree::Leaf(
            resolved_descriptor(
                &Descriptor::parse(text).map_err(|_| error("invalid Taproot leaf descriptor"))?,
                keys,
            )?
            .to_string(),
        ),
        TapTree::Branch(left, right) => TapTree::Branch(
            Box::new(resolved_tree(left, keys)?),
            Box::new(resolved_tree(right, keys)?),
        ),
    })
}

fn push_number(script: &mut ScriptBuf, value: u32) {
    // Positive thresholds use minimal signed-magnitude script numbers,
    // including the sign-padding byte at 128 and 32768.
    if value <= 16 {
        script.push_opcode(Opcode::from_u8(0x50 + value as u8));
    } else {
        let mut value = value;
        let mut bytes = Vec::new();
        while value != 0 {
            bytes.push(value as u8);
            value >>= 8;
        }
        if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
            bytes.push(0);
        }
        script.push_slice(&bytes);
    }
}

fn address_for_script(script: &ScriptBuf, network: Network) -> Option<Address> {
    let bytes = script.as_bytes();
    if script.is_p2pkh() {
        Some(Address::P2pkh {
            hash: bytes[3..23].try_into().ok()?,
            network,
        })
    } else if script.is_p2sh() {
        Some(Address::P2sh {
            hash: bytes[2..22].try_into().ok()?,
            network,
        })
    } else if script.is_p2wpkh() {
        Some(Address::P2wpkh {
            hash: bytes[2..22].try_into().ok()?,
            network,
        })
    } else if script.is_p2wsh() {
        Some(Address::P2wsh {
            hash: bytes[2..34].try_into().ok()?,
            network,
        })
    } else if script.is_p2tr() {
        Some(Address::P2tr {
            output_key: bytes[2..34].try_into().ok()?,
            network,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn published_private_descriptor_scripts_and_public_only_resolution() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/private-descriptors.json")).unwrap();
        assert_eq!(fixture["vectors"].as_array().unwrap().len(), 28);
        let mut count = 0;
        for vector in fixture["vectors"].as_array().unwrap() {
            let text = vector["descriptor"].as_str().unwrap();
            let descriptor = Descriptor::parse(text).unwrap();
            // The old public resolver must continue rejecting private material.
            assert!(descriptor
                .expand(text.contains('*').then_some(0), Network::Mainnet)
                .is_err());
            for (i, expected) in vector["scripts"].as_array().unwrap().iter().enumerate() {
                let resolved = descriptor
                    .expand_private(text.contains('*').then_some(i as u32), Network::Mainnet)
                    .unwrap();
                let expansion = &resolved.expansion;
                assert_eq!(
                    hex::encode(expansion.script_pubkey.as_bytes()),
                    expected.as_str().unwrap()
                );
                assert_eq!(expansion.is_ranged, text.contains('*'));
                let public = resolved.public_descriptor.to_string();
                assert!(!public.contains("prv") && !public.contains('[') && !public.contains('*'));
                let reparsed = Descriptor::parse(&public)
                    .unwrap()
                    .expand(None, Network::Mainnet)
                    .unwrap();
                assert_eq!(reparsed.script_pubkey, expansion.script_pubkey);
                assert_eq!(reparsed.redeem_script, expansion.redeem_script);
                assert_eq!(reparsed.witness_script, expansion.witness_script);
                assert_eq!(reparsed.tap_leaves.len(), expansion.tap_leaves.len());
                for (a, b) in reparsed.tap_leaves.iter().zip(&expansion.tap_leaves) {
                    assert_eq!(a.script, b.script);
                    assert_eq!(a.control_block, b.control_block);
                }
                count += 1;
            }
        }
        assert_eq!(count, 37);
    }

    #[test]
    fn private_derivation_network_depth_work_and_wif_context_bounds() {
        let compressed = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1";
        let uncompressed = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";
        let mut root = ExtendedPrivKey::from_seed(&[1; 32], Network::Mainnet).unwrap();
        let xprv = root.to_base58();
        let public = root.to_extended_pub_key().to_base58();
        for text in [
            format!("wpkh({uncompressed})"),
            format!("tr({uncompressed})"),
            format!("wsh(pk({uncompressed}))"),
            format!("pk({compressed}/0)"),
            format!("pk({xprv}/*h/0)"),
            format!("pk({public}/*h)"),
            format!("pk({xprv}/2147483648)"),
            format!("pk({xprv}/0hh)"),
            format!("pk({xprv}/<0;1>)"),
        ] {
            assert!(Descriptor::parse(&text)
                .unwrap()
                .expand_private(Some(0), Network::Mainnet)
                .is_err());
        }
        for key in [compressed, uncompressed, &xprv] {
            assert!(Descriptor::Pk(key.to_owned())
                .expand_private(None, Network::Regtest)
                .is_err());
        }
        for suffix in ["/0h/1/*h", "/0'/1/*'"] {
            let desc = Descriptor::Wpkh(format!("{xprv}{suffix}"));
            let result = desc
                .expand_private(Some(0x7fffffff), Network::Mainnet)
                .unwrap();
            assert_eq!(result.expansion.derivation_steps, 3);
            let child = root
                .derive_child(ChildNumber(0x80000000))
                .unwrap()
                .derive_child(ChildNumber(1))
                .unwrap()
                .derive_child(ChildNumber(0xffffffff))
                .unwrap();
            assert_eq!(
                result.public_descriptor,
                Descriptor::Wpkh(hex::encode(child.public_key().serialize()))
            );
            assert!(desc.expand_private(None, Network::Mainnet).is_err());
            assert!(desc
                .expand_private(Some(0x80000000), Network::Mainnet)
                .is_err());
        }
        root.depth = 254;
        let desc = Descriptor::Wpkh(format!("{}/0h/*", root.to_base58()));
        assert!(desc.expand_private(Some(0), Network::Mainnet).is_err());
        root.depth = 255;
        assert!(Descriptor::Wpkh(root.to_base58())
            .expand_private(None, Network::Mainnet)
            .is_ok());
        root.network = Network::Testnet;
        let desc = Descriptor::Wpkh(root.to_base58());
        assert!(desc.expand_private(None, Network::Mainnet).is_err());
        for network in [
            Network::Regtest,
            Network::Testnet,
            Network::Signet,
            Network::Testnet4,
        ] {
            assert!(desc.expand_private(None, network).is_ok());
        }
        let steps = "/0".repeat(200);
        let keys = vec![format!("{xprv}{steps}"); 51];
        let desc = Descriptor::Tr(
            KEY.to_owned(),
            Some(Box::new(TapTree::Leaf(
                Descriptor::MultiA(1, keys).to_string(),
            ))),
        );
        assert!(desc
            .expand_private(None, Network::Mainnet)
            .unwrap_err()
            .to_string()
            .contains("work limit"));
    }

    #[test]
    fn published_public_descriptor_scripts_match_exactly() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/descriptors.json")).unwrap();
        let vectors = fixture["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 20);
        let mut count = 0;
        for vector in vectors {
            let text = vector["descriptor"].as_str().unwrap();
            let descriptor = Descriptor::parse(text).unwrap();
            for (index, expected) in vector["scripts"].as_array().unwrap().iter().enumerate() {
                let index = text.contains('*').then_some(index as u32);
                let expanded = descriptor.expand(index, Network::Mainnet).unwrap();
                assert_eq!(
                    hex::encode(expanded.script_pubkey.as_bytes()),
                    expected.as_str().unwrap(),
                    "{text} {index:?}"
                );
                if index.is_none() {
                    assert_eq!(descriptor.script_pubkey().unwrap(), expanded.script_pubkey);
                }
                count += 1;
            }
        }
        assert_eq!(count, 24);
    }

    #[test]
    fn core_threshold_descriptor_commitments_and_context_bounds() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/taproot-thresholds.json")).unwrap();
        for vector in fixture["published"].as_array().unwrap() {
            let text = vector["descriptor"].as_str().unwrap();
            for (i, expected) in vector["scripts"].as_array().unwrap().iter().enumerate() {
                let expanded = Descriptor::parse(text)
                    .unwrap()
                    .expand(text.contains('*').then_some(i as u32), Network::Mainnet)
                    .unwrap();
                assert_eq!(
                    hex::encode(expanded.script_pubkey.as_bytes()),
                    expected.as_str().unwrap()
                );
            }
        }
        for vector in fixture["descriptors"].as_array().unwrap() {
            let text = vector["descriptor"].as_str().unwrap();
            let parsed = Descriptor::parse(text).unwrap();
            assert_eq!(parsed.to_string(), text);
            let expanded = parsed.expand(None, Network::Mainnet).unwrap();
            assert_eq!(
                hex::encode(expanded.script_pubkey.as_bytes()),
                vector["script_pubkey"]
            );
            let leaf = &expanded.tap_leaves[0];
            assert_eq!(hex::encode(leaf.script.as_bytes()), vector["script"]);
            assert_eq!(hex::encode(&leaf.control_block), vector["control"]);
            assert_eq!(hex::encode(leaf.leaf_hash), vector["leaf_hash"]);
        }
        for leaf in [
            format!("multi_a(1,{KEY})"),
            format!("sortedmulti_a(1,{KEY})"),
        ] {
            for text in [leaf.clone(), format!("wsh({leaf})"), format!("sh({leaf})")] {
                assert!(Descriptor::parse(&text).unwrap().script_pubkey().is_err());
            }
        }
        let excessive = Descriptor::MultiA(999, vec![KEY.to_owned(); 1000]);
        let mut work = Expansion {
            private: false,
            public_keys: Vec::new(),
            index: None,
            network: Network::Mainnet,
            ranged: false,
            steps: 0,
            keys: 0,
            redeem: None,
            witness: None,
            internal: None,
            root: None,
            leaves: Vec::new(),
        };
        assert!(work.script(&excessive, Context::Tap).is_err());
        assert!(Descriptor::Tr(
            KEY.to_owned(),
            Some(Box::new(TapTree::Leaf(format!("multi_a(0,{KEY})"))))
        )
        .script_pubkey()
        .is_err());
    }

    #[test]
    fn invalid_keys_contexts_origins_and_ranges_fail_without_output() {
        let uncompressed = "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235";
        let xpub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";
        for text in [
            "pk(aa)".to_owned(),
            "pkh(aa)".to_owned(),
            format!("wpkh({uncompressed})"),
            format!("wsh(pk({uncompressed}))"),
            format!("tr({uncompressed})"),
            format!("sh(sh(pk({KEY})))"),
            format!("wsh(wpkh({KEY}))"),
            format!("wsh(wsh(pk({KEY})))"),
            format!("sh(tr({KEY}))"),
            format!("tr({KEY},multi(1,{KEY}))"),
            format!("wpkh({KEY}/*)"),
            format!("pk([abcdefg0]{KEY})"),
            format!("pk([12345678/+1]{KEY})"),
            format!("pk([12345678/2147483648]{KEY})"),
            format!("pk({xpub}/0h)"),
            format!("pk({xpub}/*/0)"),
            format!("pk({xpub}/2147483648)"),
            format!("pk({xpub}/*h)"),
            format!("pk({xpub}/0//1)"),
            "pk(02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)".to_owned(),
        ] {
            let descriptor = Descriptor::parse(&text).unwrap();
            for index in [None, Some(1)] {
                assert!(
                    descriptor.expand(index, Network::Mainnet).is_err(),
                    "{text} {index:?}"
                );
            }
        }
        assert!(Descriptor::parse(&format!("wpkh({xpub}/*)"))
            .unwrap()
            .expand(None, Network::Mainnet)
            .is_err());
        assert!(Descriptor::parse(&format!("wpkh({xpub})"))
            .unwrap()
            .expand(None, Network::Regtest)
            .is_err());
        assert!(Descriptor::parse(&format!("wpkh({xpub})"))
            .unwrap()
            .expand(None, Network::Mainnet)
            .is_ok());
        assert!(Descriptor::parse(&format!("wpkh({KEY})"))
            .unwrap()
            .expand(Some(0), Network::Regtest)
            .is_err());
        assert!(Descriptor::parse(&format!("wpkh({xpub}/*)"))
            .unwrap()
            .expand(Some(0x80000000), Network::Mainnet)
            .is_err());
        // Secret-looking input must not appear in diagnostics.
        let secret = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1";
        let failure = Descriptor::Pk(secret.to_owned())
            .script_pubkey()
            .unwrap_err()
            .to_string();
        assert!(!failure.contains(secret));
    }

    #[test]
    fn descriptor_multisig_limits_depend_on_actual_serialized_script() {
        let multi = |n: usize, k| Descriptor::Multi(k, vec![KEY.to_owned(); n]);
        assert!(multi(4, 1).script_pubkey().is_err());
        assert!(multi(3, 0).script_pubkey().is_err());
        assert!(Descriptor::Sh(Box::new(multi(15, 1)))
            .script_pubkey()
            .is_ok());
        assert!(Descriptor::Sh(Box::new(multi(16, 1)))
            .script_pubkey()
            .is_err());
        assert!(Descriptor::Wsh(Box::new(multi(20, 17)))
            .script_pubkey()
            .is_ok());
        assert!(Descriptor::Wsh(Box::new(multi(21, 17)))
            .script_pubkey()
            .is_err());
        let expanded = Descriptor::Sh(Box::new(Descriptor::Wsh(Box::new(multi(20, 17)))))
            .expand(None, Network::Regtest)
            .unwrap();
        let witness = expanded.witness_script.unwrap();
        assert_eq!(&witness.as_bytes()[..2], &[1, 17]);
        assert_eq!(
            &witness.as_bytes()[witness.as_bytes().len() - 3..],
            &[1, 20, 0xae]
        );
        assert_eq!(expanded.redeem_script.unwrap().as_bytes().len(), 34);
    }

    #[test]
    fn descriptor_parser_and_taproot_depth_are_bounded() {
        for text in [
            "multi(1,])",
            "tr(key,{pk(key),pk(key))})",
            "pk(key))",
            "pk(é)",
        ] {
            assert!(Descriptor::parse(text).is_err());
        }
        assert!(
            Descriptor::parse(&format!("{}pk(key){}", "sh(".repeat(133), ")".repeat(133))).is_err()
        );
        assert!(Descriptor::parse(&format!("raw({})", "00".repeat(131073))).is_err());
        let leaf = format!("pk({KEY})");
        let mut tree = leaf.clone();
        for _ in 0..128 {
            tree = format!("{{{leaf},{tree}}}");
        }
        let text = format!("tr({KEY},{tree})");
        let expanded = Descriptor::parse(&text)
            .unwrap()
            .expand(None, Network::Regtest)
            .unwrap();
        assert_eq!(expanded.tap_leaves.len(), 129);
        assert_eq!(
            expanded.tap_leaves.last().unwrap().control_block.len(),
            33 + 128 * 32
        );
        let excessive = format!("tr({KEY},{{{leaf},{tree}}})");
        assert!(Descriptor::parse(&excessive)
            .unwrap()
            .expand(None, Network::Regtest)
            .is_err());
        let mut model = TapTree::Leaf(leaf.clone());
        for _ in 0..129 {
            model = TapTree::Branch(Box::new(TapTree::Leaf(leaf.clone())), Box::new(model));
        }
        assert!(Descriptor::Tr(KEY.to_owned(), Some(Box::new(model)))
            .script_pubkey()
            .is_err());
        let bip32: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/bip32-keys.json")).unwrap();
        let root = bip32["valid_keys"][0]["xpub"].as_str().unwrap();
        let expensive_leaf = format!("pk({root}{})", "/0".repeat(255));
        let mut expensive = expensive_leaf.clone();
        for _ in 0..40 {
            expensive = format!("{{{expensive_leaf},{expensive}}}");
        }
        let failure = Descriptor::parse(&format!("tr({KEY},{expensive})"))
            .unwrap()
            .expand(None, Network::Mainnet)
            .unwrap_err();
        assert!(failure.to_string().contains("work limit"));
    }
}
