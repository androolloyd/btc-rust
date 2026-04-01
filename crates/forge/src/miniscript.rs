//! Miniscript policy-to-script compiler.
//!
//! Implements the Miniscript policy language and compiles policies down to
//! Bitcoin Script ([`ScriptBuf`]). The module provides two layers:
//!
//! - [`Policy`] — high-level spending policies (key, timelock, hashlock,
//!   boolean combinators, thresholds).
//! - [`Miniscript`] — low-level compiled fragments that map directly to
//!   Bitcoin Script patterns, following the full Miniscript specification.
//!
//! Policies are first converted to an optimal Miniscript fragment via
//! [`Policy::to_miniscript()`], then compiled to Bitcoin Script via
//! [`Miniscript::compile()`].

use btc_primitives::script::{Opcode, ScriptBuf};
use thiserror::Error;

/// Errors that can occur during miniscript parsing or compilation.
#[derive(Debug, Error)]
pub enum MiniscriptError {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("expected '{0}' but found '{1}'")]
    Expected(String, String),
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("invalid number: {0}")]
    InvalidNumber(String),
    #[error("unknown policy function: {0}")]
    UnknownPolicy(String),
    #[error("thresh requires k >= 1 and k <= number of sub-policies")]
    InvalidThreshold,
    #[error("thresh requires at least one sub-policy")]
    EmptyThresh,
    #[error("trailing input after policy: {0}")]
    TrailingInput(String),
}

// ===========================================================================
// Miniscript fragments
// ===========================================================================

/// Miniscript fragment -- the compiled form of a policy.
///
/// These map directly to Bitcoin Script patterns as defined by the Miniscript
/// specification. Each variant documents the script pattern it compiles to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Miniscript {
    // -- Basic key checks --------------------------------------------------

    /// `<key> OP_CHECKSIG`
    Pk(Vec<u8>),
    /// `OP_DUP OP_HASH160 <hash160(key)> OP_EQUALVERIFY OP_CHECKSIG`
    PkH(Vec<u8>),
    /// `k <key1> ... <keyn> n OP_CHECKMULTISIG`
    Multi(u32, Vec<Vec<u8>>),

    // -- Hashlocks ---------------------------------------------------------

    /// `OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL`
    Sha256(Vec<u8>),
    /// `OP_SIZE <32> OP_EQUALVERIFY OP_HASH256 <hash> OP_EQUAL`
    Hash256(Vec<u8>),
    /// `OP_SIZE <32> OP_EQUALVERIFY OP_RIPEMD160 <hash> OP_EQUAL`
    Ripemd160(Vec<u8>),
    /// `OP_SIZE <32> OP_EQUALVERIFY OP_HASH160 <hash> OP_EQUAL`
    Hash160(Vec<u8>),

    // -- Timelocks ---------------------------------------------------------

    /// `<n> OP_CHECKLOCKTIMEVERIFY`
    After(u32),
    /// `<n> OP_CHECKSEQUENCEVERIFY`
    Older(u32),

    // -- Combinators -------------------------------------------------------

    /// `[X] [Y]` (verify-wrapped left, expression right)
    AndV(Box<Miniscript>, Box<Miniscript>),
    /// `[X] [Y] OP_BOOLAND`
    AndB(Box<Miniscript>, Box<Miniscript>),
    /// `[X] [Y] OP_BOOLOR`
    OrB(Box<Miniscript>, Box<Miniscript>),
    /// `[X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF`
    OrD(Box<Miniscript>, Box<Miniscript>),
    /// `[X] OP_NOTIF [Y] OP_ENDIF`
    OrC(Box<Miniscript>, Box<Miniscript>),
    /// `OP_IF [X] OP_ELSE [Y] OP_ENDIF`
    OrI(Box<Miniscript>, Box<Miniscript>),

    // -- Thresholds --------------------------------------------------------

    /// `[X1] [X2] OP_ADD ... [Xn] OP_ADD <k> OP_EQUAL`
    Thresh(u32, Vec<Miniscript>),

    // -- Wrappers ----------------------------------------------------------

    /// `[X] OP_VERIFY`
    Verify(Box<Miniscript>),
    /// `OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF`
    NonZero(Box<Miniscript>),
}

impl Miniscript {
    /// Compile this Miniscript fragment to Bitcoin Script.
    pub fn compile(&self) -> ScriptBuf {
        let mut buf = ScriptBuf::new();
        self.compile_into(&mut buf);
        buf
    }

    /// Compile into an existing script buffer.
    fn compile_into(&self, buf: &mut ScriptBuf) {
        match self {
            // -- Basic --
            Miniscript::Pk(key) => {
                buf.push_slice(key);
                buf.push_opcode(Opcode::OP_CHECKSIG);
            }
            Miniscript::PkH(key_hash) => {
                buf.push_opcode(Opcode::OP_DUP);
                buf.push_opcode(Opcode::OP_HASH160);
                buf.push_slice(key_hash);
                buf.push_opcode(Opcode::OP_EQUALVERIFY);
                buf.push_opcode(Opcode::OP_CHECKSIG);
            }
            Miniscript::Multi(k, keys) => {
                push_script_number(buf, *k as i64);
                for key in keys {
                    buf.push_slice(key);
                }
                push_script_number(buf, keys.len() as i64);
                buf.push_opcode(Opcode::OP_CHECKMULTISIG);
            }

            // -- Hashlocks --
            Miniscript::Sha256(hash) => {
                buf.push_opcode(Opcode::OP_SIZE);
                push_script_number(buf, 32);
                buf.push_opcode(Opcode::OP_EQUALVERIFY);
                buf.push_opcode(Opcode::OP_SHA256);
                buf.push_slice(hash);
                buf.push_opcode(Opcode::OP_EQUAL);
            }
            Miniscript::Hash256(hash) => {
                buf.push_opcode(Opcode::OP_SIZE);
                push_script_number(buf, 32);
                buf.push_opcode(Opcode::OP_EQUALVERIFY);
                buf.push_opcode(Opcode::OP_HASH256);
                buf.push_slice(hash);
                buf.push_opcode(Opcode::OP_EQUAL);
            }
            Miniscript::Ripemd160(hash) => {
                buf.push_opcode(Opcode::OP_SIZE);
                push_script_number(buf, 32);
                buf.push_opcode(Opcode::OP_EQUALVERIFY);
                buf.push_opcode(Opcode::OP_RIPEMD160);
                buf.push_slice(hash);
                buf.push_opcode(Opcode::OP_EQUAL);
            }
            Miniscript::Hash160(hash) => {
                buf.push_opcode(Opcode::OP_SIZE);
                push_script_number(buf, 32);
                buf.push_opcode(Opcode::OP_EQUALVERIFY);
                buf.push_opcode(Opcode::OP_HASH160);
                buf.push_slice(hash);
                buf.push_opcode(Opcode::OP_EQUAL);
            }

            // -- Timelocks --
            Miniscript::After(n) => {
                push_script_number(buf, *n as i64);
                buf.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
            }
            Miniscript::Older(n) => {
                push_script_number(buf, *n as i64);
                buf.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
            }

            // -- Combinators --
            Miniscript::AndV(x, y) => {
                x.compile_into(buf);
                y.compile_into(buf);
            }
            Miniscript::AndB(x, y) => {
                x.compile_into(buf);
                y.compile_into(buf);
                buf.push_opcode(Opcode::OP_BOOLAND);
            }
            Miniscript::OrB(x, y) => {
                x.compile_into(buf);
                y.compile_into(buf);
                buf.push_opcode(Opcode::OP_BOOLOR);
            }
            Miniscript::OrD(x, y) => {
                x.compile_into(buf);
                buf.push_opcode(Opcode::OP_IFDUP);
                buf.push_opcode(Opcode::OP_NOTIF);
                y.compile_into(buf);
                buf.push_opcode(Opcode::OP_ENDIF);
            }
            Miniscript::OrC(x, y) => {
                x.compile_into(buf);
                buf.push_opcode(Opcode::OP_NOTIF);
                y.compile_into(buf);
                buf.push_opcode(Opcode::OP_ENDIF);
            }
            Miniscript::OrI(x, y) => {
                buf.push_opcode(Opcode::OP_IF);
                x.compile_into(buf);
                buf.push_opcode(Opcode::OP_ELSE);
                y.compile_into(buf);
                buf.push_opcode(Opcode::OP_ENDIF);
            }

            // -- Threshold --
            Miniscript::Thresh(k, subs) => {
                for (i, sub) in subs.iter().enumerate() {
                    sub.compile_into(buf);
                    if i > 0 {
                        buf.push_opcode(Opcode::OP_ADD);
                    }
                }
                push_script_number(buf, *k as i64);
                buf.push_opcode(Opcode::OP_EQUAL);
            }

            // -- Wrappers --
            Miniscript::Verify(x) => {
                x.compile_into(buf);
                buf.push_opcode(Opcode::OP_VERIFY);
            }
            Miniscript::NonZero(x) => {
                buf.push_opcode(Opcode::OP_SIZE);
                buf.push_opcode(Opcode::OP_0NOTEQUAL);
                buf.push_opcode(Opcode::OP_IF);
                x.compile_into(buf);
                buf.push_opcode(Opcode::OP_ENDIF);
            }
        }
    }

    /// Estimate the maximum witness size (in bytes) to satisfy this fragment.
    ///
    /// This counts the total serialized size of all witness stack items needed
    /// in the worst case (largest satisfaction path). Each item is counted as
    /// 1 byte for the length prefix + the item data bytes.
    pub fn max_satisfaction_witness_size(&self) -> usize {
        match self {
            // Pk: signature (72 bytes max DER + 1 sighash) => 1 + 73
            Miniscript::Pk(_) => 1 + 73,
            // PkH: signature + pubkey => (1+73) + (1+33)
            Miniscript::PkH(_) => 1 + 73 + 1 + 33,
            // Multi: OP_0 dummy + k signatures => 1 + k * (1+73)
            Miniscript::Multi(k, _) => 1 + (*k as usize) * (1 + 73),
            // Hashlocks: 32-byte preimage => 1 + 32
            Miniscript::Sha256(_) | Miniscript::Hash256(_) |
            Miniscript::Ripemd160(_) | Miniscript::Hash160(_) => 1 + 32,
            // Timelocks: no witness items (locktime checked by interpreter)
            Miniscript::After(_) | Miniscript::Older(_) => 0,
            // And: both branches must be satisfied
            Miniscript::AndV(x, y) | Miniscript::AndB(x, y) => {
                x.max_satisfaction_witness_size() + y.max_satisfaction_witness_size()
            }
            // Or: worst-case branch + 1 byte for the selector
            Miniscript::OrB(x, y) => {
                x.max_satisfaction_witness_size() + y.max_satisfaction_witness_size()
            }
            Miniscript::OrD(x, y) | Miniscript::OrC(x, y) => {
                let sx = x.max_satisfaction_witness_size();
                let sy = y.max_satisfaction_witness_size();
                std::cmp::max(sx, sy)
            }
            Miniscript::OrI(x, y) => {
                // 1 byte for the OP_IF selector + worst-case branch
                1 + std::cmp::max(
                    x.max_satisfaction_witness_size(),
                    y.max_satisfaction_witness_size(),
                )
            }
            // Thresh: worst case is satisfying k items, dissatisfying the rest
            // Conservative: sum all sub-witness sizes
            Miniscript::Thresh(_, subs) => {
                subs.iter().map(|s| s.max_satisfaction_witness_size()).sum()
            }
            // Wrappers pass through
            Miniscript::Verify(x) => x.max_satisfaction_witness_size(),
            Miniscript::NonZero(x) => x.max_satisfaction_witness_size(),
        }
    }

    /// Estimate the compiled script size in bytes.
    pub fn script_size(&self) -> usize {
        self.compile().len()
    }

    /// Check if this fragment is "safe" -- no hidden spending paths that
    /// could allow third-party malleability or bypass intended conditions.
    ///
    /// A fragment is considered safe if:
    /// - It requires at least one signature check (preventing arbitrary
    ///   third parties from satisfying it).
    /// - It does not contain only timelocks or hashlocks without a key check.
    pub fn is_safe(&self) -> bool {
        self.requires_signature()
    }

    /// Returns true if satisfying this fragment requires providing at least
    /// one cryptographic signature.
    fn requires_signature(&self) -> bool {
        match self {
            Miniscript::Pk(_) | Miniscript::PkH(_) | Miniscript::Multi(_, _) => true,
            Miniscript::Sha256(_) | Miniscript::Hash256(_) |
            Miniscript::Ripemd160(_) | Miniscript::Hash160(_) => false,
            Miniscript::After(_) | Miniscript::Older(_) => false,
            // And: at least one branch requires sig
            Miniscript::AndV(x, y) | Miniscript::AndB(x, y) => {
                x.requires_signature() || y.requires_signature()
            }
            // Or: both branches must require sig (either path could be taken)
            Miniscript::OrB(x, y) | Miniscript::OrD(x, y) |
            Miniscript::OrC(x, y) | Miniscript::OrI(x, y) => {
                x.requires_signature() && y.requires_signature()
            }
            Miniscript::Thresh(k, subs) => {
                // Safe if even the weakest k subs all require a signature.
                // Count how many subs do NOT require a signature.
                let no_sig_count = subs.iter().filter(|s| !s.requires_signature()).count();
                // If there are fewer non-sig subs than k, then every possible
                // k-subset must include at least one sig-requiring sub.
                no_sig_count < *k as usize
            }
            Miniscript::Verify(x) | Miniscript::NonZero(x) => x.requires_signature(),
        }
    }
}

// ===========================================================================
// Policy
// ===========================================================================

/// A spending policy that can be compiled to Bitcoin Script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// Require a signature for the given key (hex-encoded public key).
    /// Compiles to: `<KEY> OP_CHECKSIG`
    Key(String),
    /// Absolute timelock. Compiles to: `<N> OP_CHECKLOCKTIMEVERIFY OP_DROP`
    After(u32),
    /// Relative timelock. Compiles to: `<N> OP_CHECKSEQUENCEVERIFY OP_DROP`
    Older(u32),
    /// SHA-256 hash preimage check.
    /// Compiles to: `OP_SHA256 <H> OP_EQUAL`
    Sha256(String),
    /// Both sub-policies must be satisfied.
    /// Compiles to: `compile(A) compile(B)`
    And(Box<Policy>, Box<Policy>),
    /// Either sub-policy may be satisfied.
    /// Compiles to: `OP_IF compile(A) OP_ELSE compile(B) OP_ENDIF`
    Or(Box<Policy>, Box<Policy>),
    /// Threshold: at least `k` of the listed sub-policies must be satisfied.
    /// For key-only sub-policies this compiles to a classic multisig.
    Thresh(usize, Vec<Policy>),
}

impl Policy {
    /// Compile this policy into a Bitcoin Script.
    ///
    /// This uses the legacy direct compilation path for backwards
    /// compatibility. For the full Miniscript pipeline, use
    /// [`to_miniscript()`](Self::to_miniscript) followed by
    /// [`Miniscript::compile()`].
    pub fn compile(&self) -> ScriptBuf {
        let mut script = ScriptBuf::new();
        self.compile_into(&mut script);
        script
    }

    /// Compile into an existing script buffer (used for concatenation).
    fn compile_into(&self, buf: &mut ScriptBuf) {
        match self {
            Policy::Key(key_hex) => {
                let key_bytes = hex::decode(key_hex).unwrap_or_default();
                buf.push_slice(&key_bytes);
                buf.push_opcode(Opcode::OP_CHECKSIG);
            }
            Policy::After(n) => {
                push_script_number(buf, *n as i64);
                buf.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
                buf.push_opcode(Opcode::OP_DROP);
            }
            Policy::Older(n) => {
                push_script_number(buf, *n as i64);
                buf.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
                buf.push_opcode(Opcode::OP_DROP);
            }
            Policy::Sha256(hash_hex) => {
                buf.push_opcode(Opcode::OP_SHA256);
                let hash_bytes = hex::decode(hash_hex).unwrap_or_default();
                buf.push_slice(&hash_bytes);
                buf.push_opcode(Opcode::OP_EQUAL);
            }
            Policy::And(a, b) => {
                a.compile_into(buf);
                b.compile_into(buf);
            }
            Policy::Or(a, b) => {
                buf.push_opcode(Opcode::OP_IF);
                a.compile_into(buf);
                buf.push_opcode(Opcode::OP_ELSE);
                b.compile_into(buf);
                buf.push_opcode(Opcode::OP_ENDIF);
            }
            Policy::Thresh(k, subs) => {
                // If all sub-policies are keys, emit classic OP_CHECKMULTISIG
                let all_keys = subs.iter().all(|p| matches!(p, Policy::Key(_)));
                if all_keys && !subs.is_empty() {
                    push_script_number(buf, *k as i64);
                    for sub in subs {
                        if let Policy::Key(key_hex) = sub {
                            let key_bytes = hex::decode(key_hex).unwrap_or_default();
                            buf.push_slice(&key_bytes);
                        }
                    }
                    push_script_number(buf, subs.len() as i64);
                    buf.push_opcode(Opcode::OP_CHECKMULTISIG);
                } else {
                    // General threshold: compile each sub-policy, then use
                    // OP_ADD to sum the boolean results and compare to k.
                    for (i, sub) in subs.iter().enumerate() {
                        sub.compile_into(buf);
                        if i > 0 {
                            buf.push_opcode(Opcode::OP_ADD);
                        }
                    }
                    push_script_number(buf, *k as i64);
                    buf.push_opcode(Opcode::OP_EQUAL);
                }
            }
        }
    }

    /// Convert this policy to the optimal Miniscript fragment.
    ///
    /// This maps each policy construct to the most appropriate Miniscript
    /// fragment type:
    /// - `Key` -> `Pk`
    /// - `After` -> `After` (fragment)
    /// - `Older` -> `Older` (fragment)
    /// - `Sha256` -> `Sha256` (fragment with size check)
    /// - `And` -> `AndV` (concatenation-based AND)
    /// - `Or` -> `OrI` (IF/ELSE-based OR)
    /// - `Thresh` (all keys) -> `Multi`
    /// - `Thresh` (general) -> `Thresh` (fragment)
    pub fn to_miniscript(&self) -> Miniscript {
        match self {
            Policy::Key(key_hex) => {
                let key_bytes = hex::decode(key_hex).unwrap_or_default();
                Miniscript::Pk(key_bytes)
            }
            Policy::After(n) => Miniscript::After(*n),
            Policy::Older(n) => Miniscript::Older(*n),
            Policy::Sha256(hash_hex) => {
                let hash_bytes = hex::decode(hash_hex).unwrap_or_default();
                Miniscript::Sha256(hash_bytes)
            }
            Policy::And(a, b) => {
                let ma = a.to_miniscript();
                let mb = b.to_miniscript();
                Miniscript::AndV(Box::new(ma), Box::new(mb))
            }
            Policy::Or(a, b) => {
                let ma = a.to_miniscript();
                let mb = b.to_miniscript();
                Miniscript::OrI(Box::new(ma), Box::new(mb))
            }
            Policy::Thresh(k, subs) => {
                let all_keys = subs.iter().all(|p| matches!(p, Policy::Key(_)));
                if all_keys && !subs.is_empty() {
                    let keys: Vec<Vec<u8>> = subs
                        .iter()
                        .map(|p| {
                            if let Policy::Key(hex) = p {
                                hex::decode(hex).unwrap_or_default()
                            } else {
                                unreachable!()
                            }
                        })
                        .collect();
                    Miniscript::Multi(*k as u32, keys)
                } else {
                    let ms: Vec<Miniscript> =
                        subs.iter().map(|p| p.to_miniscript()).collect();
                    Miniscript::Thresh(*k as u32, ms)
                }
            }
        }
    }

    /// Parse a policy string such as `"and(pk(ab01),after(100))"`.
    pub fn parse(s: &str) -> Result<Self, MiniscriptError> {
        let s = s.trim();
        let (policy, rest) = parse_policy(s)?;
        let rest = rest.trim();
        if !rest.is_empty() {
            return Err(MiniscriptError::TrailingInput(rest.to_string()));
        }
        Ok(policy)
    }
}

// ---------------------------------------------------------------------------
// Parser internals
// ---------------------------------------------------------------------------

/// Parse a single policy from the front of `input`, returning the policy and
/// the remaining unparsed input.
fn parse_policy(input: &str) -> Result<(Policy, &str), MiniscriptError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(MiniscriptError::UnexpectedEof);
    }

    // Find the function name (everything up to the first '(')
    let open = input.find('(').ok_or_else(|| {
        MiniscriptError::Expected("(".to_string(), input.to_string())
    })?;
    let name = input[..open].trim();
    let after_open = &input[open + 1..];

    match name {
        "pk" => {
            let (arg, rest) = read_until_close(after_open)?;
            let key = arg.trim().to_string();
            Ok((Policy::Key(key), rest))
        }
        "after" => {
            let (arg, rest) = read_until_close(after_open)?;
            let n: u32 = arg
                .trim()
                .parse()
                .map_err(|_| MiniscriptError::InvalidNumber(arg.trim().to_string()))?;
            Ok((Policy::After(n), rest))
        }
        "older" => {
            let (arg, rest) = read_until_close(after_open)?;
            let n: u32 = arg
                .trim()
                .parse()
                .map_err(|_| MiniscriptError::InvalidNumber(arg.trim().to_string()))?;
            Ok((Policy::Older(n), rest))
        }
        "sha256" => {
            let (arg, rest) = read_until_close(after_open)?;
            let hash = arg.trim().to_string();
            // Validate hex
            hex::decode(&hash)
                .map_err(|e| MiniscriptError::InvalidHex(e.to_string()))?;
            Ok((Policy::Sha256(hash), rest))
        }
        "and" => {
            let (a, rest_a) = parse_policy(after_open)?;
            let rest_a = rest_a.trim_start();
            let rest_a = rest_a
                .strip_prefix(',')
                .ok_or_else(|| MiniscriptError::Expected(",".to_string(), rest_a.to_string()))?;
            let (b, rest_b) = parse_policy(rest_a)?;
            let rest_b = rest_b.trim_start();
            let rest_b = rest_b
                .strip_prefix(')')
                .ok_or_else(|| MiniscriptError::Expected(")".to_string(), rest_b.to_string()))?;
            Ok((Policy::And(Box::new(a), Box::new(b)), rest_b))
        }
        "or" => {
            let (a, rest_a) = parse_policy(after_open)?;
            let rest_a = rest_a.trim_start();
            let rest_a = rest_a
                .strip_prefix(',')
                .ok_or_else(|| MiniscriptError::Expected(",".to_string(), rest_a.to_string()))?;
            let (b, rest_b) = parse_policy(rest_a)?;
            let rest_b = rest_b.trim_start();
            let rest_b = rest_b
                .strip_prefix(')')
                .ok_or_else(|| MiniscriptError::Expected(")".to_string(), rest_b.to_string()))?;
            Ok((Policy::Or(Box::new(a), Box::new(b)), rest_b))
        }
        "thresh" => {
            // thresh(k, sub1, sub2, ...)
            // First argument is the threshold number
            let (k_str, rest_k) = read_until_comma(after_open)?;
            let k: usize = k_str
                .trim()
                .parse()
                .map_err(|_| MiniscriptError::InvalidNumber(k_str.trim().to_string()))?;

            let mut subs = Vec::new();
            let mut remaining = rest_k;
            loop {
                let (sub, rest_sub) = parse_policy(remaining)?;
                subs.push(sub);
                let rest_sub = rest_sub.trim_start();
                if let Some(r) = rest_sub.strip_prefix(',') {
                    remaining = r;
                } else if let Some(r) = rest_sub.strip_prefix(')') {
                    remaining = r;
                    break;
                } else {
                    return Err(MiniscriptError::Expected(
                        ", or )".to_string(),
                        rest_sub.to_string(),
                    ));
                }
            }

            if subs.is_empty() {
                return Err(MiniscriptError::EmptyThresh);
            }
            if k < 1 || k > subs.len() {
                return Err(MiniscriptError::InvalidThreshold);
            }

            Ok((Policy::Thresh(k, subs), remaining))
        }
        other => Err(MiniscriptError::UnknownPolicy(other.to_string())),
    }
}

/// Read characters until we find the matching closing ')' at depth 0,
/// returning the content inside and the remaining input after ')'.
fn read_until_close(input: &str) -> Result<(&str, &str), MiniscriptError> {
    let mut depth = 0usize;
    for (i, ch) in input.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' if depth == 0 => {
                return Ok((&input[..i], &input[i + 1..]));
            }
            ')' => depth -= 1,
            _ => {}
        }
    }
    Err(MiniscriptError::Expected(")".to_string(), input.to_string()))
}

/// Read characters until we find a comma at depth 0.
/// Returns the content before the comma and the remaining input after the comma.
fn read_until_comma(input: &str) -> Result<(&str, &str), MiniscriptError> {
    let mut depth = 0usize;
    for (i, ch) in input.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    return Err(MiniscriptError::Expected(
                        ",".to_string(),
                        input[i..].to_string(),
                    ));
                }
                depth -= 1;
            }
            ',' if depth == 0 => {
                return Ok((&input[..i], &input[i + 1..]));
            }
            _ => {}
        }
    }
    Err(MiniscriptError::Expected(",".to_string(), input.to_string()))
}

// ---------------------------------------------------------------------------
// Script number encoding helpers
// ---------------------------------------------------------------------------

/// Push an integer onto the script using minimal CScriptNum encoding.
fn push_script_number(buf: &mut ScriptBuf, n: i64) {
    if n == 0 {
        buf.push_opcode(Opcode::OP_0);
    } else if n == -1 {
        buf.push_opcode(Opcode::OP_1NEGATE);
    } else if (1..=16).contains(&n) {
        buf.push_opcode(Opcode::from_u8(0x50 + n as u8));
    } else {
        let bytes = encode_script_num(n);
        buf.push_slice(&bytes);
    }
}

/// Encode an integer as a Bitcoin CScriptNum (minimal byte encoding).
fn encode_script_num(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }

    let negative = n < 0;
    let mut abs = if negative { -(n as i128) } else { n as i128 } as u64;

    let mut result = Vec::new();
    while abs > 0 {
        result.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    if result.last().map_or(false, |b| b & 0x80 != 0) {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = result.last_mut().unwrap();
        *last |= 0x80;
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::script::Instruction;

    /// Helper: disassemble a script into a list of instruction summaries.
    fn disasm(script: &ScriptBuf) -> Vec<String> {
        script
            .as_script()
            .instructions()
            .map(|r| match r.unwrap() {
                Instruction::Op(op) => format!("{:?}", op),
                Instruction::PushBytes(data) => format!("PUSH({})", hex::encode(data)),
            })
            .collect()
    }

    // ===================================================================
    // Policy parsing tests
    // ===================================================================

    #[test]
    fn parse_pk() {
        let p = Policy::parse("pk(deadbeef)").unwrap();
        assert_eq!(p, Policy::Key("deadbeef".to_string()));
    }

    #[test]
    fn parse_after() {
        let p = Policy::parse("after(100)").unwrap();
        assert_eq!(p, Policy::After(100));
    }

    #[test]
    fn parse_older() {
        let p = Policy::parse("older(144)").unwrap();
        assert_eq!(p, Policy::Older(144));
    }

    #[test]
    fn parse_sha256() {
        let h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let p = Policy::parse(&format!("sha256({})", h)).unwrap();
        assert_eq!(p, Policy::Sha256(h.to_string()));
    }

    #[test]
    fn parse_and() {
        let p = Policy::parse("and(pk(aa),after(50))").unwrap();
        assert_eq!(
            p,
            Policy::And(
                Box::new(Policy::Key("aa".to_string())),
                Box::new(Policy::After(50)),
            )
        );
    }

    #[test]
    fn parse_or() {
        let p = Policy::parse("or(pk(aa),pk(bb))").unwrap();
        assert_eq!(
            p,
            Policy::Or(
                Box::new(Policy::Key("aa".to_string())),
                Box::new(Policy::Key("bb".to_string())),
            )
        );
    }

    #[test]
    fn parse_thresh() {
        let p = Policy::parse("thresh(2,pk(aa),pk(bb),pk(cc))").unwrap();
        assert_eq!(
            p,
            Policy::Thresh(
                2,
                vec![
                    Policy::Key("aa".to_string()),
                    Policy::Key("bb".to_string()),
                    Policy::Key("cc".to_string()),
                ]
            )
        );
    }

    #[test]
    fn parse_nested() {
        let p = Policy::parse("and(or(pk(aa),pk(bb)),after(100))").unwrap();
        assert_eq!(
            p,
            Policy::And(
                Box::new(Policy::Or(
                    Box::new(Policy::Key("aa".to_string())),
                    Box::new(Policy::Key("bb".to_string())),
                )),
                Box::new(Policy::After(100)),
            )
        );
    }

    #[test]
    fn parse_error_trailing_input() {
        let result = Policy::parse("pk(aa)trailing");
        assert!(result.is_err());
    }

    #[test]
    fn parse_error_unknown_function() {
        let result = Policy::parse("unknown(aa)");
        assert!(result.is_err());
    }

    #[test]
    fn parse_error_invalid_number() {
        let result = Policy::parse("after(abc)");
        assert!(result.is_err());
    }

    // ===================================================================
    // Policy compilation tests (legacy path)
    // ===================================================================

    #[test]
    fn compile_pk() {
        let p = Policy::Key("deadbeef".to_string());
        let asm = disasm(&p.compile());
        assert_eq!(asm, vec!["PUSH(deadbeef)", "OP_CHECKSIG"]);
    }

    #[test]
    fn compile_after() {
        let p = Policy::After(100);
        let asm = disasm(&p.compile());
        assert_eq!(
            asm,
            vec!["PUSH(64)", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP"]
        );
    }

    #[test]
    fn compile_after_small() {
        // Values 1-16 should use OP_1..OP_16
        let p = Policy::After(5);
        let asm = disasm(&p.compile());
        assert_eq!(asm, vec!["OP_5", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP"]);
    }

    #[test]
    fn compile_older() {
        let p = Policy::Older(144);
        let asm = disasm(&p.compile());
        assert_eq!(
            asm,
            vec!["PUSH(9000)", "OP_CHECKSEQUENCEVERIFY", "OP_DROP"]
        );
    }

    #[test]
    fn compile_sha256() {
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let p = Policy::Sha256(hash.to_string());
        let asm = disasm(&p.compile());
        assert_eq!(asm[0], "OP_SHA256");
        assert_eq!(asm[1], format!("PUSH({})", hash));
        assert_eq!(asm[2], "OP_EQUAL");
        assert_eq!(asm.len(), 3);
    }

    #[test]
    fn compile_and() {
        let p = Policy::And(
            Box::new(Policy::Key("aa".to_string())),
            Box::new(Policy::After(10)),
        );
        let asm = disasm(&p.compile());
        assert_eq!(
            asm,
            vec![
                "PUSH(aa)",
                "OP_CHECKSIG",
                "OP_10",
                "OP_CHECKLOCKTIMEVERIFY",
                "OP_DROP",
            ]
        );
    }

    #[test]
    fn compile_or() {
        let p = Policy::Or(
            Box::new(Policy::Key("aa".to_string())),
            Box::new(Policy::Key("bb".to_string())),
        );
        let asm = disasm(&p.compile());
        assert_eq!(
            asm,
            vec![
                "OP_IF",
                "PUSH(aa)",
                "OP_CHECKSIG",
                "OP_ELSE",
                "PUSH(bb)",
                "OP_CHECKSIG",
                "OP_ENDIF",
            ]
        );
    }

    #[test]
    fn compile_thresh_multisig() {
        let p = Policy::Thresh(
            2,
            vec![
                Policy::Key("aa".to_string()),
                Policy::Key("bb".to_string()),
                Policy::Key("cc".to_string()),
            ],
        );
        let asm = disasm(&p.compile());
        assert_eq!(
            asm,
            vec![
                "OP_2",
                "PUSH(aa)",
                "PUSH(bb)",
                "PUSH(cc)",
                "OP_3",
                "OP_CHECKMULTISIG",
            ]
        );
    }

    #[test]
    fn compile_thresh_general() {
        let p = Policy::Thresh(
            1,
            vec![Policy::Key("aa".to_string()), Policy::After(10)],
        );
        let asm = disasm(&p.compile());
        assert_eq!(
            asm,
            vec![
                "PUSH(aa)",
                "OP_CHECKSIG",
                "OP_10",
                "OP_CHECKLOCKTIMEVERIFY",
                "OP_DROP",
                "OP_ADD",
                "OP_1",
                "OP_EQUAL",
            ]
        );
    }

    #[test]
    fn compile_nested_and_or() {
        let p = Policy::parse("and(or(pk(aa),pk(bb)),after(100))").unwrap();
        let asm = disasm(&p.compile());
        assert_eq!(
            asm,
            vec![
                "OP_IF",
                "PUSH(aa)",
                "OP_CHECKSIG",
                "OP_ELSE",
                "PUSH(bb)",
                "OP_CHECKSIG",
                "OP_ENDIF",
                "PUSH(64)",
                "OP_CHECKLOCKTIMEVERIFY",
                "OP_DROP",
            ]
        );
    }

    #[test]
    fn roundtrip_parse_compile() {
        let policy_str = "or(and(pk(aabb),after(500)),pk(ccdd))";
        let p = Policy::parse(policy_str).unwrap();
        let script = p.compile();
        assert!(!script.is_empty());
        for instr in script.as_script().instructions() {
            instr.unwrap();
        }
    }

    // ===================================================================
    // Miniscript fragment compilation tests
    // ===================================================================

    #[test]
    fn ms_pk_compile() {
        let ms = Miniscript::Pk(vec![0xde, 0xad, 0xbe, 0xef]);
        let asm = disasm(&ms.compile());
        assert_eq!(asm, vec!["PUSH(deadbeef)", "OP_CHECKSIG"]);
    }

    #[test]
    fn ms_pkh_compile() {
        let hash = vec![0xab; 20];
        let ms = Miniscript::PkH(hash.clone());
        let asm = disasm(&ms.compile());
        assert_eq!(asm[0], "OP_DUP");
        assert_eq!(asm[1], "OP_HASH160");
        assert_eq!(asm[2], format!("PUSH({})", hex::encode(&hash)));
        assert_eq!(asm[3], "OP_EQUALVERIFY");
        assert_eq!(asm[4], "OP_CHECKSIG");
        assert_eq!(asm.len(), 5);
    }

    #[test]
    fn ms_multi_compile() {
        let k1 = vec![0xaa];
        let k2 = vec![0xbb];
        let k3 = vec![0xcc];
        let ms = Miniscript::Multi(2, vec![k1, k2, k3]);
        let asm = disasm(&ms.compile());
        assert_eq!(
            asm,
            vec!["OP_2", "PUSH(aa)", "PUSH(bb)", "PUSH(cc)", "OP_3", "OP_CHECKMULTISIG"]
        );
    }

    #[test]
    fn ms_sha256_compile() {
        let hash = vec![0x42; 32];
        let ms = Miniscript::Sha256(hash.clone());
        let asm = disasm(&ms.compile());
        assert_eq!(asm[0], "OP_SIZE");
        // 32 encodes as OP_PUSHDATA with value
        assert_eq!(asm[1], "PUSH(20)"); // 0x20 = 32 in hex
        assert_eq!(asm[2], "OP_EQUALVERIFY");
        assert_eq!(asm[3], "OP_SHA256");
        assert_eq!(asm[4], format!("PUSH({})", hex::encode(&hash)));
        assert_eq!(asm[5], "OP_EQUAL");
        assert_eq!(asm.len(), 6);
    }

    #[test]
    fn ms_hash256_compile() {
        let hash = vec![0x42; 32];
        let ms = Miniscript::Hash256(hash.clone());
        let asm = disasm(&ms.compile());
        assert_eq!(asm[0], "OP_SIZE");
        assert_eq!(asm[2], "OP_EQUALVERIFY");
        assert_eq!(asm[3], "OP_HASH256");
        assert_eq!(asm[5], "OP_EQUAL");
    }

    #[test]
    fn ms_ripemd160_compile() {
        let hash = vec![0x42; 20];
        let ms = Miniscript::Ripemd160(hash.clone());
        let asm = disasm(&ms.compile());
        assert_eq!(asm[0], "OP_SIZE");
        assert_eq!(asm[2], "OP_EQUALVERIFY");
        assert_eq!(asm[3], "OP_RIPEMD160");
        assert_eq!(asm[5], "OP_EQUAL");
    }

    #[test]
    fn ms_hash160_compile() {
        let hash = vec![0x42; 20];
        let ms = Miniscript::Hash160(hash.clone());
        let asm = disasm(&ms.compile());
        assert_eq!(asm[0], "OP_SIZE");
        assert_eq!(asm[2], "OP_EQUALVERIFY");
        assert_eq!(asm[3], "OP_HASH160");
        assert_eq!(asm[5], "OP_EQUAL");
    }

    #[test]
    fn ms_after_compile() {
        let ms = Miniscript::After(100);
        let asm = disasm(&ms.compile());
        assert_eq!(asm, vec!["PUSH(64)", "OP_CHECKLOCKTIMEVERIFY"]);
    }

    #[test]
    fn ms_older_compile() {
        let ms = Miniscript::Older(10);
        let asm = disasm(&ms.compile());
        assert_eq!(asm, vec!["OP_10", "OP_CHECKSEQUENCEVERIFY"]);
    }

    #[test]
    fn ms_andv_compile() {
        let ms = Miniscript::AndV(
            Box::new(Miniscript::Pk(vec![0xaa])),
            Box::new(Miniscript::Pk(vec![0xbb])),
        );
        let asm = disasm(&ms.compile());
        assert_eq!(
            asm,
            vec!["PUSH(aa)", "OP_CHECKSIG", "PUSH(bb)", "OP_CHECKSIG"]
        );
    }

    #[test]
    fn ms_andb_compile() {
        let ms = Miniscript::AndB(
            Box::new(Miniscript::Pk(vec![0xaa])),
            Box::new(Miniscript::Pk(vec![0xbb])),
        );
        let asm = disasm(&ms.compile());
        assert_eq!(
            asm,
            vec!["PUSH(aa)", "OP_CHECKSIG", "PUSH(bb)", "OP_CHECKSIG", "OP_BOOLAND"]
        );
    }

    #[test]
    fn ms_orb_compile() {
        let ms = Miniscript::OrB(
            Box::new(Miniscript::Pk(vec![0xaa])),
            Box::new(Miniscript::Pk(vec![0xbb])),
        );
        let asm = disasm(&ms.compile());
        assert_eq!(
            asm,
            vec!["PUSH(aa)", "OP_CHECKSIG", "PUSH(bb)", "OP_CHECKSIG", "OP_BOOLOR"]
        );
    }

    #[test]
    fn ms_ord_compile() {
        let ms = Miniscript::OrD(
            Box::new(Miniscript::Pk(vec![0xaa])),
            Box::new(Miniscript::Pk(vec![0xbb])),
        );
        let asm = disasm(&ms.compile());
        assert_eq!(
            asm,
            vec![
                "PUSH(aa)", "OP_CHECKSIG",
                "OP_IFDUP", "OP_NOTIF",
                "PUSH(bb)", "OP_CHECKSIG",
                "OP_ENDIF"
            ]
        );
    }

    #[test]
    fn ms_orc_compile() {
        let ms = Miniscript::OrC(
            Box::new(Miniscript::Pk(vec![0xaa])),
            Box::new(Miniscript::Pk(vec![0xbb])),
        );
        let asm = disasm(&ms.compile());
        assert_eq!(
            asm,
            vec![
                "PUSH(aa)", "OP_CHECKSIG",
                "OP_NOTIF",
                "PUSH(bb)", "OP_CHECKSIG",
                "OP_ENDIF"
            ]
        );
    }

    #[test]
    fn ms_ori_compile() {
        let ms = Miniscript::OrI(
            Box::new(Miniscript::Pk(vec![0xaa])),
            Box::new(Miniscript::Pk(vec![0xbb])),
        );
        let asm = disasm(&ms.compile());
        assert_eq!(
            asm,
            vec![
                "OP_IF",
                "PUSH(aa)", "OP_CHECKSIG",
                "OP_ELSE",
                "PUSH(bb)", "OP_CHECKSIG",
                "OP_ENDIF"
            ]
        );
    }

    #[test]
    fn ms_thresh_compile() {
        let ms = Miniscript::Thresh(
            1,
            vec![
                Miniscript::Pk(vec![0xaa]),
                Miniscript::Pk(vec![0xbb]),
            ],
        );
        let asm = disasm(&ms.compile());
        assert_eq!(
            asm,
            vec![
                "PUSH(aa)", "OP_CHECKSIG",
                "PUSH(bb)", "OP_CHECKSIG",
                "OP_ADD",
                "OP_1", "OP_EQUAL",
            ]
        );
    }

    #[test]
    fn ms_verify_compile() {
        let ms = Miniscript::Verify(Box::new(Miniscript::Pk(vec![0xaa])));
        let asm = disasm(&ms.compile());
        assert_eq!(asm, vec!["PUSH(aa)", "OP_CHECKSIG", "OP_VERIFY"]);
    }

    #[test]
    fn ms_nonzero_compile() {
        let ms = Miniscript::NonZero(Box::new(Miniscript::Pk(vec![0xaa])));
        let asm = disasm(&ms.compile());
        assert_eq!(
            asm,
            vec![
                "OP_SIZE", "OP_0NOTEQUAL", "OP_IF",
                "PUSH(aa)", "OP_CHECKSIG",
                "OP_ENDIF"
            ]
        );
    }

    // ===================================================================
    // Witness size estimation tests
    // ===================================================================

    #[test]
    fn witness_size_pk() {
        let ms = Miniscript::Pk(vec![0xaa; 33]);
        // 1 length + 73 signature
        assert_eq!(ms.max_satisfaction_witness_size(), 74);
    }

    #[test]
    fn witness_size_pkh() {
        let ms = Miniscript::PkH(vec![0xab; 20]);
        // (1+73) + (1+33) = 108
        assert_eq!(ms.max_satisfaction_witness_size(), 108);
    }

    #[test]
    fn witness_size_multi() {
        let ms = Miniscript::Multi(2, vec![vec![0xaa; 33], vec![0xbb; 33], vec![0xcc; 33]]);
        // 1 (OP_0 dummy) + 2 * (1+73) = 1 + 148 = 149
        assert_eq!(ms.max_satisfaction_witness_size(), 149);
    }

    #[test]
    fn witness_size_sha256() {
        let ms = Miniscript::Sha256(vec![0x42; 32]);
        // 1 length + 32 preimage
        assert_eq!(ms.max_satisfaction_witness_size(), 33);
    }

    #[test]
    fn witness_size_timelocks() {
        assert_eq!(Miniscript::After(100).max_satisfaction_witness_size(), 0);
        assert_eq!(Miniscript::Older(144).max_satisfaction_witness_size(), 0);
    }

    #[test]
    fn witness_size_and() {
        let ms = Miniscript::AndV(
            Box::new(Miniscript::Pk(vec![0xaa; 33])),
            Box::new(Miniscript::Pk(vec![0xbb; 33])),
        );
        // Two signatures: 74 + 74
        assert_eq!(ms.max_satisfaction_witness_size(), 148);
    }

    #[test]
    fn witness_size_ori() {
        let ms = Miniscript::OrI(
            Box::new(Miniscript::Pk(vec![0xaa; 33])),
            Box::new(Miniscript::Pk(vec![0xbb; 33])),
        );
        // 1 selector + max(74, 74) = 75
        assert_eq!(ms.max_satisfaction_witness_size(), 75);
    }

    #[test]
    fn witness_size_verify() {
        let inner = Miniscript::Pk(vec![0xaa; 33]);
        let ms = Miniscript::Verify(Box::new(inner));
        assert_eq!(ms.max_satisfaction_witness_size(), 74);
    }

    // ===================================================================
    // Script size estimation tests
    // ===================================================================

    #[test]
    fn script_size_pk() {
        let ms = Miniscript::Pk(vec![0xaa; 33]);
        let expected = ms.compile().len();
        assert_eq!(ms.script_size(), expected);
    }

    #[test]
    fn script_size_multi() {
        let ms = Miniscript::Multi(2, vec![vec![0xaa; 33], vec![0xbb; 33], vec![0xcc; 33]]);
        let expected = ms.compile().len();
        assert_eq!(ms.script_size(), expected);
    }

    #[test]
    fn script_size_ori() {
        let ms = Miniscript::OrI(
            Box::new(Miniscript::Pk(vec![0xaa; 33])),
            Box::new(Miniscript::Pk(vec![0xbb; 33])),
        );
        let expected = ms.compile().len();
        assert_eq!(ms.script_size(), expected);
    }

    // ===================================================================
    // Safety tests
    // ===================================================================

    #[test]
    fn safe_pk() {
        assert!(Miniscript::Pk(vec![0xaa; 33]).is_safe());
    }

    #[test]
    fn safe_pkh() {
        assert!(Miniscript::PkH(vec![0xab; 20]).is_safe());
    }

    #[test]
    fn safe_multi() {
        assert!(Miniscript::Multi(2, vec![vec![0xaa; 33], vec![0xbb; 33]]).is_safe());
    }

    #[test]
    fn unsafe_hashlock_only() {
        assert!(!Miniscript::Sha256(vec![0x42; 32]).is_safe());
        assert!(!Miniscript::Hash256(vec![0x42; 32]).is_safe());
        assert!(!Miniscript::Ripemd160(vec![0x42; 20]).is_safe());
        assert!(!Miniscript::Hash160(vec![0x42; 20]).is_safe());
    }

    #[test]
    fn unsafe_timelock_only() {
        assert!(!Miniscript::After(100).is_safe());
        assert!(!Miniscript::Older(144).is_safe());
    }

    #[test]
    fn safe_and_with_key() {
        let ms = Miniscript::AndV(
            Box::new(Miniscript::Pk(vec![0xaa; 33])),
            Box::new(Miniscript::After(100)),
        );
        assert!(ms.is_safe());
    }

    #[test]
    fn unsafe_and_without_key() {
        let ms = Miniscript::AndV(
            Box::new(Miniscript::Sha256(vec![0x42; 32])),
            Box::new(Miniscript::After(100)),
        );
        assert!(!ms.is_safe());
    }

    #[test]
    fn safe_or_both_have_keys() {
        let ms = Miniscript::OrI(
            Box::new(Miniscript::Pk(vec![0xaa; 33])),
            Box::new(Miniscript::Pk(vec![0xbb; 33])),
        );
        assert!(ms.is_safe());
    }

    #[test]
    fn unsafe_or_one_branch_no_key() {
        let ms = Miniscript::OrI(
            Box::new(Miniscript::Pk(vec![0xaa; 33])),
            Box::new(Miniscript::Sha256(vec![0x42; 32])),
        );
        assert!(!ms.is_safe());
    }

    #[test]
    fn safe_thresh_all_keys() {
        let ms = Miniscript::Thresh(
            2,
            vec![
                Miniscript::Pk(vec![0xaa; 33]),
                Miniscript::Pk(vec![0xbb; 33]),
                Miniscript::Pk(vec![0xcc; 33]),
            ],
        );
        assert!(ms.is_safe());
    }

    #[test]
    fn unsafe_thresh_not_enough_keys() {
        // k=1, but one sub has no key: the non-key sub alone could satisfy
        let ms = Miniscript::Thresh(
            1,
            vec![
                Miniscript::Pk(vec![0xaa; 33]),
                Miniscript::Sha256(vec![0x42; 32]),
            ],
        );
        assert!(!ms.is_safe());
    }

    #[test]
    fn safe_verify_wrapper() {
        let ms = Miniscript::Verify(Box::new(Miniscript::Pk(vec![0xaa; 33])));
        assert!(ms.is_safe());
    }

    #[test]
    fn safe_nonzero_wrapper() {
        let ms = Miniscript::NonZero(Box::new(Miniscript::Pk(vec![0xaa; 33])));
        assert!(ms.is_safe());
    }

    // ===================================================================
    // Policy::to_miniscript tests
    // ===================================================================

    #[test]
    fn policy_to_ms_key() {
        let p = Policy::Key("aabb".to_string());
        let ms = p.to_miniscript();
        assert_eq!(ms, Miniscript::Pk(vec![0xaa, 0xbb]));
    }

    #[test]
    fn policy_to_ms_after() {
        let p = Policy::After(500);
        let ms = p.to_miniscript();
        assert_eq!(ms, Miniscript::After(500));
    }

    #[test]
    fn policy_to_ms_older() {
        let p = Policy::Older(144);
        let ms = p.to_miniscript();
        assert_eq!(ms, Miniscript::Older(144));
    }

    #[test]
    fn policy_to_ms_sha256() {
        let h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let p = Policy::Sha256(h.to_string());
        let ms = p.to_miniscript();
        let expected_bytes = hex::decode(h).unwrap();
        assert_eq!(ms, Miniscript::Sha256(expected_bytes));
    }

    #[test]
    fn policy_to_ms_and() {
        let p = Policy::And(
            Box::new(Policy::Key("aa".to_string())),
            Box::new(Policy::After(10)),
        );
        let ms = p.to_miniscript();
        assert_eq!(
            ms,
            Miniscript::AndV(
                Box::new(Miniscript::Pk(vec![0xaa])),
                Box::new(Miniscript::After(10)),
            )
        );
    }

    #[test]
    fn policy_to_ms_or() {
        let p = Policy::Or(
            Box::new(Policy::Key("aa".to_string())),
            Box::new(Policy::Key("bb".to_string())),
        );
        let ms = p.to_miniscript();
        assert_eq!(
            ms,
            Miniscript::OrI(
                Box::new(Miniscript::Pk(vec![0xaa])),
                Box::new(Miniscript::Pk(vec![0xbb])),
            )
        );
    }

    #[test]
    fn policy_to_ms_thresh_multisig() {
        let p = Policy::Thresh(
            2,
            vec![
                Policy::Key("aa".to_string()),
                Policy::Key("bb".to_string()),
                Policy::Key("cc".to_string()),
            ],
        );
        let ms = p.to_miniscript();
        assert_eq!(
            ms,
            Miniscript::Multi(2, vec![vec![0xaa], vec![0xbb], vec![0xcc]])
        );
    }

    #[test]
    fn policy_to_ms_thresh_general() {
        let p = Policy::Thresh(
            1,
            vec![Policy::Key("aa".to_string()), Policy::After(10)],
        );
        let ms = p.to_miniscript();
        assert_eq!(
            ms,
            Miniscript::Thresh(
                1,
                vec![Miniscript::Pk(vec![0xaa]), Miniscript::After(10)]
            )
        );
    }

    #[test]
    fn policy_to_ms_compile_roundtrip() {
        // Parse -> to_miniscript -> compile should produce a valid script
        let policy_str = "or(and(pk(aabb),after(500)),pk(ccdd))";
        let p = Policy::parse(policy_str).unwrap();
        let ms = p.to_miniscript();
        let script = ms.compile();
        assert!(!script.is_empty());
        for instr in script.as_script().instructions() {
            instr.unwrap();
        }
    }

    #[test]
    fn policy_to_ms_nested_is_safe() {
        // and(pk(key), after(100)) should be safe (has a key check)
        let p = Policy::parse("and(pk(aabb),after(100))").unwrap();
        let ms = p.to_miniscript();
        assert!(ms.is_safe());
    }

    #[test]
    fn policy_to_ms_nested_unsafe() {
        // or(sha256(hash), after(100)) -- no keys anywhere
        let h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let p = Policy::parse(&format!("or(sha256({}),after(100))", h)).unwrap();
        let ms = p.to_miniscript();
        assert!(!ms.is_safe());
    }

    // ===================================================================
    // All Or-variant compilation cross-checks
    // ===================================================================

    #[test]
    fn ms_all_or_variants_produce_valid_script() {
        let a = Miniscript::Pk(vec![0xaa; 33]);
        let b = Miniscript::Pk(vec![0xbb; 33]);

        for ms in [
            Miniscript::OrB(Box::new(a.clone()), Box::new(b.clone())),
            Miniscript::OrD(Box::new(a.clone()), Box::new(b.clone())),
            Miniscript::OrC(Box::new(a.clone()), Box::new(b.clone())),
            Miniscript::OrI(Box::new(a.clone()), Box::new(b.clone())),
        ] {
            let script = ms.compile();
            assert!(!script.is_empty());
            for instr in script.as_script().instructions() {
                instr.unwrap();
            }
        }
    }

    // ===================================================================
    // Complex nested fragment tests
    // ===================================================================

    #[test]
    fn ms_nested_thresh_with_wrappers() {
        let ms = Miniscript::Thresh(
            2,
            vec![
                Miniscript::Verify(Box::new(Miniscript::Pk(vec![0xaa; 33]))),
                Miniscript::Pk(vec![0xbb; 33]),
                Miniscript::NonZero(Box::new(Miniscript::Pk(vec![0xcc; 33]))),
            ],
        );
        let script = ms.compile();
        assert!(!script.is_empty());
        for instr in script.as_script().instructions() {
            instr.unwrap();
        }
        assert!(ms.is_safe());
    }

    #[test]
    fn ms_deep_nesting() {
        // OrI(AndV(Pk, After), OrD(Pk, Sha256))
        let ms = Miniscript::OrI(
            Box::new(Miniscript::AndV(
                Box::new(Miniscript::Pk(vec![0xaa; 33])),
                Box::new(Miniscript::After(1000)),
            )),
            Box::new(Miniscript::OrD(
                Box::new(Miniscript::Pk(vec![0xbb; 33])),
                Box::new(Miniscript::Sha256(vec![0x42; 32])),
            )),
        );
        let script = ms.compile();
        assert!(!script.is_empty());
        for instr in script.as_script().instructions() {
            instr.unwrap();
        }
        // Not safe because OrD right branch is Sha256 (no key check)
        // and OrI requires both branches to be safe
        assert!(!ms.is_safe());
    }
}
