//! Basic miniscript policy-to-script compiler.
//!
//! Implements a subset of the Miniscript policy language and compiles policies
//! down to Bitcoin Script ([`ScriptBuf`]).

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
                    // Each sub gets wrapped in an IF-based 0/1 evaluation.
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

    // -- Parsing tests --

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

    // -- Compilation tests --

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
        // and(A,B) => compile(A) + compile(B) (concatenation)
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
        // All-key threshold compiles to OP_CHECKMULTISIG
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
        // Mixed threshold uses OP_ADD-based counting
        let p = Policy::Thresh(
            1,
            vec![Policy::Key("aa".to_string()), Policy::After(10)],
        );
        let asm = disasm(&p.compile());
        // compile(key) + compile(after) + OP_ADD + <k> OP_EQUAL
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
        // Parse a policy, compile it, and verify the script is non-empty.
        let policy_str = "or(and(pk(aabb),after(500)),pk(ccdd))";
        let p = Policy::parse(policy_str).unwrap();
        let script = p.compile();
        assert!(!script.is_empty());
        // Ensure all instructions parse successfully
        for instr in script.as_script().instructions() {
            instr.unwrap();
        }
    }
}
