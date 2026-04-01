//! Compile a miniscript policy to Bitcoin Script.
//!
//! Usage: cargo run --example miniscript_compile -- "and(pk(ab),after(100))"

use btc_forge::miniscript::Policy;

fn main() {
    let policy_str = std::env::args().nth(1).unwrap_or_else(|| {
        "and(pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),after(100))"
            .to_string()
    });

    let policy = Policy::parse(&policy_str).expect("invalid policy");
    let script = policy.compile();

    println!("Policy:      {}", policy_str);
    println!("Script hex:  {}", hex::encode(script.as_bytes()));
    println!("Script size: {} bytes", script.as_bytes().len());
}
