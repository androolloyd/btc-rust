//! Bounded highest-common-version selection from the Electrum protocol contract.
use serde_json::Value;

pub(crate) const PROTOCOL: &str = "1.4";
pub(crate) const SERVER_VERSION: &str = concat!("btc-rust ", env!("CARGO_PKG_VERSION"));
pub(crate) const MAX_CLIENT_BYTES: usize = 128;
const MAX_VERSION_BYTES: usize = 64;
const MAX_COMPONENTS: usize = 8;

fn version(text: &str) -> Option<Vec<u32>> {
    if text.len() > MAX_VERSION_BYTES || !text.contains('.') {
        return None;
    }
    let mut result = Vec::new();
    for part in text.split('.') {
        if result.len() == MAX_COMPONENTS
            || part.is_empty()
            || !part.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        result.push(part.parse().ok()?);
    }
    Some(result)
}

/// None means no common supported version. Wrong JSON types are parameter errors.
pub(crate) fn select(request: Option<&Value>) -> Result<Option<&'static str>, &'static str> {
    let (minimum, maximum) = match request {
        None => (PROTOCOL, PROTOCOL),
        Some(Value::String(text)) => (text.as_str(), text.as_str()),
        Some(Value::Array(range)) if range.len() == 2 => (
            range[0]
                .as_str()
                .ok_or("protocol range endpoints must be strings")?,
            range[1]
                .as_str()
                .ok_or("protocol range endpoints must be strings")?,
        ),
        _ => return Err("protocol_version must be a string or two-string range"),
    };
    let Some(minimum) = version(minimum) else {
        return Ok(None);
    };
    let Some(maximum) = version(maximum) else {
        return Ok(None);
    };
    let supported = vec![1, 4];
    Ok((minimum <= supported && supported <= maximum).then_some(PROTOCOL))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hostile_versions_fail_with_bounded_work_and_typed_ranges() {
        for value in [
            json!("1.".repeat(10000)),
            json!("1.9999999999999999999999"),
            json!("1.4.0.0.0.0.0.0.0"),
            json!("1..4"),
            json!("-1.4"),
            json!("1.4\n"),
        ] {
            assert_eq!(select(Some(&value)).unwrap(), None);
        }
        for value in [
            Value::Null,
            json!(true),
            json!(1.4),
            json!([]),
            json!(["1.4"]),
            json!(["1.4", 2]),
            json!({}),
        ] {
            assert!(select(Some(&value)).is_err());
        }
    }
}
