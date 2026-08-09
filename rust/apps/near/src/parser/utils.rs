use alloc::format;
use alloc::string::String;
use core::ops::Div;
use serde::Serializer;
use {cryptoxide, hex};

pub const NEAR_THRESHOLD: u128 = 10000000000000000000;
pub const NEAR_DIVIDER: f64 = 1_000_000_000_000_000_000_000_000f64;
pub const GAS_DIVIDER: f64 = 1_000_000_000_000_f64;

use serde_json;
use serde_json::Value;

pub trait Merge {
    fn merge(&mut self, new_json_value: Value);
}

impl Merge for serde_json::Value {
    fn merge(&mut self, new_json_value: Value) {
        merge(self, &new_json_value);
    }
}

fn merge(a: &mut Value, b: &Value) {
    match (a, b) {
        (Value::Object(ref mut a), Value::Object(b)) => {
            for (k, v) in b {
                merge(a.entry(k).or_insert(Value::Null), v);
            }
        }
        (Value::Array(ref mut a), Value::Array(b)) => {
            a.extend(b.clone());
        }
        (Value::Array(ref mut a), Value::Object(b)) => {
            a.extend([Value::Object(b.clone())]);
        }
        (a, b) => {
            *a = b.clone();
        }
    }
}

pub fn format_amount(value: u128) -> String {
    if value > NEAR_THRESHOLD {
        format!("{} {}", (value as f64).div(NEAR_DIVIDER), "NEAR")
    } else {
        format!("{} {}", value, "Yocto")
    }
}

pub fn format_option_u128_amount<S>(v: &Option<u128>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format_amount(v.unwrap_or_default()))
}

pub fn format_u128_amount<S>(v: &u128, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format_amount(*v))
}

pub fn format_gas(value: u64) -> String {
    format!("{} {}", (value as f64).div(GAS_DIVIDER), "TGas")
}

pub fn format_gas_amount<S>(v: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format_gas(*v))
}

/// A sha256 summary for a code blob that must never be shown raw on the confirm screen (matches
/// the existing precedent: `DeployContractAction`'s hand-written `Debug` hex-encodes rather than
/// dumps `code`). Both ends of the hash are shown, per near-shopify/plan/01-near-actions.md
/// Deliverable 4's requirement that a code hash be checkable, not just present.
pub fn format_code_summary(code: &[u8]) -> String {
    let hash = hex::encode(cryptoxide::hashing::sha256(code));
    format!(
        "sha256 {}…{} ({} bytes)",
        &hash[..8],
        &hash[hash.len() - 8..],
        code.len()
    )
}

/// The security-relevant distinction a bare `GlobalContractDeployMode` variant name would hide:
/// `CodeHash` publishes the contract under its own hash (immutable), `AccountId` publishes it
/// under the deployer's account (who can later replace the code for every user of it). A vault
/// deployed the second way is a vault whose logic the store can silently change after a shopper
/// has funded it — see near_tx/src/action.rs's `GlobalContractDeployMode` doc for the same
/// rationale on the native side.
pub fn deploy_mode_words(mode: &crate::parser::transaction::GlobalContractDeployMode) -> &'static str {
    use crate::parser::transaction::GlobalContractDeployMode;
    match mode {
        GlobalContractDeployMode::CodeHash => "Immutable (by code hash)",
        GlobalContractDeployMode::AccountId => "Owner can replace this code later",
    }
}

/// Attacker-controlled collection lengths (a `Delegate`'s inner actions, a state-init's `data`
/// map) arrive over the QR channel on a `no_std` device with a small heap. Borsh's stock
/// `Vec`/`BTreeMap` deserialize reads this same 4-byte length prefix and allocates *before*
/// reading elements, so an attacker can make it attempt a large allocation before the "buffer too
/// short" error would otherwise fire. Checking the claimed length against a cap first turns that
/// into a clean parse error instead of an allocator-exhaustion panic — the only channel this
/// design has, with no hand-typed fallback (I3), cannot afford to crash on a malformed frame.
pub fn read_capped_len(
    buf: &mut &[u8],
    max: u32,
    what: &str,
) -> core::result::Result<u32, borsh::maybestd::io::Error> {
    use borsh::maybestd::io::{Error, ErrorKind};
    let len = <u32 as borsh::BorshDeserialize>::deserialize(buf)?;
    if len > max {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{what} claims {len} entries, more than the {max} this device allows"),
        ));
    }
    Ok(len)
}

#[cfg(test)]
mod serde_json_value_updater_test {
    use super::*;
    use alloc::string::ToString;
    use serde_json;
    use serde_json::Value;

    #[test]
    fn it_should_merge_array_string() {
        let mut first_json_value: Value = serde_json::from_str(r#"["a","b"]"#).unwrap();
        let secound_json_value: Value = serde_json::from_str(r#"["b","c"]"#).unwrap();
        first_json_value.merge(secound_json_value);
        assert_eq!(r#"["a","b","b","c"]"#, first_json_value.to_string());
    }

    #[test]
    fn it_should_merge_array_object() {
        let mut first_json_value: Value =
            serde_json::from_str(r#"[{"value":"a"},{"value":"b"}]"#).unwrap();
        let secound_json_value: Value =
            serde_json::from_str(r#"[{"value":"b"},{"value":"c"}]"#).unwrap();
        first_json_value.merge(secound_json_value);
        assert_eq!(
            r#"[{"value":"a"},{"value":"b"},{"value":"b"},{"value":"c"}]"#,
            first_json_value.to_string()
        );
    }

    #[test]
    fn it_should_merge_object() {
        let mut first_json_value: Value =
            serde_json::from_str(r#"{"value1":"a","value2":"b"}"#).unwrap();
        let secound_json_value: Value =
            serde_json::from_str(r#"{"value1":"a","value2":"c","value3":"d"}"#).unwrap();
        first_json_value.merge(secound_json_value);
        assert_eq!(
            r#"{"value1":"a","value2":"c","value3":"d"}"#,
            first_json_value.to_string()
        );
    }

    #[test]
    fn it_should_merge_string() {
        let mut value_a: Value = Value::String("a".to_string());
        let value_b: Value = Value::String("b".to_string());
        value_a.merge(value_b.clone());
        assert_eq!(value_b.to_string(), value_a.to_string());
    }
}
