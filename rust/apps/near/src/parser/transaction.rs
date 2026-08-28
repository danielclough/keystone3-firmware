use crate::account_id::AccountId;
use crate::crypto::PublicKey;
use crate::parser::utils::{format_gas_amount, format_u128_amount};
use crate::primitives_core::account::AccessKey;
use crate::primitives_core::hash::{hash, CryptoHash};

use crate::primitives_core::types::{Balance, Gas, Nonce};
use alloc::fmt;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use hex;
use serde::{Deserialize, Serialize};

// Deserialize is deliberately not derived on `Transaction` or `Action` (see the note at
// `Action`'s own derive below) — nothing in this crate deserializes either from JSON.
#[derive(BorshSerialize, BorshDeserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct Transaction {
    /// An account on which behalf transaction is signed
    pub signer_id: AccountId,
    /// A public key of the access key which was used to sign an account.
    /// Access key holds permissions for calling certain kinds of actions.
    pub public_key: PublicKey,
    /// Nonce is used to determine order of transaction in the pool.
    /// It increments for a combination of `signer_id` and `public_key`
    pub nonce: Nonce,
    /// Receiver account for this transaction
    pub receiver_id: AccountId,
    /// The hash of the block in the blockchain on top of which the given transaction is valid
    pub block_hash: CryptoHash,
    /// A list of actions to be applied
    pub actions: Vec<Action>,
}

#[allow(dead_code)]
impl Transaction {
    /// Computes a hash of the transaction for signing and size of serialized transaction
    pub fn get_hash_and_size(&self) -> (CryptoHash, u64) {
        let bytes = self.try_to_vec().expect("Failed to deserialize");
        (hash(&bytes), bytes.len() as u64)
    }
}

// Deserialize is deliberately not derived here (and not on the discriminant-8..11 payload types
// below): nothing in this crate deserializes an `Action` from JSON — every existing test parses
// the detail string into a generic `serde_json::Value`, never back into `Action` — so it would
// be dead capability the four new variants would otherwise have to carry a real implementation
// for. Only `Serialize` (confirm-screen rendering) and `BorshSerialize`/`BorshDeserialize` (the
// wire format) are load-bearing.
#[derive(BorshSerialize, BorshDeserialize, Serialize, PartialEq, Eq, Debug, Clone)]
#[serde(tag = "Action")]
pub enum Action {
    /// Create an (sub)account using a transaction `receiver_id` as an ID for
    /// a new account ID must pass validation rules described here
    /// <http://nomicon.io/Primitives/Account.html>.
    #[serde(rename = "Create Account")]
    CreateAccount(CreateAccountAction),
    /// Sets a Wasm code to a receiver_id
    #[serde(rename = "Deploy Contract")]
    DeployContract(DeployContractAction),
    #[serde(rename = "Function Call")]
    FunctionCall(FunctionCallAction),
    #[serde(rename = "Transfer")]
    Transfer(TransferAction),
    #[serde(rename = "Stake")]
    Stake(StakeAction),
    #[serde(rename = "Add Key")]
    AddKey(AddKeyAction),
    #[serde(rename = "Delete Key")]
    DeleteKey(DeleteKeyAction),
    #[serde(rename = "Delete Account")]
    DeleteAccount(DeleteAccountAction),

    /// 8. NEP-366. Borsh 0.9 has no explicit discriminants (`#[borsh(use_discriminant)]` does
    /// not exist for this version) — the wire tag IS declaration order. These four variants
    /// must stay appended here, in this order, matching near_tx::TxAction's 8/9/10/11
    /// (near_tx/src/action.rs) and nearcore's own action/mod.rs:349. Reordering them, or
    /// inserting a variant before them, silently changes what every transaction means.
    #[serde(rename = "Delegate")]
    Delegate(SignedDelegateAction),
    /// 9.
    #[serde(rename = "Deploy Global Contract")]
    DeployGlobalContract(DeployGlobalContractAction),
    /// 10.
    #[serde(rename = "Use Global Contract")]
    UseGlobalContract(UseGlobalContractAction),
    /// 11.
    #[serde(rename = "State Init")]
    DeterministicStateInit(DeterministicStateInitAction),
}

pub trait Normalizer {
    fn normalize(&self) -> String;
}

impl Normalizer for Action {
    fn normalize(&self) -> String {
        match self {
            Action::CreateAccount(v) => v.normalize(),
            Action::DeployContract(v) => v.normalize(),
            Action::FunctionCall(v) => v.normalize(),
            Action::Transfer(v) => v.normalize(),
            Action::Stake(v) => v.normalize(),
            Action::AddKey(v) => v.normalize(),
            Action::DeleteKey(v) => v.normalize(),
            Action::DeleteAccount(v) => v.normalize(),
            Action::Delegate(v) => v.normalize(),
            Action::DeployGlobalContract(v) => v.normalize(),
            Action::UseGlobalContract(v) => v.normalize(),
            Action::DeterministicStateInit(v) => v.normalize(),
        }
    }
}

/// Create account action
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct CreateAccountAction {}

impl Normalizer for CreateAccountAction {
    fn normalize(&self) -> String {
        "Create Account".to_string()
    }
}

impl From<CreateAccountAction> for Action {
    fn from(create_account_action: CreateAccountAction) -> Self {
        Self::CreateAccount(create_account_action)
    }
}

/// Deploy contract action
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct DeployContractAction {
    /// WebAssembly binary
    #[serde(skip_serializing)]
    pub code: Vec<u8>,
}

impl Normalizer for DeployContractAction {
    fn normalize(&self) -> String {
        "Deploy Contract".to_string()
    }
}

impl From<DeployContractAction> for Action {
    fn from(deploy_contract_action: DeployContractAction) -> Self {
        Self::DeployContract(deploy_contract_action)
    }
}

impl fmt::Debug for DeployContractAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeployContractAction")
            .field("code", &format_args!("{}", hex::encode(&self.code)))
            .finish()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct FunctionCallAction {
    #[serde(rename = "Method")]
    pub method_name: String,
    #[serde(skip_serializing)]
    pub args: Vec<u8>,
    #[serde(serialize_with = "format_gas_amount", rename = "Prepaid Gas")]
    pub gas: Gas,
    #[serde(serialize_with = "format_u128_amount", rename = "Deposit Value")]
    pub deposit: Balance,
}

impl Normalizer for FunctionCallAction {
    fn normalize(&self) -> String {
        "Function Call".to_string()
    }
}

impl From<FunctionCallAction> for Action {
    fn from(function_call_action: FunctionCallAction) -> Self {
        Self::FunctionCall(function_call_action)
    }
}

impl fmt::Debug for FunctionCallAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunctionCallAction")
            .field("method_name", &format_args!("{}", &self.method_name))
            .field("args", &format_args!("{}", hex::encode(&self.args)))
            .field("gas", &format_args!("{}", &self.gas))
            .field("deposit", &format_args!("{}", &self.deposit))
            .finish()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct TransferAction {
    #[serde(rename = "Value", serialize_with = "format_u128_amount")]
    pub deposit: Balance,
}

impl From<TransferAction> for Action {
    fn from(transfer_action: TransferAction) -> Self {
        Self::Transfer(transfer_action)
    }
}

impl Normalizer for TransferAction {
    fn normalize(&self) -> String {
        "Transfer".to_string()
    }
}

/// An action which stakes singer_id tokens and setup's validator public key
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct StakeAction {
    /// Amount of tokens to stake.
    #[serde(serialize_with = "format_u128_amount", rename = "Stake Amount")]
    pub stake: Balance,
    /// Validator key which will be used to sign transactions on behalf of singer_id
    #[serde(rename = "Public Key")]
    pub public_key: PublicKey,
}

impl Normalizer for StakeAction {
    fn normalize(&self) -> String {
        "Stake".to_string()
    }
}

impl From<StakeAction> for Action {
    fn from(stake_action: StakeAction) -> Self {
        Self::Stake(stake_action)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct AddKeyAction {
    /// A public key which will be associated with an access_key
    #[serde(rename = "Public Key")]
    pub public_key: PublicKey,
    /// An access key with the permission
    #[serde(flatten)]
    pub access_key: AccessKey,
}

impl Normalizer for AddKeyAction {
    fn normalize(&self) -> String {
        "Add Key".to_string()
    }
}

impl From<AddKeyAction> for Action {
    fn from(add_key_action: AddKeyAction) -> Self {
        Self::AddKey(add_key_action)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct DeleteKeyAction {
    /// A public key associated with the access_key to be deleted.
    #[serde(rename = "Public Key")]
    pub public_key: PublicKey,
}

impl Normalizer for DeleteKeyAction {
    fn normalize(&self) -> String {
        "Delete Key".to_string()
    }
}

impl From<DeleteKeyAction> for Action {
    fn from(delete_key_action: DeleteKeyAction) -> Self {
        Self::DeleteKey(delete_key_action)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct DeleteAccountAction {
    #[serde(rename = "Beneficiary ID")]
    pub beneficiary_id: AccountId,
}

impl Normalizer for DeleteAccountAction {
    fn normalize(&self) -> String {
        "Delete Account".to_string()
    }
}

impl From<DeleteAccountAction> for Action {
    fn from(delete_account_action: DeleteAccountAction) -> Self {
        Self::DeleteAccount(delete_account_action)
    }
}

// ---------------------------------------------------------------------------------------------
// Discriminants 8-11 (near-shopify plan phase 01, Deliverable 6). Layouts mirror near_tx's own
// (near_tx/src/action.rs), already verified there against near-primitives-0.37.0. Reusing this
// crate's own `CryptoHash` (primitives_core/hash.rs) for a global-contract code hash rather than
// a new newtype — its borsh layout (32 raw bytes, no length prefix) already matches, and this
// crate's `Transaction.block_hash` already uses the same `CryptoHash` type without confusion.
// ---------------------------------------------------------------------------------------------

use crate::crypto::Signature;
use crate::parser::utils::{deploy_mode_words, format_code_summary, read_capped_len};
use alloc::collections::BTreeMap;
use cryptoxide::hashing::keccak256;
use serde::Serializer;

/// nearcore/core/primitives-core/src/global_contract.rs. Tag = declaration order (CodeHash = 0,
/// AccountId = 1) — borsh 0.9 has no explicit discriminants, same hazard as the outer `Action`.
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Clone, Debug)]
pub enum GlobalContractIdentifier {
    CodeHash(CryptoHash),
    AccountId(AccountId),
}

impl Serialize for GlobalContractIdentifier {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            GlobalContractIdentifier::CodeHash(h) => serializer.serialize_str(&format!("hash {h}")),
            GlobalContractIdentifier::AccountId(a) => {
                serializer.serialize_str(&format!("account {a}"))
            }
        }
    }
}

/// nearcore/core/primitives/src/action/mod.rs. Tag = declaration order (CodeHash = 0,
/// AccountId = 1). The distinction is a security property, not a tuning knob — see
/// `deploy_mode_words`'s doc comment (parser/utils.rs) for why.
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Clone, Copy, Debug)]
pub enum GlobalContractDeployMode {
    CodeHash,
    AccountId,
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Clone)]
pub struct DeployGlobalContractAction {
    pub code: alloc::vec::Vec<u8>,
    pub deploy_mode: GlobalContractDeployMode,
}

impl Serialize for DeployGlobalContractAction {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Shadow<'a> {
            #[serde(rename = "Code")]
            code: String,
            #[serde(rename = "Deploy Mode")]
            deploy_mode: &'a str,
        }
        Shadow {
            code: format_code_summary(&self.code),
            deploy_mode: deploy_mode_words(&self.deploy_mode),
        }
        .serialize(serializer)
    }
}

impl fmt::Debug for DeployGlobalContractAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeployGlobalContractAction")
            .field("code", &format_args!("{}", format_code_summary(&self.code)))
            .field("deploy_mode", &self.deploy_mode)
            .finish()
    }
}

impl Normalizer for DeployGlobalContractAction {
    fn normalize(&self) -> String {
        "Deploy Global Contract".to_string()
    }
}

impl From<DeployGlobalContractAction> for Action {
    fn from(a: DeployGlobalContractAction) -> Self {
        Self::DeployGlobalContract(a)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, PartialEq, Eq, Clone, Debug)]
pub struct UseGlobalContractAction {
    #[serde(rename = "Contract")]
    pub contract_identifier: GlobalContractIdentifier,
}

impl Normalizer for UseGlobalContractAction {
    fn normalize(&self) -> String {
        "Use Global Contract".to_string()
    }
}

impl From<UseGlobalContractAction> for Action {
    fn from(a: UseGlobalContractAction) -> Self {
        Self::UseGlobalContract(a)
    }
}

/// nearcore/core/primitives-core/src/deterministic_account_id.rs. Single variant today (V1 = 0)
/// — still an enum, not a bare struct, because nearcore models it as one and a future V2 must
/// stay at tag 1, not collide with V1's tag 0.
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Clone, Debug)]
pub enum DeterministicAccountStateInit {
    V1(DeterministicAccountStateInitV1),
}

/// The cap on `data` entries and per-entry bytes exists for the reason `read_capped_len`
/// documents: this is attacker-controlled size arriving over the QR channel on a device with no
/// hand-typed fallback if it crashes. 64 entries of up to 4096 bytes each is far more than any
/// real vault init needs (near-shopify/plan/03-vault-contracts.md's per-order state is small key
/// bindings, not blobs) while still bounding worst-case allocation to a few hundred KB.
pub const MAX_STATE_INIT_DATA_ENTRIES: u32 = 64;
pub const MAX_STATE_INIT_ENTRY_BYTES: u32 = 4096;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DeterministicAccountStateInitV1 {
    pub code: GlobalContractIdentifier,
    pub data: BTreeMap<alloc::vec::Vec<u8>, alloc::vec::Vec<u8>>,
}

impl BorshSerialize for DeterministicAccountStateInitV1 {
    fn serialize<W: borsh::maybestd::io::Write>(
        &self,
        writer: &mut W,
    ) -> Result<(), borsh::maybestd::io::Error> {
        BorshSerialize::serialize(&self.code, writer)?;
        BorshSerialize::serialize(&self.data, writer)
    }
}

impl BorshDeserialize for DeterministicAccountStateInitV1 {
    fn deserialize(buf: &mut &[u8]) -> Result<Self, borsh::maybestd::io::Error> {
        use borsh::maybestd::io::{Error, ErrorKind};
        let code = GlobalContractIdentifier::deserialize(buf)?;
        let len = read_capped_len(buf, MAX_STATE_INIT_DATA_ENTRIES, "a state-init's data map")?;
        let mut data = BTreeMap::new();
        for _ in 0..len {
            let key = <alloc::vec::Vec<u8> as BorshDeserialize>::deserialize(buf)?;
            if key.len() as u32 > MAX_STATE_INIT_ENTRY_BYTES {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "a state-init data key exceeds this device's per-entry limit",
                ));
            }
            let value = <alloc::vec::Vec<u8> as BorshDeserialize>::deserialize(buf)?;
            if value.len() as u32 > MAX_STATE_INIT_ENTRY_BYTES {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "a state-init data value exceeds this device's per-entry limit",
                ));
            }
            data.insert(key, value);
        }
        Ok(DeterministicAccountStateInitV1 { code, data })
    }
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Clone, Debug)]
pub struct DeterministicStateInitAction {
    pub state_init: DeterministicAccountStateInit,
    pub deposit: Balance,
}

impl Serialize for DeterministicStateInitAction {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Shadow {
            #[serde(rename = "Address")]
            address: String,
            #[serde(
                rename = "Deposit",
                serialize_with = "crate::parser::utils::format_u128_amount"
            )]
            deposit: Balance,
            #[serde(rename = "Code")]
            code: String,
            #[serde(rename = "Data Entries")]
            data_entries: usize,
            #[serde(rename = "Data Bytes")]
            data_bytes: usize,
        }
        let DeterministicAccountStateInit::V1(v1) = &self.state_init;
        // Computed on-device from the bytes about to be signed — never trusted from an
        // accompanying plaintext field. This IS the point of NEP-616 (F11/F15,
        // near-shopify/plan/00-foundations.md): the operator authorises funds to an address they
        // cannot see in the payload, so the confirm screen must derive it itself or the screen
        // is unapprovable (near-shopify/plan/01-near-actions.md, Deliverable 6.3).
        let hash =
            keccak256(&borsh::BorshSerialize::try_to_vec(&self.state_init).unwrap_or_default());
        let address = format!("0s{}", hex::encode(&hash[12..32]));
        let (data_entries, data_bytes) = (
            v1.data.len(),
            v1.data.iter().map(|(k, val)| k.len() + val.len()).sum(),
        );
        Shadow {
            address,
            deposit: self.deposit,
            code: match &v1.code {
                GlobalContractIdentifier::CodeHash(h) => format!("hash {h}"),
                GlobalContractIdentifier::AccountId(a) => format!("account {a}"),
            },
            data_entries,
            data_bytes,
        }
        .serialize(serializer)
    }
}

impl Normalizer for DeterministicStateInitAction {
    fn normalize(&self) -> String {
        "State Init".to_string()
    }
}

impl From<DeterministicStateInitAction> for Action {
    fn from(a: DeterministicStateInitAction) -> Self {
        Self::DeterministicStateInit(a)
    }
}

/// nearcore/core/primitives/src/action/delegate.rs — `pub struct NonDelegateAction(Action)`.
/// Borsh-transparent (a one-field tuple struct serialises as exactly the inner field), and
/// `#[serde(transparent)]` gives the same behaviour for JSON: each inner action renders as a
/// full `{"Action": ..., ...fields}` object, identical to a top-level action — which is what
/// makes `SignedDelegateAction`'s recursion below "reuse the normal rendering", not a special case.
#[derive(BorshSerialize, Serialize, PartialEq, Eq, Clone, Debug)]
#[serde(transparent)]
pub struct NonDelegateAction(pub Action);

impl BorshDeserialize for NonDelegateAction {
    fn deserialize(buf: &mut &[u8]) -> Result<Self, borsh::maybestd::io::Error> {
        let action = Action::deserialize(buf)?;
        if matches!(action, Action::Delegate(_)) {
            return Err(borsh::maybestd::io::Error::new(
                borsh::maybestd::io::ErrorKind::InvalidData,
                "a delegate action cannot itself contain a Delegate action (NEP-366)",
            ));
        }
        Ok(NonDelegateAction(action))
    }
}

/// The cap on how many actions one delegate can carry — same DoS rationale as
/// `MAX_STATE_INIT_DATA_ENTRIES`: attacker-controlled length, no hand-typed fallback if parsing
/// crashes. 64 is far more than any real meta-transaction near-shopify's relayer needs.
pub const MAX_DELEGATE_ACTIONS: u32 = 64;

/// nearcore/core/primitives/src/action/delegate.rs:46.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DelegateAction {
    pub sender_id: AccountId,
    pub receiver_id: AccountId,
    pub actions: alloc::vec::Vec<NonDelegateAction>,
    pub nonce: Nonce,
    /// The action is valid until this height — a signed delegate action is a bearer instrument
    /// until then, which is why it's shown prominently (see `SignedDelegateAction`'s Serialize).
    pub max_block_height: u64,
    pub public_key: PublicKey,
}

impl BorshSerialize for DelegateAction {
    fn serialize<W: borsh::maybestd::io::Write>(
        &self,
        writer: &mut W,
    ) -> Result<(), borsh::maybestd::io::Error> {
        BorshSerialize::serialize(&self.sender_id, writer)?;
        BorshSerialize::serialize(&self.receiver_id, writer)?;
        BorshSerialize::serialize(&self.actions, writer)?;
        BorshSerialize::serialize(&self.nonce, writer)?;
        BorshSerialize::serialize(&self.max_block_height, writer)?;
        BorshSerialize::serialize(&self.public_key, writer)
    }
}

impl BorshDeserialize for DelegateAction {
    fn deserialize(buf: &mut &[u8]) -> Result<Self, borsh::maybestd::io::Error> {
        let sender_id = <AccountId as BorshDeserialize>::deserialize(buf)?;
        let receiver_id = <AccountId as BorshDeserialize>::deserialize(buf)?;
        let len = read_capped_len(
            buf,
            MAX_DELEGATE_ACTIONS,
            "a delegate action's inner actions",
        )?;
        let mut actions = alloc::vec::Vec::with_capacity(len.min(64) as usize);
        for _ in 0..len {
            actions.push(NonDelegateAction::deserialize(buf)?);
        }
        let nonce = <Nonce as BorshDeserialize>::deserialize(buf)?;
        let max_block_height = <u64 as BorshDeserialize>::deserialize(buf)?;
        let public_key = <PublicKey as BorshDeserialize>::deserialize(buf)?;
        Ok(DelegateAction {
            sender_id,
            receiver_id,
            actions,
            nonce,
            max_block_height,
            public_key,
        })
    }
}

/// nearcore/core/primitives/src/action/delegate.rs:78.
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Clone, Debug)]
pub struct SignedDelegateAction {
    pub delegate_action: DelegateAction,
    pub signature: Signature,
}

impl Serialize for SignedDelegateAction {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Shadow<'a> {
            #[serde(rename = "Sender")]
            sender: String,
            #[serde(rename = "Receiver")]
            receiver: String,
            #[serde(rename = "Valid Until Block")]
            valid_until_block: u64,
            // Each entry serialises as a full top-level-shaped `{"Action": ..., ...}` object
            // (NonDelegateAction is `#[serde(transparent)]`) — this IS the recursion the
            // confirm screen needs: approving a Delegate approves everything inside it, so
            // every inner action must render exactly as if it were top-level, never a summary
            // line (near-shopify/plan/01-near-actions.md, Deliverable 6.3).
            #[serde(rename = "Actions")]
            actions: &'a [NonDelegateAction],
        }
        // The signature itself is not rendered — 64/65 raw bytes are not human-checkable data,
        // matching the existing convention of never dumping raw code bytes either.
        Shadow {
            sender: self.delegate_action.sender_id.to_string(),
            receiver: self.delegate_action.receiver_id.to_string(),
            valid_until_block: self.delegate_action.max_block_height,
            actions: &self.delegate_action.actions,
        }
        .serialize(serializer)
    }
}

impl Normalizer for SignedDelegateAction {
    fn normalize(&self) -> String {
        "Delegate".to_string()
    }
}

impl From<SignedDelegateAction> for Action {
    fn from(a: SignedDelegateAction) -> Self {
        Self::Delegate(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PublicKey;
    use crate::primitives_core::account::{AccessKeyPermission, FunctionCallPermission};
    use alloc::string::ToString;
    use hex;
    use serde_json;

    /// This test is change checker for a reason - we don't expect transaction format to change.
    /// If it does - you MUST update all of the dependencies: like nearlib and other clients.
    #[test]
    fn test_serialize_transaction() {
        let public_key: PublicKey = "22skMptHjFWNyuEWY22ftn2AbLPSYpmYwGJRGwpNHbTV"
            .parse()
            .unwrap();
        let transaction = Transaction {
            signer_id: "test.near".parse().unwrap(),
            public_key: public_key.clone(),
            nonce: 1,
            receiver_id: "123".parse().unwrap(),
            block_hash: Default::default(),
            actions: vec![
                Action::CreateAccount(CreateAccountAction {}),
                Action::DeployContract(DeployContractAction {
                    code: vec![1, 2, 3],
                }),
                Action::FunctionCall(FunctionCallAction {
                    method_name: "qqq".to_string(),
                    args: vec![1, 2, 3],
                    gas: 1_000,
                    deposit: 1_000_000,
                }),
                Action::Transfer(TransferAction { deposit: 123 }),
                Action::Stake(StakeAction {
                    public_key: public_key.clone(),
                    stake: 1_000_000,
                }),
                Action::AddKey(AddKeyAction {
                    public_key: public_key.clone(),
                    access_key: AccessKey {
                        nonce: 0,
                        permission: AccessKeyPermission::FunctionCall(FunctionCallPermission {
                            allowance: None,
                            receiver_id: "zzz".parse().unwrap(),
                            method_names: vec!["www".to_string()],
                        }),
                    },
                }),
                Action::DeleteKey(DeleteKeyAction { public_key }),
                Action::DeleteAccount(DeleteAccountAction {
                    beneficiary_id: "123".parse().unwrap(),
                }),
            ],
        };
        let result = BorshSerialize::try_to_vec(&transaction).unwrap();
        assert_eq!(
            "09000000746573742e6e656172000f56a5f028dfc089ec7c39c1183b321b4d8f89ba5bec9e1762803cc2491f6ef8010000000000000003000000313233000000000000000000000000000000000000000000000000000000000000000008000000000103000000010203020300000071717103000000010203e80300000000000040420f00000000000000000000000000037b0000000000000000000000000000000440420f00000000000000000000000000000f56a5f028dfc089ec7c39c1183b321b4d8f89ba5bec9e1762803cc2491f6ef805000f56a5f028dfc089ec7c39c1183b321b4d8f89ba5bec9e1762803cc2491f6ef800000000000000000000030000007a7a7a010000000300000077777706000f56a5f028dfc089ec7c39c1183b321b4d8f89ba5bec9e1762803cc2491f6ef80703000000313233",
            hex::encode(result),
        );
    }

    // -----------------------------------------------------------------------------------------
    // Discriminants 8-11 (near-shopify plan phase 01, Deliverable 6).
    // -----------------------------------------------------------------------------------------

    fn a_public_key() -> PublicKey {
        "22skMptHjFWNyuEWY22ftn2AbLPSYpmYwGJRGwpNHbTV"
            .parse()
            .unwrap()
    }

    #[test]
    fn every_new_action_round_trips_through_borsh() {
        let cases: Vec<Action> = vec![
            Action::DeployGlobalContract(DeployGlobalContractAction {
                code: vec![9, 9, 9],
                deploy_mode: GlobalContractDeployMode::CodeHash,
            }),
            Action::UseGlobalContract(UseGlobalContractAction {
                contract_identifier: GlobalContractIdentifier::CodeHash(CryptoHash([7u8; 32])),
            }),
            Action::DeterministicStateInit(DeterministicStateInitAction {
                state_init: DeterministicAccountStateInit::V1(DeterministicAccountStateInitV1 {
                    code: GlobalContractIdentifier::CodeHash(CryptoHash([8u8; 32])),
                    data: BTreeMap::new(),
                }),
                deposit: 1_000,
            }),
            Action::Delegate(SignedDelegateAction {
                delegate_action: DelegateAction {
                    sender_id: "a.testnet".parse().unwrap(),
                    receiver_id: "b.testnet".parse().unwrap(),
                    actions: vec![NonDelegateAction(Action::Transfer(TransferAction {
                        deposit: 1,
                    }))],
                    nonce: 1,
                    max_block_height: 100,
                    public_key: a_public_key(),
                },
                signature: Signature::ED25519([0u8; 64]),
            }),
        ];
        for action in cases {
            let bytes = BorshSerialize::try_to_vec(&action).unwrap();
            let back = Action::try_from_slice(&bytes).unwrap();
            assert_eq!(action, back, "{action:?}");
        }
    }

    #[test]
    fn discriminants_8_through_11_are_declaration_order() {
        // Borsh 0.9 tags by declaration order; this is what keeps that property honest as the
        // file changes — DeleteAccount stays 7, and the four new variants must read 8..=11.
        assert_eq!(
            BorshSerialize::try_to_vec(&Action::DeleteAccount(DeleteAccountAction {
                beneficiary_id: "a.testnet".parse().unwrap(),
            }))
            .unwrap()[0],
            7
        );
        assert_eq!(
            BorshSerialize::try_to_vec(&Action::Delegate(SignedDelegateAction {
                delegate_action: DelegateAction {
                    sender_id: "a.testnet".parse().unwrap(),
                    receiver_id: "b.testnet".parse().unwrap(),
                    actions: vec![],
                    nonce: 1,
                    max_block_height: 1,
                    public_key: a_public_key(),
                },
                signature: Signature::ED25519([0u8; 64]),
            }))
            .unwrap()[0],
            8
        );
        assert_eq!(
            BorshSerialize::try_to_vec(&Action::DeployGlobalContract(DeployGlobalContractAction {
                code: vec![],
                deploy_mode: GlobalContractDeployMode::CodeHash,
            }))
            .unwrap()[0],
            9
        );
        assert_eq!(
            BorshSerialize::try_to_vec(&Action::UseGlobalContract(UseGlobalContractAction {
                contract_identifier: GlobalContractIdentifier::CodeHash(CryptoHash([0u8; 32])),
            }))
            .unwrap()[0],
            10
        );
        assert_eq!(
            BorshSerialize::try_to_vec(&Action::DeterministicStateInit(
                DeterministicStateInitAction {
                    state_init: DeterministicAccountStateInit::V1(
                        DeterministicAccountStateInitV1 {
                            code: GlobalContractIdentifier::CodeHash(CryptoHash([0u8; 32])),
                            data: BTreeMap::new(),
                        }
                    ),
                    deposit: 0,
                }
            ))
            .unwrap()[0],
            11
        );
    }

    #[test]
    fn an_action_this_firmware_does_not_know_is_refused_not_guessed() {
        // Tag 12 (TransferToGasKey) doesn't exist here — F12's property (an unrecognised
        // variant borsh-fails rather than rendering badly) must survive this extension.
        let bytes = [12u8];
        assert!(Action::try_from_slice(&bytes).is_err());
    }

    #[test]
    fn a_nested_delegate_is_refused() {
        let inner_bytes = BorshSerialize::try_to_vec(&Action::Delegate(SignedDelegateAction {
            delegate_action: DelegateAction {
                sender_id: "a.testnet".parse().unwrap(),
                receiver_id: "b.testnet".parse().unwrap(),
                actions: vec![],
                nonce: 1,
                max_block_height: 1,
                public_key: a_public_key(),
            },
            signature: Signature::ED25519([0u8; 64]),
        }))
        .unwrap();
        let mut buf: &[u8] = &inner_bytes;
        assert!(
            NonDelegateAction::deserialize(&mut buf).is_err(),
            "NEP-366 forbids a delegate inside a delegate"
        );
    }

    #[test]
    fn an_oversized_data_map_is_refused_before_full_allocation() {
        // A hand-crafted borsh buffer for DeterministicAccountStateInitV1: a CodeHash identifier
        // (tag 0 + 32 bytes) followed by a data-map length claiming far more entries than
        // MAX_STATE_INIT_DATA_ENTRIES allows. Must fail on the length check, not attempt to
        // read (or allocate for) that many entries.
        let mut bytes = vec![0u8]; // GlobalContractIdentifier::CodeHash tag
        bytes.extend_from_slice(&[0u8; 32]); // the hash itself
        bytes.extend_from_slice(&(MAX_STATE_INIT_DATA_ENTRIES + 1).to_le_bytes());
        let mut buf: &[u8] = &bytes;
        let err = DeterministicAccountStateInitV1::deserialize(&mut buf).unwrap_err();
        assert!(err.to_string().contains("more than"), "{err}");
    }

    #[test]
    fn a_delegate_action_shows_every_inner_action() {
        let signed = SignedDelegateAction {
            delegate_action: DelegateAction {
                sender_id: "sender.testnet".parse().unwrap(),
                receiver_id: "receiver.testnet".parse().unwrap(),
                actions: vec![
                    NonDelegateAction(Action::Transfer(TransferAction { deposit: 5 })),
                    NonDelegateAction(Action::DeleteKey(DeleteKeyAction {
                        public_key: a_public_key(),
                    })),
                ],
                nonce: 1,
                max_block_height: 999,
                public_key: a_public_key(),
            },
            signature: Signature::ED25519([0u8; 64]),
        };
        let json = serde_json::to_string(&signed).unwrap();
        assert!(json.contains("\"Sender\":\"sender.testnet\""), "{json}");
        assert!(json.contains("\"Receiver\":\"receiver.testnet\""), "{json}");
        assert!(json.contains("\"Valid Until Block\":999"), "{json}");
        // Each inner action must render exactly as a top-level action would — recursion, not a
        // one-line summary (near-shopify/plan/01-near-actions.md, Deliverable 6.3).
        assert!(json.contains("\"Action\":\"Transfer\""), "{json}");
        assert!(json.contains("\"Action\":\"Delete Key\""), "{json}");
    }

    #[test]
    fn a_global_deploy_says_whether_the_owner_can_replace_the_code() {
        let immutable = DeployGlobalContractAction {
            code: vec![1, 2, 3],
            deploy_mode: GlobalContractDeployMode::CodeHash,
        };
        let mutable = DeployGlobalContractAction {
            code: vec![1, 2, 3],
            deploy_mode: GlobalContractDeployMode::AccountId,
        };
        let immutable_json = serde_json::to_string(&immutable).unwrap();
        let mutable_json = serde_json::to_string(&mutable).unwrap();
        assert!(
            immutable_json.contains("Immutable (by code hash)"),
            "{immutable_json}"
        );
        assert!(
            mutable_json.contains("Owner can replace this code later"),
            "{mutable_json}"
        );
        // Never the bare enum name.
        assert!(!immutable_json.contains("CodeHash"), "{immutable_json}");
        assert!(!mutable_json.contains("\"AccountId\""), "{mutable_json}");
    }

    /// The cross-implementation check: this exact vector is also pinned in
    /// `near_tx::tx::render_tests::a_deterministic_address_matches_the_one_near_cli_derives`
    /// (near_tx/src/tx.rs) — captured from near-cli-rs 0.29.0's own NEP-616 derivation. Both
    /// sides hardcode the same bytes with a comment pointing at the other, deliberately, not via
    /// a shared file: this crate is a vendored, independently-owned submodule and must never gain
    /// a build/test dependency reaching outside its own tree, and the vector itself is a
    /// permanent regression pin with no planned recapture (ongoing near-cli-rs drift is instead
    /// caught continuously by `make tx-oracle`, which runs differentially against near-cli-rs's
    /// current version on every run) — so a shared file would only add path/ownership complexity
    /// with nothing to keep in sync. See near-shopify/plan/01-near-actions.md Deliverable 6.5.
    #[test]
    fn a_state_init_computes_the_same_address_near_tx_derives() {
        let code_hash: [u8; 32] = {
            let v = hex::decode("f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2")
                .unwrap();
            v.try_into().unwrap()
        };
        let action = DeterministicStateInitAction {
            state_init: DeterministicAccountStateInit::V1(DeterministicAccountStateInitV1 {
                code: GlobalContractIdentifier::CodeHash(CryptoHash(code_hash)),
                data: BTreeMap::new(),
            }),
            deposit: 1_000,
        };
        let json = serde_json::to_string(&action).unwrap();
        assert!(
            json.contains("\"Address\":\"0s889b0a9aef03a0aecdc11056a5a4f7831fc96b9e\""),
            "{json}"
        );
    }
}
