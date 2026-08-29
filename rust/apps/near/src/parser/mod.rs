pub mod detail;
pub mod overview;
pub mod structs;
mod transaction;
pub mod utils;

use crate::errors::{NearError, Result};
use crate::parser::overview::{NearTxOverview, NearTxOverviewGeneral, NearTxOverviewTransfer};
use crate::parser::structs::{NearTxDisplayType, ParsedNearTx};
use crate::parser::transaction::{Action, Normalizer, Transaction};
use crate::parser::utils::args_display;
use crate::parser::utils::format_allowance;
use crate::parser::utils::format_amount;
use crate::parser::utils::sanitize_display;
use crate::parser::utils::Merge;
use crate::primitives_core::account::AccessKeyPermission;
use alloc::format;
use alloc::string::{String, ToString};

use alloc::vec::Vec;
use borsh::BorshDeserialize;
use serde_json;
use serde_json::{json, Value};

impl ParsedNearTx {
    pub fn build(data: &Vec<u8>) -> Result<Self> {
        let tx = Transaction::try_from_slice(data).map_err(|err| {
            NearError::ParseTxError(format!("borsh deserialize failed {:?}", err.to_string()))
        })?;
        let display_type = Self::detect_display_type(&tx);
        let parsed_overview = Self::build_overview(&display_type, &tx)?;
        let parsed_detail = Self::build_detail(&tx)?;
        Ok(Self {
            display_type,
            overview: parsed_overview,
            detail: parsed_detail,
            // A NEAR transaction, the NearSignRequest UR wrapping it, and the derivation path
            // all carry no chain-id/network field (checked ur-registry-1.0.8's NearSignRequest:
            // request_id, sign_data, derivation_path, account, origin — none of it) — so there
            // is no data this device could use to say "Mainnet" or "Testnet" correctly. Every
            // testnet transaction this project has ever signed was previously displayed as
            // Mainnet (near-shopify/plan/01-near-actions.md, Deliverable 6.3), which is worse
            // than saying nothing: stop claiming a specific network rather than guess one.
            network: "NEAR".to_string(),
        })
    }

    fn detect_display_type(tx: &Transaction) -> NearTxDisplayType {
        if tx.actions.len() == 1 {
            let action = &tx.actions[0];
            match action {
                Action::Transfer(_) => NearTxDisplayType::Transfer,
                _ => NearTxDisplayType::General,
            }
        } else {
            NearTxDisplayType::General
        }
    }
    fn build_detail(tx: &Transaction) -> Result<String> {
        let detail_str = serde_json::to_string(&tx.actions)?;
        let mut result = json!([{
            "From": tx.signer_id.to_string(),
            "To": tx.receiver_id.to_string()
        }]);
        let action_values: Value = serde_json::from_str(detail_str.as_str())?;
        result.merge(action_values);
        Ok(serde_json::to_string(&result)?)
    }
    fn build_overview(
        display_type: &NearTxDisplayType,
        tx: &Transaction,
    ) -> Result<NearTxOverview> {
        match display_type {
            NearTxDisplayType::Transfer => Self::build_transfer_overview(tx),
            NearTxDisplayType::General => Self::build_general_overview(tx),
        }
    }

    fn build_transfer_overview(tx: &Transaction) -> Result<NearTxOverview> {
        match &tx.actions[0] {
            Action::Transfer(action) => Ok(NearTxOverview::Transfer(NearTxOverviewTransfer {
                value: format_amount(action.deposit),
                main_action: "Transfer".to_string(),
                from: tx.signer_id.to_string(),
                to: tx.receiver_id.to_string(),
            })),
            _ => Err(NearError::ParseTxError(format!(
                "invalid action, expect transfer, found {:?}",
                &tx.actions
            ))),
        }
    }

    fn build_general_overview(tx: &Transaction) -> Result<NearTxOverview> {
        let action_list = tx
            .actions
            .iter()
            .map(|action| match action {
                // A function call's operator-relevant content is its `args` (a token transfer's
                // recipient and amount, a swap's parameters), which the bare "Function Call" label
                // hides. Surface method + args here, on the Overview — the screen the operator reads
                // first — so two calls differing only in args no longer render identically. Mirrors
                // Solana's general overview, which lists each instruction's program and data.
                // Both the method and the args are attacker-controlled and freeform, so both are run
                // through sanitize_display: control characters (a newline especially, which could
                // forge extra "Method:"/"Args:" lines in this multi-line label) become spaces.
                // args_display already sanitises, so only the method needs it here.
                Action::FunctionCall(fc) => {
                    let mut entry =
                        format!("{}\nMethod: {}", fc.normalize(), sanitize_display(&fc.method_name));
                    // A call with no args (deposit_and_stake, unstake_all, withdraw_all) gets no
                    // `Args:` line at all — matching the `skip_serializing_if` on the Details side —
                    // rather than a trailing `Args: ` that reads as an empty argument.
                    if !fc.args.is_empty() {
                        entry.push_str("\nArgs: ");
                        entry.push_str(&args_display(&fc.args));
                    }
                    entry
                }
                // AddKey's operator-relevant content is *what the granted key can do*: a full-access
                // key is total account control, a function-call key is scoped to one contract and a
                // set of methods. The bare "Add Key" label hides all of it, so a full-access grant
                // and a pool-scoped staking key rendered a byte-identical Overview — the
                // addkey-permission collision (keystone-guide-kit/security_lab/
                // S-P2-CONFIRM-DIFFERENTIAL.md). Surface the granted key and its permission here, on
                // the screen the operator reads first, the same way FunctionCall surfaces method/
                // args above. `receiver_id` and the method names are attacker-controlled freeform
                // (`receiver_id` is a String, not an AccountId — testnet genesis holds invalid ones)
                // so both run through sanitize_display, exactly like the method/args above.
                Action::AddKey(ak) => {
                    let mut entry = format!("Add Key\nPublic Key: {}", ak.public_key);
                    match &ak.access_key.permission {
                        AccessKeyPermission::FullAccess => entry.push_str("\nAccess: Full Access"),
                        AccessKeyPermission::FunctionCall(fc) => {
                            entry.push_str("\nAccess: Function Call");
                            entry.push_str("\nContract: ");
                            entry.push_str(&sanitize_display(&fc.receiver_id));
                            entry.push_str("\nMethods: ");
                            if fc.method_names.is_empty() {
                                // An empty method set authorises *any* method on the contract — the
                                // broadest function-call grant — so say so, not leave a blank line.
                                entry.push_str("any");
                            } else {
                                let methods: Vec<String> =
                                    fc.method_names.iter().map(|m| sanitize_display(m)).collect();
                                entry.push_str(&methods.join(", "));
                            }
                            entry.push_str("\nAllowance: ");
                            entry.push_str(&format_allowance(&fc.allowance));
                        }
                    }
                    entry
                }
                other => other.normalize(),
            })
            .collect();
        Ok(NearTxOverview::General(NearTxOverviewGeneral {
            from: tx.signer_id.to_string(),
            to: tx.receiver_id.to_string(),
            action_list,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::parse;
    use crate::parser::overview::NearTxOverview;
    use alloc::string::ToString;
    use serde_json::{json, Value};
    use ur_registry::near::near_sign_request::NearSignRequest;
    use {hex, serde_json};

    #[test]
    fn a_transaction_is_not_labelled_near_mainnet() {
        // Nothing in a NEAR transaction, its NearSignRequest UR wrapper, or the derivation path
        // says which network it's for (near-shopify/plan/01-near-actions.md, Deliverable 6.3) —
        // this only pins that the device stopped claiming a specific one it cannot know.
        let cbor_str = "a301d82550ed2ab5bb9cc24571b7dcbec9e5bc7b79028159016040000000333138323466626632343335666231656361346466633339373734313833636232356631336231303335326435643533323736313662353963333565616539660031824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f442d16f48e3f00003c000000613062383639393163363231386233366331643139643461326539656230636533363036656234382e666163746f72792e6272696467652e6e6561728db41252bff5ecc0b28f55fc078d1b2de23990f728fc762502688d340bb42c9301000000020b00000066745f7472616e73666572630000007b22616d6f756e74223a223232303030222c2272656365697665725f6964223a2230346361353938333132633631656464646165656531333035333938303366323931313464363534353537643330333066313561623533316335653730613264227d00e057eb481b00000100000000000000000000000000000003d90130a20186182cf519018df500f5021a707eed6c";
        let near_sign_request = NearSignRequest::try_from(hex::decode(cbor_str).unwrap()).unwrap();
        let sign_data = near_sign_request.get_sign_data();
        let parsed = crate::parse(&sign_data[0]).unwrap();
        assert_eq!(parsed.network, "NEAR");
        assert_ne!(parsed.network, "Near Mainnet");
    }

    #[test]
    fn test_parse_transaction_1() {
        // function call
        let cbor_str = "a301d82550ed2ab5bb9cc24571b7dcbec9e5bc7b79028159016040000000333138323466626632343335666231656361346466633339373734313833636232356631336231303335326435643533323736313662353963333565616539660031824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f442d16f48e3f00003c000000613062383639393163363231386233366331643139643461326539656230636533363036656234382e666163746f72792e6272696467652e6e6561728db41252bff5ecc0b28f55fc078d1b2de23990f728fc762502688d340bb42c9301000000020b00000066745f7472616e73666572630000007b22616d6f756e74223a223232303030222c2272656365697665725f6964223a2230346361353938333132633631656464646165656531333035333938303366323931313464363534353537643330333066313561623533316335653730613264227d00e057eb481b00000100000000000000000000000000000003d90130a20186182cf519018df500f5021a707eed6c";
        let near_sign_request = NearSignRequest::try_from(hex::decode(cbor_str).unwrap()).unwrap();
        let sign_data = near_sign_request.get_sign_data();
        let parsed = parse(&sign_data[0]).unwrap();
        match parsed.overview {
            NearTxOverview::General(overview) => {
                assert_eq!(
                    "31824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f".to_string(),
                    overview.from
                );
                assert_eq!(
                    "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.factory.bridge.near".to_string(),
                    overview.to
                );
                assert_eq!(1, overview.action_list.len());
                assert_eq!(
                    "Function Call\nMethod: ft_transfer\nArgs: {\"amount\":\"22000\",\"receiver_id\":\"04ca598312c61edddaeee130539803f29114d654557d3030f15ab531c5e70a2d\"}",
                    overview.action_list[0]
                );
            }
            _ => panic!("error overview type"),
        };
        let parsed_detail: Value = serde_json::from_str(parsed.detail.as_str()).unwrap();
        let expected_detail = json!([
            {
                "From": "31824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f",
                "To": "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.factory.bridge.near"
            },
            {
                "Action": "Function Call",
                "Deposit Value": "1 Yocto",
                "Method": "ft_transfer",
                "Args": "{\"amount\":\"22000\",\"receiver_id\":\"04ca598312c61edddaeee130539803f29114d654557d3030f15ab531c5e70a2d\"}",
                "Prepaid Gas": "30 TGas"
            }
        ]);
        assert_eq!(expected_detail, parsed_detail);
    }

    #[test]
    fn test_parse_transaction_2() {
        // createAccount
        let cbor_str = "a401d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d028258a81200000073776561745f77656c636f6d652e6e6561720031824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f002e1519ae5900004000000033313832346662663234333566623165636134646663333937373431383363623235663133623130333532643564353332373631366235396333356561653966fef24c7d5a41e0e6858d4e54439322d754f93e33c55281dddb5b75dc33f10e67010000000058a81200000073776561745f77656c636f6d652e6e6561720031824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f002e1519ae5900004000000033313832346662663234333566623165636134646663333937373431383363623235663133623130333532643564353332373631366235396333356561653966fef24c7d5a41e0e6858d4e54439322d754f93e33c55281dddb5b75dc33f10e67010000000003d90130a2018a182cf519018df500f500f501f5021a78230804056a6e65617277616c6c6574";
        let near_sign_request = NearSignRequest::try_from(hex::decode(cbor_str).unwrap()).unwrap();
        let sign_data = near_sign_request.get_sign_data();
        let parsed = parse(&sign_data[0]).unwrap();
        match parsed.overview {
            NearTxOverview::General(overview) => {
                assert_eq!("sweat_welcome.near".to_string(), overview.from);
                assert_eq!(
                    "31824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f".to_string(),
                    overview.to
                );
                assert_eq!(1, overview.action_list.len());
                assert_eq!("Create Account", overview.action_list[0]);
            }
            _ => panic!("error overview type"),
        };
        let parsed_detail: Value = serde_json::from_str(parsed.detail.as_str()).unwrap();
        let expected_detail = json!([
            {
                "From": "sweat_welcome.near",
                "To": "31824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f"
            },
            {
                "Action": "Create Account"
            }
        ]);
        assert_eq!(expected_detail, parsed_detail);
    }

    #[test]
    fn test_parse_transaction_3() {
        // transfer
        let cbor_str = "a401d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d028158b81200000073776561745f77656c636f6d652e6e6561720031824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f002e1519ae5900004000000033313832346662663234333566623165636134646663333937373431383363623235663133623130333532643564353332373631366235396333356561653966fef24c7d5a41e0e6858d4e54439322d754f93e33c55281dddb5b75dc33f10e6701000000037b00000000000000000000000000000003d90130a2018a182cf519018df500f500f501f5021a78230804056a6e65617277616c6c6574";
        let near_sign_request = NearSignRequest::try_from(hex::decode(cbor_str).unwrap()).unwrap();
        let sign_data = near_sign_request.get_sign_data();
        let parsed = parse(&sign_data[0]).unwrap();
        match parsed.overview {
            NearTxOverview::Transfer(overview) => {
                assert_eq!("sweat_welcome.near".to_string(), overview.from);
                assert_eq!(
                    "31824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f".to_string(),
                    overview.to
                );
                assert_eq!("Transfer".to_string(), overview.main_action);
                assert_eq!("123 Yocto", overview.value);
            }
            _ => panic!("error overview type"),
        };
        let parsed_detail: Value = serde_json::from_str(parsed.detail.as_str()).unwrap();
        let expected_detail = json!([
            {
                "From": "sweat_welcome.near",
                "To": "31824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f"
            },
            {
                "Action": "Transfer",
                "Value": "123 Yocto"
            }
        ]);
        assert_eq!(expected_detail, parsed_detail);
    }

    #[test]
    fn test_parse_transaction_4() {
        // transfer Big
        let cbor_str = "a401d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d0281587c09000000746573742e6e65617200917b3d268d4b58f7fec1b150bd68d69be3ee5d4cc39855e341538465bb77860d01000000000000000d00000077686174657665722e6e656172fef24c7d5a41e0e6858d4e54439322d754f93e33c55281dddb5b75dc33f10e6701000000030000485637193cc3430000000000000003d90130a2018a182cf519018df500f500f501f5021a78230804056a6e65617277616c6c6574";
        let near_sign_request = NearSignRequest::try_from(hex::decode(cbor_str).unwrap()).unwrap();
        let sign_data = near_sign_request.get_sign_data();
        let parsed = parse(&sign_data[0]).unwrap();
        match parsed.overview {
            NearTxOverview::Transfer(overview) => {
                assert_eq!("test.near".to_string(), overview.from);
                assert_eq!("whatever.near".to_string(), overview.to);
                assert_eq!("Transfer".to_string(), overview.main_action);
                assert_eq!("0.00125 NEAR", overview.value);
            }
            _ => panic!("error overview type"),
        };
        let parsed_detail: Value = serde_json::from_str(parsed.detail.as_str()).unwrap();
        let expected_detail = json!([
            {
                "From": "test.near",
                "To": "whatever.near"
            },
            {
                "Action": "Transfer",
                "Value": "0.00125 NEAR"
            }
        ]);
        assert_eq!(expected_detail, parsed_detail);
    }

    #[test]
    fn test_parse_transaction_5() {
        // mixed
        let cbor_str = "a401d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d028159014609000000746573742e6e65617200917b3d268d4b58f7fec1b150bd68d69be3ee5d4cc39855e341538465bb77860d01000000000000000d00000077686174657665722e6e656172fef24c7d5a41e0e6858d4e54439322d754f93e33c55281dddb5b75dc33f10e6708000000000103000000010203020300000071717103000000010203e80300000000000040420f00000000000000000000000000037b0000000000000000000000000000000440420f000000000000000000000000000031824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f050031824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f00000000000000000000030000007a7a7a0100000003000000777777060031824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f070300000031323303d90130a2018a182cf519018df500f500f501f5021a78230804056a6e65617277616c6c6574";
        let near_sign_request = NearSignRequest::try_from(hex::decode(cbor_str).unwrap()).unwrap();
        let sign_data = near_sign_request.get_sign_data();
        let parsed = parse(&sign_data[0]).unwrap();
        match parsed.overview {
            NearTxOverview::General(overview) => {
                assert_eq!("test.near".to_string(), overview.from);
                assert_eq!("whatever.near".to_string(), overview.to);
                assert_eq!(8, overview.action_list.len());
                assert_eq!("Create Account", overview.action_list[0]);
                assert_eq!("Deploy Contract", overview.action_list[1]);
                assert_eq!(
                    // [1, 2, 3] control bytes are sanitised to three spaces on the Overview too.
                    format!("Function Call\nMethod: qqq\nArgs: {}", " ".repeat(3)),
                    overview.action_list[2]
                );
                assert_eq!("Transfer", overview.action_list[3]);
                assert_eq!("Stake", overview.action_list[4]);
                assert_eq!(
                    "Add Key\nPublic Key: ed25519:4LGE55cdv7DRfErMovJY3Hm6jQrzRFyGfGpAW9vnb8Sz\n\
                     Access: Function Call\nContract: zzz\nMethods: www\nAllowance: Unlimited",
                    overview.action_list[5]
                );
                assert_eq!("Delete Key", overview.action_list[6]);
                assert_eq!("Delete Account", overview.action_list[7]);
            }
            _ => panic!("error overview type"),
        };
        let parsed_detail: Value = serde_json::from_str(parsed.detail.as_str()).unwrap();
        let expected_detail = json!([
            {
                "From": "test.near",
                "To": "whatever.near"
            },
            {
                "Action": "Create Account"
            },
            {
                "Action": "Deploy Contract"
            },
            {
                "Action": "Function Call",
                "Deposit Value": "1000000 Yocto",
                "Method": "qqq",
                // [1, 2, 3] are control bytes, so sanitize_display renders them as three spaces.
                "Args": "   ",
                "Prepaid Gas": "0.000000001 TGas"
            },
            {
                "Action": "Transfer",
                "Value": "123 Yocto"
            },
            {
                "Action": "Stake",
                "Public Key": "ed25519:4LGE55cdv7DRfErMovJY3Hm6jQrzRFyGfGpAW9vnb8Sz",
                "Stake Amount": "1000000 Yocto"
            },
            {
                "Action": "Add Key",
                "Public Key": "ed25519:4LGE55cdv7DRfErMovJY3Hm6jQrzRFyGfGpAW9vnb8Sz",
                "Access Key Permission": "FunctionCall",
                "Access Key Receiver ID": "zzz",
                "Access Key Allowance": "Unlimited",
                "Access Key Nonce": 0,
                "Access Key Method Names": ["www"]
            },
            {
                "Action": "Delete Key",
                "Public Key": "ed25519:4LGE55cdv7DRfErMovJY3Hm6jQrzRFyGfGpAW9vnb8Sz"
            },
            {
                "Action": "Delete Account",
                "Beneficiary ID": "123"
            }
        ]);
        assert_eq!(expected_detail, parsed_detail);
    }

    #[test]
    fn test_parse_transaction_6() {
        // access key full access
        let cbor_str = "a401d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d0281589609000000746573742e6e65617200917b3d268d4b58f7fec1b150bd68d69be3ee5d4cc39855e341538465bb77860d01000000000000000d00000077686174657665722e6e656172fef24c7d5a41e0e6858d4e54439322d754f93e33c55281dddb5b75dc33f10e6701000000050031824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f00000000000000000103d90130a2018a182cf519018df500f500f501f5021a78230804056a6e65617277616c6c6574";
        let near_sign_request = NearSignRequest::try_from(hex::decode(cbor_str).unwrap()).unwrap();
        let sign_data = near_sign_request.get_sign_data();
        let parsed = parse(&sign_data[0]).unwrap();
        match parsed.overview {
            NearTxOverview::General(overview) => {
                assert_eq!("test.near".to_string(), overview.from);
                assert_eq!("whatever.near".to_string(), overview.to);
                assert_eq!(1, overview.action_list.len());
                assert_eq!(
                    "Add Key\nPublic Key: ed25519:4LGE55cdv7DRfErMovJY3Hm6jQrzRFyGfGpAW9vnb8Sz\n\
                     Access: Full Access",
                    overview.action_list[0]
                );
            }
            _ => panic!("error overview type"),
        };
        let parsed_detail: Value = serde_json::from_str(parsed.detail.as_str()).unwrap();
        let expected_detail = json!([
            {
                "From": "test.near",
                "To": "whatever.near"
            },
            {
                "Action": "Add Key",
                "Access Key Permission": "FullAccess",
                "Access Key Nonce": 0,
                "Public Key": "ed25519:4LGE55cdv7DRfErMovJY3Hm6jQrzRFyGfGpAW9vnb8Sz"
            }
        ]);
        assert_eq!(expected_detail, parsed_detail);
    }

    #[test]
    fn test_parse_transaction_7() {
        // Function Call
        let cbor_str = "a401d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d028158b509000000746573742e6e65617200917b3d268d4b58f7fec1b150bd68d69be3ee5d4cc39855e341538465bb77860d01000000000000000d00000077686174657665722e6e656172fef24c7d5a41e0e6858d4e54439322d754f93e33c55281dddb5b75dc33f10e67010000000203000000717171260000007b22616d6f756e74223a2234373030303030303030303030303030303030303030303030227d00d098d4af710000000000bdf4eb8b5efacf02000000000003d90130a2018a182cf519018df500f500f501f5021a78230804056a6e65617277616c6c6574";
        let near_sign_request = NearSignRequest::try_from(hex::decode(cbor_str).unwrap()).unwrap();
        let sign_data = near_sign_request.get_sign_data();
        let parsed = parse(&sign_data[0]).unwrap();
        match parsed.overview {
            NearTxOverview::General(overview) => {
                assert_eq!("test.near".to_string(), overview.from);
                assert_eq!("whatever.near".to_string(), overview.to);
                assert_eq!(1, overview.action_list.len());
                assert_eq!(
                    "Function Call\nMethod: qqq\nArgs: {\"amount\":\"4700000000000000000000000\"}",
                    overview.action_list[0]
                );
            }
            _ => panic!("error overview type"),
        };
        let parsed_detail: Value = serde_json::from_str(parsed.detail.as_str()).unwrap();
        let expected_detail = json!([
            {"From":"test.near","To":"whatever.near"},
            {"Action":"Function Call","Deposit Value":"3.4 NEAR","Method":"qqq","Args":"{\"amount\":\"4700000000000000000000000\"}","Prepaid Gas":"125 TGas"}]);
        assert_eq!(expected_detail, parsed_detail);
    }

    #[test]
    fn test_parse_transaction_8() {
        // Function Call
        let cbor_str = "a401d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d0281588d09000000746573742e6e65617200917b3d268d4b58f7fec1b150bd68d69be3ee5d4cc39855e341538465bb77860d01000000000000000d00000077686174657665722e6e656172fef24c7d5a41e0e6858d4e54439322d754f93e33c55281dddb5b75dc33f10e67010000000600456d45cac4994a2a4a3bc83d433ac04d410661d8a64b11060de10976051939c503d90130a2018a182cf519018df500f500f501f5021a78230804056a6e65617277616c6c6574";
        let near_sign_request = NearSignRequest::try_from(hex::decode(cbor_str).unwrap()).unwrap();
        let sign_data = near_sign_request.get_sign_data();
        let parsed = parse(&sign_data[0]).unwrap();
        match parsed.overview {
            NearTxOverview::General(overview) => {
                assert_eq!("test.near".to_string(), overview.from);
                assert_eq!("whatever.near".to_string(), overview.to);
                assert_eq!(1, overview.action_list.len());
                assert_eq!("Delete Key", overview.action_list[0]);
            }
            _ => panic!("error overview type"),
        };
        let parsed_detail: Value = serde_json::from_str(parsed.detail.as_str()).unwrap();
        let expected_detail = json!( [
            {"From":"test.near","To":"whatever.near"},
            {"Action":"Delete Key","Public Key":"ed25519:5g1moPK2ijKpFocxeDRhvnRkfEZQ93wczPBB9WSQk6EQ"}]);
        assert_eq!(expected_detail, parsed_detail);
    }

    #[test]
    fn an_empty_args_call_shows_no_args_line_on_either_screen() {
        // deposit_and_stake / unstake_all / withdraw_all carry no args. The confirm screen must
        // not invent an empty `Args:` line for them — that reads as "an empty argument" rather
        // than "this call takes none". Build the borsh transaction directly and parse it.
        use crate::parser::transaction::{Action, FunctionCallAction, Transaction};
        use borsh::BorshSerialize;

        let tx = Transaction {
            signer_id: "test.near".parse().unwrap(),
            public_key: "22skMptHjFWNyuEWY22ftn2AbLPSYpmYwGJRGwpNHbTV"
                .parse()
                .unwrap(),
            nonce: 1,
            receiver_id: "pool.near".parse().unwrap(),
            block_hash: Default::default(),
            actions: alloc::vec![Action::FunctionCall(FunctionCallAction {
                method_name: "deposit_and_stake".to_string(),
                args: alloc::vec![],
                gas: 30_000_000_000_000,
                deposit: 0,
            })],
        };
        let bytes = BorshSerialize::try_to_vec(&tx).unwrap();
        let parsed = parse(&bytes).unwrap();
        match parsed.overview {
            NearTxOverview::General(overview) => {
                assert_eq!(1, overview.action_list.len());
                assert_eq!(
                    "Function Call\nMethod: deposit_and_stake",
                    overview.action_list[0]
                );
                assert!(!overview.action_list[0].contains("Args"));
            }
            _ => panic!("error overview type"),
        };
        let parsed_detail: Value = serde_json::from_str(parsed.detail.as_str()).unwrap();
        // The Details entry for the call carries Method but no Args key at all.
        let call = &parsed_detail.as_array().unwrap()[1];
        assert_eq!(call["Method"], "deposit_and_stake");
        assert!(call.get("Args").is_none(), "{parsed_detail}");
    }

    #[test]
    fn a_full_access_grant_and_a_function_call_grant_render_different_overviews() {
        // The addkey-permission confirm-screen collision: same account, same granted key, but one
        // grants total account control and the other a pool-scoped staking key. The Overview — the
        // screen the operator reads first, and the one the differential fingerprints — must render
        // the difference, not the bare "Add Key" that hid it (S-P2-CONFIRM-DIFFERENTIAL).
        use crate::parser::transaction::{Action, AddKeyAction, Transaction};
        use crate::primitives_core::account::{
            AccessKey, AccessKeyPermission, FunctionCallPermission,
        };
        use borsh::BorshSerialize;

        let granted: crate::crypto::PublicKey = "22skMptHjFWNyuEWY22ftn2AbLPSYpmYwGJRGwpNHbTV"
            .parse()
            .unwrap();
        let overview = |permission: AccessKeyPermission| {
            let tx = Transaction {
                signer_id: "alice.near".parse().unwrap(),
                public_key: "22skMptHjFWNyuEWY22ftn2AbLPSYpmYwGJRGwpNHbTV".parse().unwrap(),
                nonce: 1,
                receiver_id: "alice.near".parse().unwrap(),
                block_hash: Default::default(),
                actions: alloc::vec![Action::AddKey(AddKeyAction {
                    public_key: granted.clone(),
                    access_key: AccessKey { nonce: 0, permission },
                })],
            };
            let bytes = BorshSerialize::try_to_vec(&tx).unwrap();
            match parse(&bytes).unwrap().overview {
                NearTxOverview::General(o) => o.action_list[0].clone(),
                _ => panic!("expected a general overview"),
            }
        };
        let full = overview(AccessKeyPermission::FullAccess);
        let restricted = overview(AccessKeyPermission::FunctionCall(FunctionCallPermission {
            allowance: Some(250_000_000_000_000_000_000_000_000),
            receiver_id: "pool.near".to_string(),
            method_names: alloc::vec!["deposit_and_stake".to_string()],
        }));
        assert!(full.contains("Full Access"), "{full}");
        assert!(restricted.contains("Function Call"), "{restricted}");
        assert!(restricted.contains("pool.near"), "{restricted}");
        // The whole point: the operator can tell them apart on the first screen.
        assert_ne!(full, restricted);
    }

    #[test]
    fn test_parse_transaction_9() {
        // Add Key
        let cbor_str = "a301d82550d63b2bcc149d41e485f429b05ce2a4f1028159012b40000000333138323466626632343335666231656361346466633339373734313833636232356631336231303335326435643533323736313662353963333565616539660031824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f452d16f48e3f00004000000033313832346662663234333566623165636134646663333937373431383363623235663133623130333532643564353332373631366235396333356561653966985676ff103ae696d5654434d300a4818edf38c4fcb6228a62557763849111bc010000000500bc37e7c948e4e127d55070003805c7834f70ef44f454af4e7be0bfde558a57a5000000000000000000002200000061737365742d6d616e616765722e6f726465726c792d6e6574776f726b2e6e6561720000000003d90130a20186182cf519018df500f5021a707eed6c";
        let near_sign_request = NearSignRequest::try_from(hex::decode(cbor_str).unwrap()).unwrap();
        let sign_data = near_sign_request.get_sign_data();
        let parsed = parse(&sign_data[0]).unwrap();
        match parsed.overview {
            NearTxOverview::General(overview) => {
                assert_eq!(
                    "31824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f".to_string(),
                    overview.from
                );
                assert_eq!(
                    "31824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f".to_string(),
                    overview.to
                );
                assert_eq!(1, overview.action_list.len());
                assert_eq!(
                    "Add Key\nPublic Key: ed25519:Dfj6EUNikNmNVxKCRxdq9GDVpEJJNaU3pEzmNVZZ6uTi\n\
                     Access: Function Call\nContract: asset-manager.orderly-network.near\n\
                     Methods: any\nAllowance: Unlimited",
                    overview.action_list[0]
                );
            }
            _ => panic!("error overview type"),
        };
        let parsed_detail: Value = serde_json::from_str(parsed.detail.as_str()).unwrap();
        let expected_detail = json!( [
            {"From":"31824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f","To":"31824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f"},
            {"Access Key Allowance":"Unlimited", "Access Key Permission": "FunctionCall","Access Key Method Names":[],"Access Key Nonce": 0,"Access Key Receiver ID":"asset-manager.orderly-network.near","Action":"Add Key","Public Key":"ed25519:Dfj6EUNikNmNVxKCRxdq9GDVpEJJNaU3pEzmNVZZ6uTi"}]);
        assert_eq!(expected_detail, parsed_detail);
    }
}
