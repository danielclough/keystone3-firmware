//! nearcore's `Signature` (core/crypto/src/signature.rs), tag+bytes on the wire: ED25519 = 0
//! (64 bytes), SECP256K1 = 1 (65 bytes) — the same shape as `PublicKey` in this module.
//!
//! Parse-only, like everything else in this crate: this device never constructs a signature of
//! its own inside a transaction it's parsing (it produces its own signature separately, over the
//! raw bytes it was handed — see `crate::sign`). So there is no `Display`/`FromStr`/`Serialize`
//! here: a `SignedDelegateAction`'s signature is round-tripped so the surrounding borsh parses at
//! all, but never rendered — 64/65 raw bytes are not human-checkable data any more than a deploy
//! action's code bytes are, which is why those aren't dumped to the confirm screen either.

use crate::crypto::errors::ParseKeyError;
use alloc::string::ToString;
use borsh::maybestd::io::{Error, ErrorKind, Write};
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, PartialEq, Eq)]
pub enum Signature {
    ED25519([u8; 64]),
    SECP256K1([u8; 65]),
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Signature::ED25519(_) => write!(f, "ed25519:<signature>"),
            Signature::SECP256K1(_) => write!(f, "secp256k1:<signature>"),
        }
    }
}

impl BorshSerialize for Signature {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        match self {
            Signature::ED25519(sig) => {
                BorshSerialize::serialize(&0u8, writer)?;
                writer.write_all(sig)?;
            }
            Signature::SECP256K1(sig) => {
                BorshSerialize::serialize(&1u8, writer)?;
                writer.write_all(sig)?;
            }
        }
        Ok(())
    }
}

impl BorshDeserialize for Signature {
    fn deserialize(buf: &mut &[u8]) -> Result<Self, Error> {
        let tag = <u8 as BorshDeserialize>::deserialize(buf)?;
        match tag {
            0 => Ok(Signature::ED25519(BorshDeserialize::deserialize(buf)?)),
            1 => Ok(Signature::SECP256K1(BorshDeserialize::deserialize(buf)?)),
            unknown => Err(Error::new(
                ErrorKind::InvalidData,
                ParseKeyError::UnknownKeyType {
                    unknown_key_type: unknown.to_string(),
                }
                .to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_round_trips_through_borsh() {
        let sig = Signature::ED25519([7u8; 64]);
        let bytes = borsh::BorshSerialize::try_to_vec(&sig).unwrap();
        assert_eq!(bytes.len(), 65, "1 tag byte + 64 signature bytes");
        assert_eq!(bytes[0], 0, "ED25519 tag");
        let back = Signature::try_from_slice(&bytes).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn an_unknown_signature_tag_is_refused() {
        let bytes = [9u8; 65]; // tag 9 does not exist
        assert!(Signature::try_from_slice(&bytes).is_err());
    }
}
