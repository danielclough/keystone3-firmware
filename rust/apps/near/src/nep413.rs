//! NEP-413: signing an off-chain message with a NEAR key.
//!
//! <https://github.com/near/NEPs/blob/master/neps/nep-0413.md>
//!
//! Without this a NEAR key on the device can only ever sign a `Transaction`, so anything that is
//! not a transaction — a wallet login challenge, an off-chain authorization, a proof that the
//! holder controls an account — has to be smuggled through a transaction that is never broadcast.
//! Such a payload then shows up on the confirm screen as a transfer or a function call, which is
//! precisely the wrong thing to tell the person approving it. NEP-413 is the standard shape for
//! signing a message instead, and this parses it so the device can show it as one.
//!
//! What is signed is `sha256(TAG_LE ++ borsh(payload))` — the same "hash the payload, sign the
//! digest" shape a transaction uses, so `crate::sign` covers both unchanged.

use alloc::format;
use alloc::string::String;

use borsh::BorshDeserialize;

use crate::errors::{NearError, Result};
use crate::parser::utils::read_capped_string;

/// `2^31 + 413`, the NEP-413 domain-separation prefix, little-endian ahead of the borsh payload.
///
/// This is what lets one `near-sign-request` carry both payload families safely. A `Transaction`'s
/// first field is `signer_id`, whose borsh encoding begins with a 4-byte little-endian length, and
/// a NEAR account id is at most 64 bytes — so a transaction's first four bytes are always a small
/// number, never `TAG`. The two encodings are disjoint by construction: a message cannot be
/// re-read as a transaction, and a transaction the holder signed for some other purpose cannot be
/// replayed as a signed message.
pub const TAG: u32 = 2u32.pow(31) + 413;

/// Caps on the attacker-controlled string lengths, for the reason `read_capped_len` documents:
/// borsh reads a 4-byte length and allocates before reading the bytes, so an unbounded length is
/// an allocator-exhaustion primitive on a device with a small heap and no fallback channel.
///
/// The limits are also a display bound. A message longer than the confirm screen can show is a
/// message the holder cannot actually read before approving it, and refusing it outright is
/// honest where truncating it silently would not be.
pub const MAX_MESSAGE_BYTES: u32 = 4096;
/// A recipient is a domain or an account id, both far under this.
pub const MAX_RECIPIENT_BYTES: u32 = 256;
pub const MAX_CALLBACK_URL_BYTES: u32 = 512;

/// The NEP-413 payload, in the standard's field order — the borsh layout is the wire format.
///
/// The tag is not a field: it is domain separation, checked by [`Nep413Payload::parse`], not data
/// the requester gets to choose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nep413Payload {
    pub message: String,
    pub nonce: [u8; 32],
    pub recipient: String,
    pub callback_url: Option<String>,
}

impl Nep413Payload {
    /// True when `data` claims to be a NEP-413 message. Only reads the prefix: a payload that
    /// starts with `TAG` but is otherwise malformed is a *broken message* and must be reported as
    /// one, never retried as a transaction and shown on the wrong screen.
    pub fn is_signing_payload(data: &[u8]) -> bool {
        data.len() >= 4 && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == TAG
    }

    /// Hand-written rather than derived so every attacker-controlled length is capped before it is
    /// allocated (`read_capped_string`), and so trailing bytes are refused: anything appended
    /// after the payload is covered by the signature but invisible on the confirm screen, which is
    /// exactly the mislead this device exists to prevent.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut buf = data;
        let tag = u32::deserialize(&mut buf)
            .map_err(|err| NearError::ParseTxError(format!("NEP-413 tag unreadable: {}", err)))?;
        if tag != TAG {
            return Err(NearError::ParseTxError(format!(
                "not a NEP-413 message: tag {} is not {}",
                tag, TAG
            )));
        }

        let parse_err =
            |err: borsh::maybestd::io::Error| NearError::ParseTxError(format!("{}", err));

        let message =
            read_capped_string(&mut buf, MAX_MESSAGE_BYTES, "a message").map_err(parse_err)?;
        let nonce = <[u8; 32]>::deserialize(&mut buf).map_err(|err| {
            NearError::ParseTxError(format!("a message nonce is unreadable: {}", err))
        })?;
        let recipient = read_capped_string(&mut buf, MAX_RECIPIENT_BYTES, "a message recipient")
            .map_err(parse_err)?;
        // Borsh's Option: one tag byte, then the value when present. Written out rather than
        // derived so the string inside a `Some` goes through the same cap as the others.
        let callback_url = match u8::deserialize(&mut buf).map_err(|err| {
            NearError::ParseTxError(format!("a message callback url is unreadable: {}", err))
        })? {
            0 => None,
            1 => Some(
                read_capped_string(&mut buf, MAX_CALLBACK_URL_BYTES, "a message callback url")
                    .map_err(parse_err)?,
            ),
            other => {
                return Err(NearError::ParseTxError(format!(
                    "a message callback url has option tag {}, expected 0 or 1",
                    other
                )))
            }
        };

        if !buf.is_empty() {
            return Err(NearError::ParseTxError(format!(
                "a message carries {} trailing byte(s) after its payload",
                buf.len()
            )));
        }

        Ok(Nep413Payload {
            message,
            nonce,
            recipient,
            callback_url,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Builds the bytes a requester would put in `sign_data`, by hand — this is the wire format,
    /// so the test must not reuse the parser's own idea of it.
    fn signing_bytes(
        message: &str,
        nonce: [u8; 32],
        recipient: &str,
        callback_url: Option<&str>,
    ) -> Vec<u8> {
        let mut out = TAG.to_le_bytes().to_vec();
        out.extend((message.len() as u32).to_le_bytes());
        out.extend(message.as_bytes());
        out.extend(nonce);
        out.extend((recipient.len() as u32).to_le_bytes());
        out.extend(recipient.as_bytes());
        match callback_url {
            None => out.push(0),
            Some(url) => {
                out.push(1);
                out.extend((url.len() as u32).to_le_bytes());
                out.extend(url.as_bytes());
            }
        }
        out
    }

    #[test]
    fn a_message_parses_into_the_fields_the_confirm_screen_shows() {
        let parsed = Nep413Payload::parse(&signing_bytes(
            "login to app.example",
            [0x11; 32],
            "app.example",
            Some("https://app.example/cb"),
        ))
        .unwrap();

        assert_eq!("login to app.example", parsed.message);
        assert_eq!([0x11; 32], parsed.nonce);
        assert_eq!("app.example", parsed.recipient);
        assert_eq!(
            Some("https://app.example/cb".to_string()),
            parsed.callback_url
        );
    }

    /// The wire layout, pinned as a literal. A requester builds these bytes with its own borsh
    /// implementation and this device parses them with another, so the layout is the only thing
    /// the two share: if they ever disagreed, this device's signature would cover different bytes
    /// than the requester believes it signed. near-keystone's `near_tx` pins the identical vector
    /// from the requester side (`near_tx/src/nep413.rs`,
    /// `the_signing_bytes_are_the_tag_then_the_borsh_payload`).
    #[test]
    fn the_wire_layout_matches_the_host_sides_pinned_vector() {
        let bytes = signing_bytes("hello", [0x11; 32], "app.near", None);
        assert_eq!(
            concat!(
                "9d010080",                                                         // tag, LE
                "05000000",                                                         // len("hello")
                "68656c6c6f",                                                       // "hello"
                "1111111111111111111111111111111111111111111111111111111111111111", // nonce, raw
                "08000000",         // len("app.near")
                "6170702e6e656172", // "app.near"
                "00",               // callback_url = None
            ),
            hex::encode(&bytes)
        );

        let parsed = Nep413Payload::parse(&bytes).unwrap();
        assert_eq!("hello", parsed.message);
        assert_eq!("app.near", parsed.recipient);
        assert_eq!(2_147_484_061, TAG);
    }

    #[test]
    fn an_absent_callback_url_is_none_not_an_empty_string() {
        let parsed =
            Nep413Payload::parse(&signing_bytes("hello", [0u8; 32], "app.example", None)).unwrap();
        assert_eq!(None, parsed.callback_url);
    }

    /// The domain separation the tag exists for, from both directions.
    #[test]
    fn a_transaction_is_not_a_message_and_a_message_is_not_a_transaction() {
        // A real function-call transaction (the fixture the parser tests use).
        let tx = hex::decode("40000000333138323466626632343335666231656361346466633339373734313833636232356631336231303335326435643533323736313662353963333565616539660031824fbf2435fb1eca4dfc39774183cb25f13b10352d5d5327616b59c35eae9f442d16f48e3f00003c000000613062383639393163363231386233366331643139643461326539656230636533363036656234382e666163746f72792e6272696467652e6e6561728db41252bff5ecc0b28f55fc078d1b2de23990f728fc762502688d340bb42c9301000000020b00000066745f7472616e73666572630000007b22616d6f756e74223a223232303030222c2272656365697665725f6964223a2230346361353938333132633631656464646165656531333035333938303366323931313464363534353537643330333066313561623533316335653730613264227d00e057eb481b000001000000000000000000000000000000").unwrap();
        assert!(!Nep413Payload::is_signing_payload(&tx));
        assert!(Nep413Payload::parse(&tx).is_err());
        // ...and still renders as the transaction it is, on the transaction screen.
        assert_eq!(
            "General",
            crate::parse(&tx).unwrap().display_type.to_string()
        );

        let message = signing_bytes("hello", [0u8; 32], "app.example", None);
        assert!(Nep413Payload::is_signing_payload(&message));
        assert_eq!(
            "Message",
            crate::parse(&message).unwrap().display_type.to_string()
        );
    }

    #[test]
    fn trailing_bytes_after_a_message_are_refused() {
        let mut extended = signing_bytes("hello", [0u8; 32], "app.example", None);
        extended.push(0xaa);
        assert!(Nep413Payload::parse(&extended).is_err());
    }

    /// A claimed length no frame could actually carry must fail as a parse error, not as an
    /// allocation the device cannot service.
    #[test]
    fn an_oversized_claimed_length_is_refused_before_it_is_allocated() {
        let mut oversized = TAG.to_le_bytes().to_vec();
        oversized.extend(u32::MAX.to_le_bytes());
        oversized.extend(b"hello");
        assert!(Nep413Payload::parse(&oversized).is_err());

        // Same for a length that is merely past the cap rather than absurd.
        let mut over_cap = TAG.to_le_bytes().to_vec();
        over_cap.extend((MAX_MESSAGE_BYTES + 1).to_le_bytes());
        over_cap.extend(vec![b'a'; MAX_MESSAGE_BYTES as usize + 1]);
        assert!(Nep413Payload::parse(&over_cap).is_err());
    }

    #[test]
    fn a_truncated_message_is_refused() {
        let full = signing_bytes("hello", [0u8; 32], "app.example", None);
        for cut in [4, 8, 12, full.len() - 1] {
            assert!(
                Nep413Payload::parse(&full[..cut]).is_err(),
                "a payload cut to {} bytes must not parse",
                cut
            );
        }
    }

    #[test]
    fn a_message_that_is_not_utf8_is_refused() {
        let mut bad = TAG.to_le_bytes().to_vec();
        bad.extend(2u32.to_le_bytes());
        bad.extend([0xff, 0xfe]);
        bad.extend([0u8; 32]);
        bad.extend(0u32.to_le_bytes());
        bad.push(0);
        assert!(Nep413Payload::parse(&bad).is_err());
    }
}
