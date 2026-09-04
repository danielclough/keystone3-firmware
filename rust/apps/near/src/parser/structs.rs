use crate::parser::overview::NearTxOverview;

use alloc::string::{String, ToString};

#[derive(Clone, Debug)]
pub struct ParsedNearTx {
    pub display_type: NearTxDisplayType,
    pub overview: NearTxOverview,
    pub detail: String,
    pub network: String,
}

// method label on ui
#[derive(Clone, Debug)]
pub enum NearTxDisplayType {
    Transfer,
    General,
    /// A NEP-413 off-chain message, not a transaction. A third display type rather than a second
    /// view: the page is the same Overview/Details tabview, but what the holder must check is
    /// entirely different — text, recipient and callback url, none of which a transaction has.
    Message,
}

impl ToString for NearTxDisplayType {
    fn to_string(&self) -> String {
        match &self {
            NearTxDisplayType::Transfer => "Transfer".to_string(),
            NearTxDisplayType::General => "General".to_string(),
            NearTxDisplayType::Message => "Message".to_string(),
        }
    }
}
