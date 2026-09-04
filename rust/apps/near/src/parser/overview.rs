use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct NearTxOverviewTransfer {
    pub value: String,
    pub main_action: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone)]
pub struct NearTxOverviewGeneral {
    pub from: String,
    pub to: String,
    pub action_list: Vec<String>,
}

/// A NEP-413 message's Overview. The nonce is deliberately absent: it is replay protection the
/// holder cannot meaningfully check by eye, and putting it here would crowd out the two fields
/// they can — the text they are authorizing and who it is addressed to. It is on the Details tab.
///
/// `callback_url` is on the Overview when present because it is where an approval can be sent,
/// which is exactly the field a phishing request needs the holder not to read.
#[derive(Debug, Clone)]
pub struct NearTxOverviewMessage {
    pub message: String,
    pub recipient: String,
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone)]
pub enum NearTxOverview {
    Transfer(NearTxOverviewTransfer),
    General(NearTxOverviewGeneral),
    Message(NearTxOverviewMessage),
}
