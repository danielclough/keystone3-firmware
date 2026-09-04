use crate::common::ffi::VecFFI;
use crate::common::free::{free_ptr_string, Free};
use crate::common::structs::TransactionParseResult;
use crate::common::types::{PtrString, PtrT};
use crate::common::utils::convert_c_char;
use crate::{check_and_free_ptr, free_str_ptr, impl_c_ptr, impl_c_ptrs, make_free_method};
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use app_near::parser::overview::NearTxOverview;
use app_near::parser::structs::{NearTxDisplayType, ParsedNearTx};
use core::ptr::null_mut;
use itertools::Itertools;

#[repr(C)]
pub struct DisplayNearTx {
    pub network: PtrString,
    pub overview: PtrT<DisplayNearTxOverview>,
    pub detail: PtrString,
}

#[repr(C)]
pub struct DisplayNearTxOverviewGeneralAction {
    pub action: PtrString,
}

impl Free for DisplayNearTxOverviewGeneralAction {
    unsafe fn free(&self) {
        free_str_ptr!(self.action)
    }
}

#[repr(C)]
pub struct DisplayNearTxOverview {
    // `Transfer`, `General`, `Message`
    pub display_type: PtrString,
    // 'Transfer',
    pub main_action: PtrString,
    // transfer
    pub transfer_value: PtrString,
    pub transfer_from: PtrString,
    pub transfer_to: PtrString,
    // general
    pub from: PtrString,
    pub to: PtrString,
    pub action_list: PtrT<VecFFI<DisplayNearTxOverviewGeneralAction>>,
    // message (NEP-413). `callback_url` is null when the payload carries none — an absent
    // callback and an empty one are different things, and the screen says so.
    pub message: PtrString,
    pub recipient: PtrString,
    pub callback_url: PtrString,
}

impl_c_ptrs!(DisplayNearTx, DisplayNearTxOverview);

impl Default for DisplayNearTxOverview {
    fn default() -> Self {
        Self {
            display_type: null_mut(),
            transfer_value: null_mut(),
            main_action: null_mut(),
            transfer_from: null_mut(),
            transfer_to: null_mut(),
            from: null_mut(),
            to: null_mut(),
            action_list: null_mut(),
            message: null_mut(),
            recipient: null_mut(),
            callback_url: null_mut(),
        }
    }
}

impl Free for DisplayNearTx {
    unsafe fn free(&self) {
        check_and_free_ptr!(self.overview);
        free_str_ptr!(self.network);
        free_str_ptr!(self.detail);
    }
}

impl Free for DisplayNearTxOverview {
    unsafe fn free(&self) {
        free_str_ptr!(self.display_type);
        free_str_ptr!(self.main_action);
        free_str_ptr!(self.transfer_value);
        free_str_ptr!(self.transfer_from);
        free_str_ptr!(self.transfer_to);
        free_str_ptr!(self.from);
        free_str_ptr!(self.to);
        free_str_ptr!(self.message);
        free_str_ptr!(self.recipient);
        free_str_ptr!(self.callback_url);
        if !self.action_list.is_null() {
            let x = Box::from_raw(self.action_list);
            let ve = Vec::from_raw_parts(x.data, x.size, x.cap);
            ve.iter().for_each(|v| {
                v.free();
            });
        }
    }
}

impl From<ParsedNearTx> for DisplayNearTx {
    fn from(value: ParsedNearTx) -> Self {
        DisplayNearTx {
            network: convert_c_char(value.network.to_string()),
            overview: DisplayNearTxOverview::from(&value).c_ptr(),
            detail: convert_c_char(value.detail),
        }
    }
}

impl From<&ParsedNearTx> for DisplayNearTxOverview {
    fn from(value: &ParsedNearTx) -> Self {
        let display_type = convert_c_char(value.display_type.to_string());
        match value.display_type {
            NearTxDisplayType::Transfer => {
                if let NearTxOverview::Transfer(overview) = &value.overview {
                    return Self {
                        display_type,
                        //transfer
                        transfer_value: convert_c_char(overview.value.to_string()),
                        main_action: convert_c_char(overview.main_action.to_string()),
                        transfer_from: convert_c_char(overview.from.to_string()),
                        transfer_to: convert_c_char(overview.to.to_string()),
                        ..DisplayNearTxOverview::default()
                    };
                }
            }
            NearTxDisplayType::Message => {
                if let NearTxOverview::Message(overview) = &value.overview {
                    return Self {
                        display_type,
                        message: convert_c_char(overview.message.to_string()),
                        recipient: convert_c_char(overview.recipient.to_string()),
                        // Left null when absent, so the screen can say "none" rather than render
                        // a blank line that reads as an empty url.
                        callback_url: overview
                            .callback_url
                            .as_ref()
                            .map(|u| convert_c_char(u.to_string()))
                            .unwrap_or(null_mut()),
                        ..DisplayNearTxOverview::default()
                    };
                }
            }
            NearTxDisplayType::General => {
                if let NearTxOverview::General(overview) = &value.overview {
                    return Self {
                        display_type,
                        //vote
                        from: convert_c_char(overview.from.to_string()),
                        to: convert_c_char(overview.to.to_string()),
                        action_list: VecFFI::from(
                            overview
                                .action_list
                                .iter()
                                .map(|v| DisplayNearTxOverviewGeneralAction {
                                    action: convert_c_char(v.to_string()),
                                })
                                .collect_vec(),
                        )
                        .c_ptr(),
                        ..DisplayNearTxOverview::default()
                    };
                }
            }
        }
        DisplayNearTxOverview::default()
    }
}

make_free_method!(TransactionParseResult<DisplayNearTx>);
