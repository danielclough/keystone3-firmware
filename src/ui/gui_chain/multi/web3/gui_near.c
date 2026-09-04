#include "rust.h"
#include "keystore.h"
#include "user_memory.h"
#include "gui_chain.h"
#include "screen_manager.h"
#include "keystore.h"
#include "account_manager.h"
#include "account_public_info.h"
#include "secret_cache.h"
#include "gui_analyze.h"
#include "cjson/cJSON.h"

static bool g_isMulti = false;
static URParseResult *g_urResult = NULL;
static URParseMultiResult *g_urMultiResult = NULL;
static void *g_parseResult = NULL;

void GuiSetNearUrData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi)
{
    g_urResult = urResult;
    g_urMultiResult = urMultiResult;
    g_isMulti = multi;
}

#define CHECK_FREE_PARSE_RESULT(result)                                                              \
    if (result != NULL)                                                                              \
    {                                                                                                 \
        free_TransactionParseResult_DisplayNearTx((PtrT_TransactionParseResult_DisplayNearTx)result); \
        result = NULL;                                                                                \
    }

void FreeNearMemory(void)
{
    CHECK_FREE_UR_RESULT(g_urResult, false);
    CHECK_FREE_UR_RESULT(g_urMultiResult, true);
    CHECK_FREE_PARSE_RESULT(g_parseResult);
}

PtrT_TransactionCheckResult GuiGetNearCheckResult(void)
{
    uint8_t mfp[4];
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    GetMasterFingerPrint(mfp);
    return near_check(data, mfp, sizeof(mfp));
}

char *GuiGetNearPubkey(uint8_t pathType, uint16_t index)
{
    switch (pathType)
    {
    case 0:
        return GetCurrentAccountPublicKey(XPUB_TYPE_NEAR_STANDARD_0);
    case 1:
        return GetCurrentAccountPublicKey(XPUB_TYPE_NEAR_LEDGER_LIVE_0 + index);
    default:
        printf("GuiGetNearPubkey: pathType = %d\n is not supported", pathType);
        return "";
    }
}

void *GuiGetNearData(void)
{
    CHECK_FREE_PARSE_RESULT(g_parseResult);
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    do {
        PtrT_TransactionParseResult_DisplayNearTx parseResult = near_parse_tx(data);
        CHECK_CHAIN_BREAK(parseResult);
        g_parseResult = (void *)parseResult;
    } while (0);
    return g_parseResult;
}

static void SetContainerDefaultStyle(lv_obj_t *container)
{
    lv_obj_set_style_radius(container, 24, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(container, WHITE_COLOR, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_bg_opa(container, 30, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_add_flag(container, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(container, LV_OBJ_FLAG_CLICKABLE);
}

static void SetTitleLabelStyle(lv_obj_t *label)
{
    lv_obj_set_style_text_font(label, &openSans_20, LV_PART_MAIN);
    lv_obj_set_style_text_color(label, WHITE_COLOR, LV_PART_MAIN);
    lv_obj_set_style_text_opa(label, 144, LV_PART_MAIN | LV_STATE_DEFAULT);
}

static void SetContentLableStyle(lv_obj_t *label)
{
    lv_obj_set_style_text_font(label, &openSans_20, LV_PART_MAIN);
    lv_obj_set_style_text_color(label, WHITE_COLOR, LV_PART_MAIN);
}

static void GuiShowNearTxTransferOverview(lv_obj_t *parent, PtrT_DisplayNearTxOverview overviewData)
{

    lv_obj_t *valueContainer = GuiCreateContainerWithParent(parent, 408, 106);
    lv_obj_align(valueContainer, LV_ALIGN_DEFAULT, 0, 0);
    SetContainerDefaultStyle(valueContainer);

    lv_obj_t *label = lv_label_create(valueContainer);
    lv_label_set_text(label, "Value");
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, 24, 16);
    SetTitleLabelStyle(label);

    label = lv_label_create(valueContainer);
    lv_label_set_text(label, overviewData->transfer_value);
    lv_obj_set_style_text_font(label, &openSansEnLittleTitle, LV_PART_MAIN);
    lv_obj_set_style_text_color(label, lv_color_hex(0xF5870A), LV_PART_MAIN);
    // A full-precision NEAR amount can run to 30+ characters (format_near_units renders every yocto
    // digit). Wrap it and grow the container to fit — exactly as the From/To labels below do —
    // instead of leaving it a single unwrapped line that overflows the fixed 408px box and clips the
    // low-order digits at the right edge. That clip made two transfers differing only in a clipped
    // digit render a byte-identical Overview: the amount-dust confirm-differential collision
    // (keystone-guide-kit/security_lab/S-P2-CONFIRM-DIFFERENTIAL.md). The device signs the exact
    // u128, so the confirm screen must show every digit of it.
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(label, 360);
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, 24, 50);
    lv_obj_update_layout(label);
    lv_obj_set_height(valueContainer, lv_obj_get_y2(label) + 16);

    lv_obj_t *mainActionContainer = GuiCreateContainerWithParent(parent, 408, 62);
    lv_obj_align_to(mainActionContainer, valueContainer, LV_ALIGN_OUT_BOTTOM_MID, 0, 16);
    SetContainerDefaultStyle(mainActionContainer);

    label = lv_label_create(mainActionContainer);
    lv_label_set_text(label, "Main Action");
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, 24, 20);
    SetTitleLabelStyle(label);

    label = lv_label_create(mainActionContainer);
    lv_label_set_text(label, overviewData->main_action);
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, 151, 20);
    SetContentLableStyle(label);

    lv_obj_t *addressContainer = GuiCreateContainerWithParent(parent, 408, 194);
    lv_obj_align_to(addressContainer, mainActionContainer, LV_ALIGN_OUT_BOTTOM_MID, 0, 16);
    SetContainerDefaultStyle(addressContainer);

    label = lv_label_create(addressContainer);
    lv_label_set_text(label, "From");
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, 24, 16);
    SetTitleLabelStyle(label);

    lv_obj_t *prev = label;
    label = lv_label_create(addressContainer);
    lv_label_set_text(label, overviewData->transfer_from);
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(label, 360);
    lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 8);
    SetContentLableStyle(label);
    prev = label;

    label = lv_label_create(addressContainer);
    lv_label_set_text(label, "To");
    lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 16);
    SetTitleLabelStyle(label);
    prev = label;

    label = lv_label_create(addressContainer);
    lv_label_set_text(label, overviewData->transfer_to);
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(label, 360);
    lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 8);
    SetContentLableStyle(label);
    prev = label;

    lv_obj_update_layout(prev);
    lv_obj_set_height(addressContainer, lv_obj_get_y2(prev) + 16);
}

static void GuiShowNearTxGeneralOverview(lv_obj_t *parent, PtrT_DisplayNearTxOverview overviewData)
{
    PtrT_VecFFI_DisplayNearTxOverviewGeneralAction general = overviewData->action_list;

    lv_obj_t *container = GuiCreateContainerWithParent(parent, 408, 150);
    lv_obj_align(container, LV_ALIGN_DEFAULT, 0, 0);
    SetContainerDefaultStyle(container);

    lv_obj_t *prev = NULL;
    lv_obj_t *label = NULL;

    label = lv_label_create(container);
    lv_label_set_text(label, "From");
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, 24, 16);
    SetTitleLabelStyle(label);
    prev = label;

    label = lv_label_create(container);
    lv_label_set_text(label, overviewData->from);
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(label, 360);
    lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 8);
    SetContentLableStyle(label);
    prev = label;

    label = lv_label_create(container);
    lv_label_set_text(label, "To");
    lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 16);
    SetTitleLabelStyle(label);
    prev = label;

    label = lv_label_create(container);
    lv_label_set_text(label, overviewData->to);
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(label, 360);
    lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 8);
    SetContentLableStyle(label);
    prev = label;

    label = lv_label_create(container);
    lv_label_set_text(label, "Action List");
    lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 16);
    SetTitleLabelStyle(label);
    prev = label;

    for (int i = 0; i < general->size; i++) {
        label = lv_label_create(container);
        // A function call's action string now carries its method and args over multiple lines
        // (see build_general_overview) — so wrap it, like the From/To labels above, instead of
        // letting a token transfer's recipient/amount run off the right edge. The action text is a
        // %s argument, never the format string, so a `%` in the args stays literal.
        lv_label_set_text_fmt(label, "%d. %s", i + 1, general->data[i].action);
        lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(label, 360);
        lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 8);
        SetContentLableStyle(label);
        prev = label;
    }

    lv_obj_update_layout(prev);
    lv_obj_set_height(container, lv_obj_get_y2(prev) + 16);
}

// A NEP-413 off-chain message (nep413.rs), not a transaction: what the holder has to check is the
// text they are authorising, who it is addressed to, and where an approval can be sent. Every one
// of those is requester-controlled freeform text — sanitised on the Rust side, wrapped here — so
// each gets a wrapped label sized to the container rather than a single clipped line, for the same
// reason the transfer amount above does: a value the screen cuts off is a value the holder did not
// actually approve.
static void GuiShowNearMessageOverview(lv_obj_t *parent, PtrT_DisplayNearTxOverview overviewData)
{
    lv_obj_t *container = GuiCreateContainerWithParent(parent, 408, 150);
    lv_obj_align(container, LV_ALIGN_DEFAULT, 0, 0);
    SetContainerDefaultStyle(container);

    lv_obj_t *label = lv_label_create(container);
    lv_label_set_text(label, "Message");
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, 24, 16);
    SetTitleLabelStyle(label);
    lv_obj_t *prev = label;

    label = lv_label_create(container);
    lv_label_set_text(label, overviewData->message);
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(label, 360);
    lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 8);
    SetContentLableStyle(label);
    prev = label;

    label = lv_label_create(container);
    lv_label_set_text(label, "Recipient");
    lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 16);
    SetTitleLabelStyle(label);
    prev = label;

    label = lv_label_create(container);
    lv_label_set_text(label, overviewData->recipient);
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(label, 360);
    lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 8);
    SetContentLableStyle(label);
    prev = label;

    label = lv_label_create(container);
    lv_label_set_text(label, "Callback URL");
    lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 16);
    SetTitleLabelStyle(label);
    prev = label;

    label = lv_label_create(container);
    // A message with no callback url says so. Rendering a null pointer as an empty line would let
    // an absent callback and an empty one look identical.
    lv_label_set_text(label, overviewData->callback_url != NULL ? overviewData->callback_url : "None");
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(label, 360);
    lv_obj_align_to(label, prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 8);
    SetContentLableStyle(label);
    prev = label;

    lv_obj_update_layout(prev);
    lv_obj_set_height(container, lv_obj_get_y2(prev) + 16);
}

void GuiShowNearTxOverview(lv_obj_t *parent, void *totalData)
{
    lv_obj_set_size(parent, 408, 444);
    lv_obj_add_flag(parent, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(parent, LV_OBJ_FLAG_CLICKABLE);

    DisplayNearTx *txData = (DisplayNearTx*)totalData;
    PtrT_DisplayNearTxOverview overviewData = txData->overview;

    if (0 == strcmp(overviewData->display_type, "Transfer")) {
        GuiShowNearTxTransferOverview(parent, overviewData);
    } else if (0 == strcmp(overviewData->display_type, "General")) {
        GuiShowNearTxGeneralOverview(parent, overviewData);
    } else if (0 == strcmp(overviewData->display_type, "Message")) {
        GuiShowNearMessageOverview(parent, overviewData);
    }
}

static bool IsKeyInline(char *key)
{
    return 0 == strcmp(key, "Action")
        || 0 == strcmp(key, "Value")
        || 0 == strcmp(key, "Access Key Permission")
        || 0 == strcmp(key, "Method")
        || 0 == strcmp(key, "Deposit Value")
        || 0 == strcmp(key, "Prepaid Gas")
        || 0 == strcmp(key, "Stake Amount");
}

static void GuiRenderTextList(cJSON *array, lv_obj_t *parent, lv_obj_t **prev)
{
    lv_obj_t *label;
    int8_t len = cJSON_GetArraySize(array);
    for (int8_t i = 0; i < len; i++) {
        cJSON *item = cJSON_GetArrayItem(array, i);
        label = lv_label_create(parent);
        if (len > 1) {
            lv_label_set_text_fmt(label, "%d. %s", i + 1, item->valuestring);
        } else {
            lv_label_set_text(label, item->valuestring);
        }
        lv_obj_align_to(label, *prev, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 8);
        SetContentLableStyle(label);
        *prev = label;
    }
}

void GuiShowNearTxDetail(lv_obj_t *parent, void *totalData)
{
    lv_obj_set_size(parent, 408, 444);
    lv_obj_add_flag(parent, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(parent, LV_OBJ_FLAG_CLICKABLE);

    DisplayNearTx *txData = (DisplayNearTx*)totalData;
    PtrString detail = txData->detail;

    cJSON *root = cJSON_Parse((const char *)detail);
    int8_t len = cJSON_GetArraySize(root);
    lv_obj_t *prevContainer = NULL;
    lv_obj_t *prevLabel = NULL;
    int8_t gapS = 8;
    int8_t gapM = 16;
    for (int8_t i = 0; i < len; i++) {
        lv_obj_t *container = GuiCreateContainerWithParent(parent, 408, 150);
        if (NULL != prevContainer) {
            lv_obj_align_to(container, prevContainer, LV_ALIGN_OUT_BOTTOM_LEFT, 0, gapM);
        } else {
            lv_obj_align(container, LV_ALIGN_TOP_LEFT, 0, 0);
        }
        prevContainer = container;
        SetContainerDefaultStyle(container);

        cJSON *item = cJSON_GetArrayItem(root, i);
        int8_t kLen = cJSON_GetArraySize(item);

        if (i > 0) {
            lv_obj_t *iLabel = lv_label_create(container);
            lv_label_set_text_fmt(iLabel, "#%d", i);
            lv_obj_align(iLabel, LV_ALIGN_TOP_LEFT, 24, gapM);
            lv_obj_set_style_text_font(iLabel, &openSans_20, LV_PART_MAIN);
            lv_obj_set_style_text_color(iLabel, ORANGE_COLOR, LV_PART_MAIN);
            prevLabel = iLabel;
        } else {
            prevLabel = NULL;
        }

        for (int8_t k = 0; k < kLen; k++) {
            cJSON *key = cJSON_GetArrayItem(item, k);
            if (key->type == cJSON_Array && cJSON_GetArraySize(key) == 0) {
                continue;
            }
            lv_obj_t *tLabel = lv_label_create(container);
            lv_label_set_text(tLabel, key->string);
            if (NULL != prevLabel) {
                int8_t g = gapM;
                if (k > 0) {
                    g = gapS;
                }
                lv_obj_align_to(tLabel, prevLabel, LV_ALIGN_OUT_BOTTOM_LEFT, 0, g);
            } else {
                lv_obj_align(tLabel, LV_ALIGN_TOP_LEFT, 24, gapM);
            }
            SetTitleLabelStyle(tLabel);
            prevLabel = tLabel;
            if (key->type == cJSON_Array) {
                GuiRenderTextList(key, container, &prevLabel);
            } else {
                lv_obj_t *vLabel = lv_label_create(container);
                if (key->type == cJSON_String) {
                    lv_label_set_text(vLabel, key->valuestring);
                } else if (key->type == cJSON_Number) {
                    lv_label_set_text_fmt(vLabel, "%d", key->valueint);
                }
                lv_label_set_long_mode(vLabel, LV_LABEL_LONG_WRAP);
                if (IsKeyInline(key->string)) {
                    lv_obj_align_to(vLabel, prevLabel, LV_ALIGN_OUT_RIGHT_TOP, gapM, 0);
                } else {
                    lv_obj_align_to(vLabel, prevLabel, LV_ALIGN_OUT_BOTTOM_LEFT, 0, gapS);
                    lv_obj_set_width(vLabel, 360);
                    prevLabel = vLabel;
                }
                SetContentLableStyle(vLabel);
            }
        }
        lv_obj_update_layout(prevLabel);
        int16_t bottom = lv_obj_get_y2(prevLabel);
        lv_obj_set_height(container, bottom + gapM);
    }
    cJSON_Delete(root);
}

UREncodeResult *GuiGetNearSignQrCodeData(void)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    UREncodeResult *encodeResult;
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    do {
        uint8_t seed[64];
        int len = GetMnemonicType() == MNEMONIC_TYPE_BIP39 ? sizeof(seed) : GetCurrentAccountEntropyLen();
        GetAccountSeed(GetCurrentAccountIndex(), seed, SecretCacheGetPassword());
        encodeResult = near_sign_tx(data, seed, len);
        ClearSecretCache();
        CHECK_CHAIN_BREAK(encodeResult);
    } while (0);
    SetLockScreen(enable);
    return encodeResult;
}
