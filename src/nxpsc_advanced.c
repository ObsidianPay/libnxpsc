//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// libnxpsc - EV2 and later extras: delegated applications, MIFARE Classic
// mapping, transaction MAC files, key sets and the proximity check
//-----------------------------------------------------------------------------

#include "nxpsc_internal.h"
#include "nxpsc_crypto.h"

#include <string.h>

#define PC_CHALLENGE_LEN    8
#define PC_MAC_LEN          8
#define PC_MAX_ROUNDS       8

// without a session every command is plain, no matter what the caller asked for
static nxpsc_mode_t eff_mode(const nxpsc_card_t *card, nxpsc_mode_t mode) {
    if (card->authenticated == false) {
        return MODE_PLAIN;
    }
    return mode;
}

static void put_u24le(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value & 0xFF);
    out[1] = (uint8_t)((value >> 8) & 0xFF);
    out[2] = (uint8_t)((value >> 16) & 0xFF);
}

static bool fits_u24(uint32_t value) {
    return (value & 0xFF000000U) == 0;
}

// AES CMAC truncated to its odd bytes, the form DESFire uses for 8 byte MACs
static int cmac8(const uint8_t *key, const uint8_t *data, size_t len, uint8_t *mac8) {
    uint8_t full[16] = {0};

    int rc = nxpsc_cmac(NXPSC_KEY_AES128, key, NULL, data, len, 0, full);
    if (rc != NXPSC_OK) {
        return rc;
    }

    for (int i = 0; i < 8; i++) {
        mac8[i] = full[i * 2 + 1];
    }
    return NXPSC_OK;
}

//-----------------------------------------------------------------------------
// ISO chaining variants of the file access commands
//-----------------------------------------------------------------------------
void nxpsc_set_iso_chaining(nxpsc_card_t *card, bool enable) {
    if (card != NULL) {
        card->iso_chaining = enable;
    }
}

bool nxpsc_get_iso_chaining(const nxpsc_card_t *card) {
    return (card != NULL) ? card->iso_chaining : false;
}

//-----------------------------------------------------------------------------
// transaction MAC file
//-----------------------------------------------------------------------------
int nxpsc_create_transaction_mac_file(nxpsc_card_t *card, uint8_t file_no,
                                      nxpsc_commmode_t comm, const nxpsc_access_t *access,
                                      const nxpsc_key_t *tm_key, uint8_t key_version) {
    if (card == NULL || access == NULL || tm_key == NULL) {
        return NXPSC_E_PARAM;
    }
    if (tm_key->type != NXPSC_KEY_AES128) {
        return NXPSC_E_UNSUPPORTED;
    }

    uint8_t data[22] = {0};
    size_t len = 0;

    data[len++] = file_no;
    data[len++] = (comm == NXPSC_COMM_FULL) ? 0x03 : ((comm == NXPSC_COMM_MAC) ? 0x01 : 0x00);

    uint16_t rights = nxpsc_pack_access(access);
    data[len++] = (uint8_t)(rights & 0xFF);
    data[len++] = (uint8_t)(rights >> 8);

    data[len++] = 0x02;                 // TMKeyOption, AES128
    memcpy(data + len, tm_key->data, 16);
    len += 16;
    data[len++] = key_version;

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    // the key travels enciphered, so this command is always full mode
    return nxpsc_exchange(card, DF_CREATE_TRANS_MAC_FILE, data, len, MODE_ENC, MODE_MAC,
                          resp, sizeof(resp), &resp_len);
}

//-----------------------------------------------------------------------------
// transaction MAC, host side
//
// The card computes a Transaction MAC Value over a Transaction MAC Input it
// accumulates during the transaction, under a session key derived from the
// AppTransactionMACKey and the transaction counter. A back office holding the
// same key recomputes both from data it already has, which is what these two
// functions are for: neither touches a card.
//
// MF2DL(H)x0 data sheet rev 3.3 section 10.3 ("Transaction MAC"):
//   SV1          = 5Ah || 00h || 01h || 00h || 80h || (TMC+1) || UID
//   SesTMMACKey  = PRF(AppTransactionMACKey, SV1)      PRF = CMAC, NIST SP 800-108
//   TMV          = MACtTM(SesTMMACKey, TMI)            truncated CMAC, zero IV
// TMC is 4 bytes LSB first. CommitTransaction reports the already incremented
// counter, i.e. exactly the value that went into SV1, so the caller passes the
// reported TMC through unchanged.
//
// proxmark3's DesfireGenTransSessionKeyEV2 builds the same SV1; it has no TMI
// accumulation or TMV computation to compare against. See
// docs/md/Development/Porting_Notes.md.
//-----------------------------------------------------------------------------
int nxpsc_tmac_compute(const nxpsc_key_t *tm_key, const uint8_t *uid, size_t uid_len,
                       const uint8_t tmc[4], const uint8_t *tmi, size_t tmi_len,
                       uint8_t tmv[8]) {
    if (tm_key == NULL || uid == NULL || tmc == NULL || tmi == NULL || tmv == NULL) {
        return NXPSC_E_PARAM;
    }
    if (tm_key->type != NXPSC_KEY_AES128) {
        return NXPSC_E_UNSUPPORTED;
    }
    // the 11 byte context of SV1 is the 4 byte counter and a 7 byte UID
    if (uid_len != 7) {
        return NXPSC_E_LENGTH;
    }
    // every TMI update ends on a 16 byte boundary, so a TMI that does not is a
    // caller error rather than something a card would ever have accumulated
    if (tmi_len == 0 || (tmi_len % 16) != 0) {
        return NXPSC_E_LENGTH;
    }

    uint8_t sv1[16] = { 0x5A, 0x00, 0x01, 0x00, 0x80 };
    memcpy(sv1 + 5, tmc, 4);
    memcpy(sv1 + 9, uid, 7);

    uint8_t session_key[16] = {0};
    int status = nxpsc_cmac(NXPSC_KEY_AES128, tm_key->data, NULL, sv1, sizeof(sv1), 0, session_key);
    if (status != NXPSC_OK) {
        nxpsc_secure_zero(session_key, sizeof(session_key));
        return status;
    }

    uint8_t full[16] = {0};
    status = nxpsc_cmac(NXPSC_KEY_AES128, session_key, NULL, tmi, tmi_len, 0, full);
    if (status == NXPSC_OK) {
        nxpsc_truncate_mac(full, tmv);
    }

    nxpsc_secure_zero(session_key, sizeof(session_key));
    nxpsc_secure_zero(full, sizeof(full));
    return status;
}

// Data sheet section 10.3.4.2, WriteRecord:
//   TMI = TMI || Cmd || FileNo || Offset || Length || ZeroPadding || Data
// The eight zero bytes bring the command parameters up to 16; record data is
// itself a multiple of 16, so nothing is appended after it. Offset and Length
// are 3 bytes LSB first, exactly as they appear on the command interface, and
// the data is the plain record regardless of the communication mode used.
int nxpsc_tmac_tmi_write_record(uint8_t file_no, uint32_t offset,
                                const uint8_t *data, size_t data_len,
                                uint8_t *tmi, size_t cap, size_t *tmi_len) {
    if (data == NULL || tmi == NULL || tmi_len == NULL) {
        return NXPSC_E_PARAM;
    }
    if (offset > 0xFFFFFF || data_len == 0 || data_len > 0xFFFFFF) {
        return NXPSC_E_PARAM;
    }

    size_t padded = (data_len + 15) / 16 * 16;
    size_t needed = 16 + padded;
    if (cap < needed) {
        return NXPSC_E_LENGTH;
    }

    memset(tmi, 0, needed);
    tmi[0] = DF_WRITE_RECORD;
    tmi[1] = file_no;
    tmi[2] = (uint8_t)(offset & 0xFF);
    tmi[3] = (uint8_t)((offset >> 8) & 0xFF);
    tmi[4] = (uint8_t)((offset >> 16) & 0xFF);
    tmi[5] = (uint8_t)(data_len & 0xFF);
    tmi[6] = (uint8_t)((data_len >> 8) & 0xFF);
    tmi[7] = (uint8_t)((data_len >> 16) & 0xFF);
    // tmi[8..15] stay zero: the ZeroPadding of the command parameters
    memcpy(tmi + 16, data, data_len);

    *tmi_len = needed;
    return NXPSC_OK;
}

//-----------------------------------------------------------------------------
// delegated application management
//-----------------------------------------------------------------------------
int nxpsc_create_delegated_application(nxpsc_card_t *card, uint32_t aid, uint16_t dam_slot,
                                       uint8_t dam_slot_version, uint16_t quota_limit,
                                       uint8_t key_settings, uint8_t num_keys,
                                       nxpsc_keytype_t key_type,
                                       uint16_t iso_fid, const uint8_t *df_name, size_t df_name_len,
                                       const uint8_t *enck, size_t enck_len,
                                       const uint8_t *dam_mac, size_t dam_mac_len) {

    if (card == NULL || enck == NULL || dam_mac == NULL) {
        return NXPSC_E_PARAM;
    }
    if (fits_u24(aid) == false) {
        return NXPSC_E_LENGTH;
    }
    if (df_name_len > 16 || (df_name_len > 0 && df_name == NULL)) {
        return NXPSC_E_PARAM;
    }
    if (enck_len > 32 || dam_mac_len > 16) {
        return NXPSC_E_LENGTH;
    }

    uint8_t data[96] = {0};
    size_t len = 0;

    put_u24le(data, aid);
    len = 3;
    data[len++] = (uint8_t)(dam_slot & 0xFF);
    data[len++] = (uint8_t)(dam_slot >> 8);
    data[len++] = dam_slot_version;
    data[len++] = (uint8_t)(quota_limit & 0xFF);
    data[len++] = (uint8_t)(quota_limit >> 8);

    data[len++] = key_settings;
    uint8_t key_byte = (uint8_t)(num_keys & 0x0F);
    switch (key_type) {
        case NXPSC_KEY_3K3DES:
            key_byte |= 0x40;
            break;
        case NXPSC_KEY_AES128:
            key_byte |= 0x80;
            break;
        default:
            break;
    }
    if (iso_fid != 0 || df_name_len > 0) {
        key_byte |= 0x20;
    }
    data[len++] = key_byte;

    if ((key_byte & 0x20) != 0) {
        data[len++] = (uint8_t)(iso_fid & 0xFF);
        data[len++] = (uint8_t)(iso_fid >> 8);
        if (df_name_len > 0) {
            memcpy(data + len, df_name, df_name_len);
            len += df_name_len;
        }
    }

    // the encrypted key material and the DAM MAC follow as continuation data
    memcpy(data + len, enck, enck_len);
    len += enck_len;
    memcpy(data + len, dam_mac, dam_mac_len);
    len += dam_mac_len;

    uint8_t resp[32] = {0};
    size_t resp_len = 0;
    return nxpsc_exchange(card, DF_CREATE_DELEGATED_APP, data, len, MODE_MAC, MODE_MAC,
                          resp, sizeof(resp), &resp_len);
}

int nxpsc_get_delegated_info(nxpsc_card_t *card, uint16_t dam_slot,
                             nxpsc_delegate_info_t *info) {
    if (card == NULL || info == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t data[2] = { (uint8_t)(dam_slot & 0xFF), (uint8_t)(dam_slot >> 8) };
    uint8_t resp[32] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_exchange(card, DF_GET_DELEGATE_INFO, data, sizeof(data), MODE_MAC, MODE_MAC,
                            resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (resp_len < 8) {
        return NXPSC_E_LENGTH;
    }

    memset(info, 0, sizeof(*info));
    info->dam_slot_version = resp[0];
    info->quota_limit = (uint16_t)(resp[1] | (resp[2] << 8));
    info->free_blocks = (uint16_t)(resp[3] | (resp[4] << 8));
    info->aid = (uint32_t)resp[5] | ((uint32_t)resp[6] << 8) | ((uint32_t)resp[7] << 16);
    return NXPSC_OK;
}

//-----------------------------------------------------------------------------
// MIFARE Classic mapping, EV2 XL and EV3
//-----------------------------------------------------------------------------
int nxpsc_create_mfc_mapping(nxpsc_card_t *card, const uint8_t *data, size_t len) {
    if (card == NULL || data == NULL || len == 0 || len > 64) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    // the mapping carries key material, the card only accepts it enciphered
    return nxpsc_exchange(card, DF_CREATE_MFC_MAPPING, data, len, MODE_ENC, MODE_MAC,
                          resp, sizeof(resp), &resp_len);
}

int nxpsc_restrict_mfc_update(nxpsc_card_t *card, const uint8_t *data, size_t len) {
    if (card == NULL || (len > 0 && data == NULL) || len > 32) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    return nxpsc_exchange(card, DF_RESTRICT_MFC_UPDATE, data, len, eff_mode(card, MODE_MAC),
                          eff_mode(card, MODE_MAC), resp, sizeof(resp), &resp_len);
}

//-----------------------------------------------------------------------------
// transaction notification, used by ECP capable readers
//-----------------------------------------------------------------------------
int nxpsc_notify_transaction_success(nxpsc_card_t *card) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    return nxpsc_exchange(card, DF_NOTIFY_TX_SUCCESS, NULL, 0, eff_mode(card, MODE_MAC),
                          eff_mode(card, MODE_MAC), resp, sizeof(resp), &resp_len);
}

//-----------------------------------------------------------------------------
// key set management, EV2 and later
//-----------------------------------------------------------------------------
int nxpsc_init_key_set(nxpsc_card_t *card, uint8_t key_set, nxpsc_keytype_t key_type) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    // InitializeKeySet takes exactly two bytes, verified against EV3: one and
    // three byte payloads answer 0x7E. the second is the key type of the new
    // set, carried unshifted rather than in the top two bits the way a key
    // number carries it
    uint8_t type_code;
    switch (key_type) {
        case NXPSC_KEY_DES:
        case NXPSC_KEY_2K3DES:
            type_code = 0x00;
            break;
        case NXPSC_KEY_3K3DES:
            type_code = 0x01;
            break;
        case NXPSC_KEY_AES128:
            type_code = 0x02;
            break;
        default:
            return NXPSC_E_UNSUPPORTED;
    }

    uint8_t data[2] = { key_set, type_code };
    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    return nxpsc_exchange(card, DF_INIT_KEY_SETTINGS, data, sizeof(data), MODE_MAC, MODE_MAC,
                          resp, sizeof(resp), &resp_len);
}

int nxpsc_finalize_key_set(nxpsc_card_t *card, uint8_t key_set, uint8_t key_set_version) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t data[2] = { key_set, key_set_version };
    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    return nxpsc_exchange(card, DF_FINALIZE_KEY_SETTINGS, data, sizeof(data), MODE_MAC, MODE_MAC,
                          resp, sizeof(resp), &resp_len);
}

int nxpsc_roll_key_set(nxpsc_card_t *card, uint8_t key_set) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    // rolling swaps the whole key set, including the key the running session
    // was built from, so the card answers without a MAC and the session is
    // gone once it has. asking for a MACed answer here reports a length error
    // over a command the card actually carried out
    int rc = nxpsc_exchange(card, DF_ROLL_KEY_SETTINGS, &key_set, 1, MODE_MAC, MODE_PLAIN,
                            resp, sizeof(resp), &resp_len);
    nxpsc_reset_channel(card);
    return rc;
}

//-----------------------------------------------------------------------------
// proximity check, the relay attack countermeasure of EV2 and later
//-----------------------------------------------------------------------------
// The proximity check exchange answers 0x90 rather than 0x00 on EV3, which is
// the same value the library calls DF_S_SIGNATURE elsewhere. SpringCard, who
// build readers for this silicon, treat an SW of 0x9190 from PreparePC as
// success, and the response MAC is computed over that status, so accept both.
//
// With this the whole exchange runs on EV3: PreparePC answers 0x90 with
// Option, a two byte published response time and PPS1, the rounds are
// answered, and VerifyPC returns eight bytes. What does not yet work is
// verifying those eight bytes, and nxpsc_proximity_check() reports that
// honestly through mac_ok rather than calling the check passed.
//
// The MAC input is not simply a field ordering question. 456 combinations of
// truncation, random interleaving and header layout were tried against two
// captured exchanges and none reproduces the card's answer. The likely reason
// is that the proximity check belongs to the Virtual Card protocol rather than
// to a DESFire application session: SpringCard reach it through ISOSelect with
// an installation identifier followed by IsoExternalAuthenticate, using a
// separate VC proximity key, none of which this library implements yet.
static bool pc_status_ok(uint8_t status) {
    return (status == DF_S_OK || status == DF_S_SIGNATURE);
}

int nxpsc_proximity_check(nxpsc_card_t *card, const nxpsc_key_t *pc_key, uint8_t rounds,
                          bool *mac_ok) {

    // the challenge is split evenly, so only a round count that divides 8
    // produces equal chunks. LogicalAccess asserts the same set
    if (card == NULL || pc_key == NULL ||
            (rounds != 1 && rounds != 2 && rounds != 4 && rounds != PC_MAX_ROUNDS)) {
        return NXPSC_E_PARAM;
    }
    if (pc_key->type != NXPSC_KEY_AES128) {
        return NXPSC_E_UNSUPPORTED;
    }

    if (mac_ok != NULL) {
        *mac_ok = false;
    }

    uint8_t challenge[PC_CHALLENGE_LEN] = {0};
    int rc = nxpsc_random_bytes(challenge, sizeof(challenge));
    if (rc != NXPSC_OK) {
        return rc;
    }

    // PreparePC returns the timing options, and on some cards one extra byte
    uint8_t status = 0;
    uint8_t prep[16] = {0};
    size_t prep_len = 0;

    rc = nxpsc_raw_exchange(card, DF_PREPARE_PC, NULL, 0, &status, prep, sizeof(prep), &prep_len);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (pc_status_ok(status) == false) {
        nxpsc_reset_channel(card);
        return NXPSC_E_CARD;
    }

    if (prep_len < 3) {
        nxpsc_reset_channel(card);
        return NXPSC_E_LENGTH;
    }

    // bit 0 of the Option byte is what says a PPS1 byte follows, rather than
    // the response simply being longer. EV3 answers 01 03 20 0A, so Option
    // 0x01, a published response time of 0x0320 and PPS1 0x0A
    size_t opt_len = 3;
    bool has_ext = (prep[0] & 0x01) != 0;
    if (has_ext && prep_len < 4) {
        nxpsc_reset_channel(card);
        return NXPSC_E_LENGTH;
    }
    uint8_t ext = has_ext ? prep[3] : 0x00;

    // the challenge is split over the requested number of rounds, the card
    // answers each part, and both halves are interleaved for the final MAC
    uint8_t exchanged[PC_CHALLENGE_LEN * 2] = {0};
    size_t exchanged_len = 0;
    size_t offset = 0;
    size_t split = PC_CHALLENGE_LEN / rounds;
    if (split == 0) {
        split = 1;
    }

    for (uint8_t round = 0; round < rounds; round++) {
        size_t remaining = PC_CHALLENGE_LEN - offset;
        size_t part = ((round + 1) == rounds) ? remaining : ((split < remaining) ? split : remaining);
        if (part == 0) {
            return NXPSC_E_PARAM;
        }

        uint8_t payload[1 + PC_CHALLENGE_LEN] = {0};
        payload[0] = (uint8_t)part;
        memcpy(payload + 1, challenge + offset, part);

        uint8_t answer[32] = {0};
        size_t answer_len = 0;
        rc = nxpsc_raw_exchange(card, DF_PROXIMITY_CHECK, payload, part + 1, &status,
                                answer, sizeof(answer), &answer_len);
        if (rc != NXPSC_OK) {
            return rc;
        }
        if (pc_status_ok(status) == false) {
            nxpsc_reset_channel(card);
            return NXPSC_E_CARD;
        }

        size_t slice = (answer_len < part) ? answer_len : part;
        memcpy(exchanged + exchanged_len, answer, slice);
        exchanged_len += slice;
        memcpy(exchanged + exchanged_len, challenge + offset, part);
        exchanged_len += part;

        offset += part;
    }

    uint8_t mac_input[1 + 3 + 1 + (PC_CHALLENGE_LEN * 2)] = {0};
    size_t mac_input_len = 0;

    mac_input[mac_input_len++] = DF_VERIFY_PC;
    memcpy(mac_input + mac_input_len, prep, opt_len);
    mac_input_len += opt_len;
    if (has_ext) {
        mac_input[mac_input_len++] = ext;
    }
    memcpy(mac_input + mac_input_len, exchanged, exchanged_len);
    mac_input_len += exchanged_len;

    uint8_t mac[PC_MAC_LEN] = {0};
    rc = cmac8(pc_key->data, mac_input, mac_input_len, mac);
    if (rc != NXPSC_OK) {
        return rc;
    }

    uint8_t verify[32] = {0};
    size_t verify_len = 0;
    rc = nxpsc_raw_exchange(card, DF_VERIFY_PC, mac, sizeof(mac), &status,
                            verify, sizeof(verify), &verify_len);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (pc_status_ok(status) == false) {
        nxpsc_reset_channel(card);
        return NXPSC_E_CARD;
    }

    if (verify_len < PC_MAC_LEN) {
        nxpsc_secure_zero(challenge, sizeof(challenge));
        nxpsc_secure_zero(exchanged, sizeof(exchanged));
        nxpsc_secure_zero(mac_input, sizeof(mac_input));
        nxpsc_secure_zero(mac, sizeof(mac));
        nxpsc_secure_zero(verify, sizeof(verify));
        return NXPSC_E_LENGTH;
    }

    // same input with the response status in place of the command byte
    mac_input[0] = DF_S_SIGNATURE;

    uint8_t expected[PC_MAC_LEN] = {0};
    rc = cmac8(pc_key->data, mac_input, mac_input_len, expected);
    if (rc != NXPSC_OK) {
        return rc;
    }

    bool ok = nxpsc_memeq(verify, expected, PC_MAC_LEN);
    if (mac_ok != NULL) {
        *mac_ok = ok;
    }
    if (ok == false) {
        nxpsc_secure_zero(challenge, sizeof(challenge));
        nxpsc_secure_zero(exchanged, sizeof(exchanged));
        nxpsc_secure_zero(mac_input, sizeof(mac_input));
        nxpsc_secure_zero(mac, sizeof(mac));
        nxpsc_secure_zero(verify, sizeof(verify));
        nxpsc_secure_zero(expected, sizeof(expected));
        return NXPSC_E_AUTH;
    }

    nxpsc_secure_zero(challenge, sizeof(challenge));
    nxpsc_secure_zero(exchanged, sizeof(exchanged));
    nxpsc_secure_zero(mac_input, sizeof(mac_input));
    nxpsc_secure_zero(mac, sizeof(mac));
    nxpsc_secure_zero(verify, sizeof(verify));
    nxpsc_secure_zero(expected, sizeof(expected));
    return NXPSC_OK;
}

//-----------------------------------------------------------------------------
// SetConfiguration convenience wrappers
//-----------------------------------------------------------------------------
// option 0x00, one byte, four flags. the format bit is inverted: the byte says
// what is enabled, so a set bit 0 means format stays available
int nxpsc_set_picc_config_ex(nxpsc_card_t *card, const nxpsc_picc_config_t *config) {
    if (card == NULL || config == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t value = (uint8_t)((config->disable_format ? 0x00 : 0x01) |
                              (config->random_uid ? 0x02 : 0x00) |
                              (config->pc_mandatory ? 0x04 : 0x00) |
                              (config->auth_vc_mandatory ? 0x08 : 0x00));
    return nxpsc_set_configuration(card, 0x00, &value, 1);
}

int nxpsc_set_picc_config(nxpsc_card_t *card, bool disable_format, bool random_uid) {
    nxpsc_picc_config_t config;
    memset(&config, 0, sizeof(config));
    config.disable_format = disable_format;
    config.random_uid = random_uid;
    return nxpsc_set_picc_config_ex(card, &config);
}

int nxpsc_set_default_key(nxpsc_card_t *card, const nxpsc_key_t *key) {
    if (card == NULL || key == NULL) {
        return NXPSC_E_PARAM;
    }

    size_t key_len = nxpsc_key_size(key->type);
    if (key_len == 0 || key_len > 24) {
        return NXPSC_E_UNSUPPORTED;
    }

    uint8_t data[25] = {0};
    memcpy(data, key->data, key_len);
    // the payload is always 24 bytes of key plus the version byte
    data[24] = key->version;

    return nxpsc_set_configuration(card, 0x01, data, sizeof(data));
}

int nxpsc_set_ats(nxpsc_card_t *card, const uint8_t *ats, size_t len) {
    if (card == NULL || ats == NULL || len == 0 || len > 32) {
        return NXPSC_E_PARAM;
    }
    return nxpsc_set_configuration(card, 0x02, ats, len);
}
