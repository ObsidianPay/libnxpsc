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
// libnxpsc - DESFire application, file and key management
//-----------------------------------------------------------------------------

#include "nxpsc/nxpsc.h"
#include "nxpsc_internal.h"

#include <stdlib.h>
#include <string.h>

//-----------------------------------------------------------------------------
// helpers
//-----------------------------------------------------------------------------
// without a session every command is plain, no matter what the caller asked
// for. a session that the card threw away mid conversation is the exception,
// there the caller asked for protection we can no longer give, so the mode is
// left alone and nxpsc_exchange() refuses it with NXPSC_E_AUTH
static nxpsc_mode_t eff(const nxpsc_card_t *card, nxpsc_mode_t mode) {
    if (card->authenticated == false && card->session_lost == false) {
        return MODE_PLAIN;
    }
    return mode;
}

// ISO chaining swaps the file access opcodes, the payloads stay identical
static uint8_t file_cmd(const nxpsc_card_t *card, uint8_t native, uint8_t chained) {
    return card->iso_chaining ? chained : native;
}

static void put_u24(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value & 0xFF);
    out[1] = (uint8_t)((value >> 8) & 0xFF);
    out[2] = (uint8_t)((value >> 16) & 0xFF);
}

static uint32_t get_u24(const uint8_t *in) {
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16);
}

static bool fits_u24(uint32_t value) {
    return (value & 0xFF000000U) == 0;
}

static void put_u32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value & 0xFF);
    out[1] = (uint8_t)((value >> 8) & 0xFF);
    out[2] = (uint8_t)((value >> 16) & 0xFF);
    out[3] = (uint8_t)((value >> 24) & 0xFF);
}

static int32_t get_i32(const uint8_t *in) {
    return (int32_t)((uint32_t)in[0] | ((uint32_t)in[1] << 8) |
                     ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24));
}

static uint8_t keytype_to_card(nxpsc_keytype_t type) {
    switch (type) {
        case NXPSC_KEY_3K3DES:
            return 0x40;
        case NXPSC_KEY_AES128:
        case NXPSC_KEY_AES256:
            return 0x80;
        case NXPSC_KEY_DES:
        case NXPSC_KEY_2K3DES:
        default:
            break;
    }
    return 0x00;
}

static nxpsc_keytype_t keytype_from_card(uint8_t raw) {
    switch (raw & 0xC0) {
        case 0x40:
            return NXPSC_KEY_3K3DES;
        case 0x80:
            return NXPSC_KEY_AES128;
        default:
            break;
    }
    return NXPSC_KEY_2K3DES;
}

uint16_t nxpsc_pack_access(const nxpsc_access_t *access) {
    if (access == NULL) {
        return 0;
    }
    return (uint16_t)(((access->read & 0x0F) << 12) | ((access->write & 0x0F) << 8) |
                      ((access->read_write & 0x0F) << 4) | (access->change & 0x0F));
}

void nxpsc_unpack_access(uint16_t raw, nxpsc_access_t *access) {
    if (access == NULL) {
        return;
    }
    access->read = (uint8_t)((raw >> 12) & 0x0F);
    access->write = (uint8_t)((raw >> 8) & 0x0F);
    access->read_write = (uint8_t)((raw >> 4) & 0x0F);
    access->change = (uint8_t)(raw & 0x0F);
}

static uint8_t comm_to_file(nxpsc_commmode_t comm) {
    switch (comm) {
        case NXPSC_COMM_MAC:
            return 0x01;
        case NXPSC_COMM_FULL:
            return 0x03;
        case NXPSC_COMM_PLAIN:
        default:
            break;
    }
    return 0x00;
}

static nxpsc_commmode_t comm_from_file(uint8_t raw) {
    switch (raw & 0x03) {
        case 0x01:
            return NXPSC_COMM_MAC;
        case 0x03:
            return NXPSC_COMM_FULL;
        default:
            break;
    }
    return NXPSC_COMM_PLAIN;
}

//-----------------------------------------------------------------------------
// applications
//-----------------------------------------------------------------------------
int nxpsc_select_application(nxpsc_card_t *card, uint32_t aid) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }
    if (fits_u24(aid) == false) {
        return NXPSC_E_LENGTH;
    }

    uint8_t data[3];
    put_u24(data, aid);

    // selecting an application always drops the running session
    nxpsc_reset_channel(card);

    size_t resp_len = 0;
    uint8_t resp[8] = {0};
    int rc = nxpsc_exchange(card, DF_SELECT_APPLICATION, data, sizeof(data), MODE_PLAIN,
                            MODE_PLAIN, resp, sizeof(resp), &resp_len);
    if (rc == NXPSC_OK) {
        card->selected_aid = aid;
    }
    return rc;
}

// CreateApplication payload, in the order the card wants it:
//   AID(3) KeySett1 KeySett2 [KeySett3 AKSVersion NoKeySets MaxKeySize
//   AppKeySetSett] [ISOFileID(2) ISODFName]
// KeySett2 bit 4 announces KeySett3, and KeySett3 bit 0 announces the four key
// set bytes. the key set block sits before the ISO fields, not after
static int create_app(nxpsc_card_t *card, uint32_t aid, const nxpsc_app_config_t *cfg) {
    if (card == NULL || cfg == NULL || cfg->num_keys == 0 || cfg->num_keys > NXPSC_MAX_KEYS) {
        return NXPSC_E_PARAM;
    }
    if (fits_u24(aid) == false) {
        return NXPSC_E_LENGTH;
    }
    if (cfg->iso_fid_enabled && cfg->df_name_len > 16) {
        return NXPSC_E_LENGTH;
    }
    if (cfg->df_name_len > 0 && cfg->df_name == NULL) {
        return NXPSC_E_PARAM;
    }
    // a key set aware application holds at least the active set plus one more
    if (cfg->num_key_sets == 1 || cfg->num_key_sets > NXPSC_MAX_KEYS) {
        return NXPSC_E_PARAM;
    }
    // AppKeySetSett is three bits wide
    if (cfg->key_set_settings > 0x07) {
        return NXPSC_E_PARAM;
    }

    uint8_t data[32] = {0};
    size_t len = 0;
    bool key_sets = (cfg->num_key_sets >= 2);
    bool has_ks3 = (key_sets || cfg->specific_vc_keys || cfg->specific_capability_data);

    put_u24(data, aid);
    len = 3;
    data[len++] = cfg->key_settings;
    data[len++] = (uint8_t)((cfg->num_keys & 0x0F) | keytype_to_card(cfg->key_type)
                            | (cfg->iso_fid_enabled ? 0x20 : 0x00)
                            | (has_ks3 ? 0x10 : 0x00));

    if (has_ks3) {
        data[len++] = (uint8_t)((key_sets ? 0x01 : 0x00)
                                | (cfg->specific_vc_keys ? 0x02 : 0x00)
                                | (cfg->specific_capability_data ? 0x04 : 0x00));
    }

    // the four key set bytes only follow when KeySett3 announced key sets
    if (key_sets) {
        data[len++] = cfg->key_set_version;
        data[len++] = cfg->num_key_sets;
        data[len++] = cfg->max_key_size;
        data[len++] = cfg->key_set_settings;
    }

    if (cfg->iso_fid_enabled) {
        data[len++] = (uint8_t)(cfg->iso_fid & 0xFF);
        data[len++] = (uint8_t)((cfg->iso_fid >> 8) & 0xFF);
        if (cfg->df_name_len > 0) {
            memcpy(data + len, cfg->df_name, cfg->df_name_len);
            len += cfg->df_name_len;
        }
    }

    size_t resp_len = 0;
    uint8_t resp[8] = {0};
    return nxpsc_exchange(card, DF_CREATE_APPLICATION, data, len, eff(card, MODE_MAC),
                          eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
}

int nxpsc_create_application(nxpsc_card_t *card, uint32_t aid, uint8_t key_settings,
                             uint8_t num_keys, nxpsc_keytype_t key_type) {
    nxpsc_app_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.key_settings = key_settings;
    cfg.num_keys = num_keys;
    cfg.key_type = key_type;
    return create_app(card, aid, &cfg);
}

int nxpsc_create_application_iso(nxpsc_card_t *card, uint32_t aid, uint8_t key_settings,
                                 uint8_t num_keys, nxpsc_keytype_t key_type,
                                 uint16_t iso_fid, const uint8_t *df_name, size_t df_name_len) {
    nxpsc_app_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.key_settings = key_settings;
    cfg.num_keys = num_keys;
    cfg.key_type = key_type;
    cfg.iso_fid_enabled = true;
    cfg.iso_fid = iso_fid;
    cfg.df_name = df_name;
    cfg.df_name_len = df_name_len;
    return create_app(card, aid, &cfg);
}

int nxpsc_create_application_ex(nxpsc_card_t *card, uint32_t aid,
                                const nxpsc_app_config_t *config) {
    return create_app(card, aid, config);
}

int nxpsc_delete_application(nxpsc_card_t *card, uint32_t aid) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t data[3];
    put_u24(data, aid);

    size_t resp_len = 0;
    uint8_t resp[8] = {0};
    return nxpsc_exchange(card, DF_DELETE_APPLICATION, data, sizeof(data), eff(card, MODE_MAC),
                          eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
}

int nxpsc_get_application_ids(nxpsc_card_t *card, uint32_t *aids, size_t cap, size_t *count) {
    if (card == NULL || aids == NULL || count == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[NXPSC_MAX_APPS * 3] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_exchange(card, DF_GET_APPLICATION_IDS, NULL, 0, eff(card, MODE_MAC),
                            eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    size_t n = resp_len / 3;
    if (n > cap) {
        return NXPSC_E_LENGTH;
    }

    for (size_t i = 0; i < n; i++) {
        aids[i] = get_u24(resp + i * 3);
    }
    *count = n;
    return NXPSC_OK;
}

int nxpsc_get_df_names(nxpsc_card_t *card, nxpsc_app_t *apps, size_t cap, size_t *count) {
    if (card == NULL || apps == NULL || count == NULL) {
        return NXPSC_E_PARAM;
    }

    // This must not be sent while the PICC has a session open. Measured by the
    // proxmark3 project on three EV1 8K cards: with one open the card answers
    // the first 0xAF continuation frame of the chained response with 0xC1,
    // "PICC will be disabled", and is dead from then on. EV2 and EV3 dropped
    // the self disabling statuses, so it survives there, which is what makes
    // the mistake easy to ship. It is the card's session that matters, not
    // whether we MAC the command, so refusing is the only safe answer.
    // SelectApplication ends the session on the card, so select and then call.
    if (card->authenticated) {
        return NXPSC_E_AUTH;
    }

    // The card answers one application per frame, and the DF name carries no
    // length of its own, so the frame boundary is the only thing that says
    // where it ends. Reading the frames one at a time keeps that; following the
    // 0xAF chain in one go concatenates them and the entries become
    // indistinguishable. proxmark3 keeps each frame's length for the same
    // reason. There is no session by the check above, so no MAC or command
    // counter to maintain across the frames.
    size_t n = 0;
    uint8_t status = 0;
    uint8_t cmd = DF_GET_DF_NAMES;

    for (;;) {
        uint8_t frame[64] = {0};
        size_t frame_len = 0;

        int rc = nxpsc_raw_exchange_ex(card, cmd, NULL, 0, &status, frame, sizeof(frame),
                                       &frame_len, false);
        if (rc != NXPSC_OK) {
            return rc;
        }
        if (status != DF_S_OK && status != DF_S_ADDITIONAL_FRAME) {
            card->last_status = status;
            return NXPSC_E_CARD;
        }

        // AID(3) || ISO FID(2) || DF name, the name filling the rest of it
        if (frame_len >= 5 && n < cap) {
            size_t name_len = frame_len - 5;
            if (name_len > 16) {
                name_len = 16;
            }

            memset(&apps[n], 0, sizeof(apps[n]));
            apps[n].aid = get_u24(frame);
            apps[n].iso_fid = (uint16_t)(frame[3] | (frame[4] << 8));
            apps[n].iso_fid_enabled = true;
            memcpy(apps[n].df_name, frame + 5, name_len);
            apps[n].df_name_len = (uint8_t)name_len;
            n++;
        }

        if (status != DF_S_ADDITIONAL_FRAME) {
            break;
        }
        cmd = DF_ADDITIONAL_FRAME;
    }

    *count = n;
    return NXPSC_OK;
}

int nxpsc_format_picc(nxpsc_card_t *card) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    size_t resp_len = 0;
    uint8_t resp[8] = {0};
    return nxpsc_exchange(card, DF_FORMAT_PICC, NULL, 0, eff(card, MODE_MAC),
                          eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
}

int nxpsc_set_configuration(nxpsc_card_t *card, uint8_t option, const uint8_t *data, size_t len) {
    if (card == NULL || (len > 0 && data == NULL) || len > 64) {
        return NXPSC_E_PARAM;
    }
    if (card->authenticated == false) {
        return NXPSC_E_AUTH;
    }

    uint8_t buf[72] = {0};
    buf[0] = option;
    if (len > 0) {
        memcpy(buf + 1, data, len);
    }

    size_t resp_len = 0;
    uint8_t resp[16] = {0};
    return nxpsc_exchange(card, DF_SET_CONFIGURATION, buf, len + 1, MODE_ENC, MODE_MAC,
                          resp, sizeof(resp), &resp_len);
}

//-----------------------------------------------------------------------------
// keys
//-----------------------------------------------------------------------------
int nxpsc_get_key_version(nxpsc_card_t *card, uint8_t key_no, uint8_t *version) {
    if (card == NULL || version == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_exchange(card, DF_GET_KEY_VERSION, &key_no, 1, eff(card, MODE_MAC),
                            eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (resp_len < 1) {
        return NXPSC_E_LENGTH;
    }

    *version = resp[0];
    return NXPSC_OK;
}

int nxpsc_get_key_settings(nxpsc_card_t *card, uint8_t *key_settings, uint8_t *num_keys,
                           nxpsc_keytype_t *key_type) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_exchange(card, DF_GET_KEY_SETTINGS, NULL, 0, eff(card, MODE_MAC),
                            eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (resp_len < 2) {
        return NXPSC_E_LENGTH;
    }

    if (key_settings != NULL) {
        *key_settings = resp[0];
    }
    if (num_keys != NULL) {
        *num_keys = resp[1] & 0x0F;
    }
    if (key_type != NULL) {
        *key_type = keytype_from_card(resp[1]);
    }
    return NXPSC_OK;
}

int nxpsc_change_key_settings(nxpsc_card_t *card, uint8_t key_settings) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }
    if (card->authenticated == false) {
        return NXPSC_E_AUTH;
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    return nxpsc_exchange(card, DF_CHANGE_KEY_SETTINGS, &key_settings, 1, MODE_ENC,
                          MODE_MAC, resp, sizeof(resp), &resp_len);
}

// ChangeKey / ChangeKeyEV2 payload, see AN12343 and the reference libraries.
// the new key is XORed with the old one unless it is the key we authenticated
// with, and the checksums differ per secure channel
static int change_key(nxpsc_card_t *card, bool ev2, uint8_t key_set, uint8_t key_no,
                      const nxpsc_key_t *old_key, const nxpsc_key_t *new_key) {
    if (card == NULL || nxpsc_key_is_valid(new_key) == false) {
        return NXPSC_E_PARAM;
    }
    if (card->authenticated == false) {
        return NXPSC_E_AUTH;
    }

    bool same_key = (key_no == card->key_no) && (ev2 == false);
    // Changing the key the running session was built on ends that session, so
    // the card answers without a MAC. Asking for a MACed answer turns a key
    // change the card carried out into a local length error, which is the worst
    // way for this particular command to fail: the key really has changed and
    // the caller has been told it did not. A key in a key set other than the
    // active one is not the session key, so that case keeps its MAC.
    bool ends_session = (key_no == card->key_no) && (ev2 == false || key_set == 0);
    if (same_key == false && nxpsc_key_is_valid(old_key) == false) {
        return NXPSC_E_PARAM;
    }

    uint8_t key_no_data = key_no & 0x3F;
    // the PICC master key changes its type only through the key number field
    if (card->selected_aid == 0 && key_no == 0) {
        key_no_data |= (uint8_t)((keytype_to_card(new_key->type) & 0xC0) >> 6) << 6;
    }

    uint8_t old_buf[NXPSC_MAX_KEY_SIZE] = {0};
    uint8_t new_buf[NXPSC_MAX_KEY_SIZE] = {0};

    // A (2K3)DES key carries its version in the low bit of every key byte, so
    // the bytes the card stores are not the bytes the caller handed over. Both
    // keys have to be put through the same normalisation: the new one because
    // that is what gets written, and the old one because the card XORs against
    // what it stored. Missing it on the old key is invisible until the key is
    // changed a second time, since DES treats those bits as parity and
    // authenticates either way, and then the CRC fails with 0x1E.
    // Normalise before duplicating a single DES key, or the two halves stop
    // matching and the card reads it as 2TDEA.
    size_t new_len = nxpsc_key_size(new_key->type);
    memcpy(new_buf, new_key->data, new_len);
    if (new_key->type != NXPSC_KEY_AES128 && new_key->type != NXPSC_KEY_AES256) {
        nxpsc_des_key_set_version(new_buf, new_key->type, new_key->version);
    }
    if (new_key->type == NXPSC_KEY_DES) {
        // a single DES key travels as a 2K3DES key with both halves equal
        memcpy(new_buf + 8, new_buf, 8);
        new_len = 16;
    }

    if (same_key == false) {
        memcpy(old_buf, old_key->data, nxpsc_key_size(old_key->type));
        if (old_key->type != NXPSC_KEY_AES128 && old_key->type != NXPSC_KEY_AES256) {
            nxpsc_des_key_set_version(old_buf, old_key->type, old_key->version);
        }
        if (old_key->type == NXPSC_KEY_DES) {
            memcpy(old_buf + 8, old_buf, 8);
        }
    }

    // command byte and key number prefix the checksum input
    uint8_t frame[NXPSC_MAX_KEY_SIZE + 16] = {0};
    uint8_t *payload = frame + 2;
    size_t payload_len = new_len;

    frame[0] = ev2 ? DF_CHANGE_KEY_EV2 : DF_CHANGE_KEY;
    frame[1] = key_no_data;

    memcpy(payload, new_buf, new_len);
    if (same_key == false) {
        nxpsc_xor(payload, old_buf, new_len);
    }

    // AES keys carry their version as a separate byte, (2K3)DES keys carry it
    // in the low bit of every key byte. that is a property of the key being
    // written, including into a key set, so it does not change for a key set
    // other than the active one
    if (new_key->type == NXPSC_KEY_AES128 || new_key->type == NXPSC_KEY_AES256) {
        payload[payload_len++] = new_key->version;
    }

    switch (card->channel) {
        case NXPSC_CHAN_D40:
            nxpsc_crc16(payload, payload_len, payload + payload_len);
            payload_len += 2;
            if (same_key == false) {
                nxpsc_crc16(new_buf, new_len, payload + payload_len);
                payload_len += 2;
            }
            break;

        case NXPSC_CHAN_EV1:
            // the EV1 CRC32 covers the command byte, the key number and the payload
            nxpsc_crc32(frame, payload_len + 2, payload + payload_len);
            payload_len += 4;
            if (same_key == false) {
                nxpsc_crc32(new_buf, new_len, payload + payload_len);
                payload_len += 4;
            }
            break;

        case NXPSC_CHAN_EV2:
        case NXPSC_CHAN_LRP:
            // EV2 wraps the payload in the session, only the new key CRC is added
            if (same_key == false) {
                nxpsc_crc32(new_buf, new_len, payload + payload_len);
                payload_len += 4;
            }
            break;

        default:
            return NXPSC_E_AUTH;
    }

    uint8_t data[NXPSC_MAX_KEY_SIZE + 16] = {0};
    size_t len = 0;

    if (ev2) {
        data[len++] = key_set;
    }
    data[len++] = key_no_data;
    memcpy(data + len, payload, payload_len);
    len += payload_len;

    uint8_t resp[16] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_exchange(card, ev2 ? DF_CHANGE_KEY_EV2 : DF_CHANGE_KEY, data, len,
                            MODE_ENC_PLAIN, ends_session ? MODE_PLAIN : MODE_MAC,
                            resp, sizeof(resp), &resp_len);

    if (ends_session) {
        nxpsc_reset_channel(card);
    }
    return rc;
}

int nxpsc_change_key(nxpsc_card_t *card, uint8_t key_no, const nxpsc_key_t *old_key,
                     const nxpsc_key_t *new_key) {
    return change_key(card, false, 0, key_no, old_key, new_key);
}

int nxpsc_change_key_ev2(nxpsc_card_t *card, uint8_t key_set, uint8_t key_no,
                         const nxpsc_key_t *old_key, const nxpsc_key_t *new_key) {
    return change_key(card, true, key_set, key_no, old_key, new_key);
}

int nxpsc_diversify_an10922(const nxpsc_key_t *master, const uint8_t *div_input,
                            size_t div_input_len, nxpsc_key_t *out) {
    return nxpsc_kdf_an10922(master, div_input, div_input_len, out);
}

//-----------------------------------------------------------------------------
// files
//-----------------------------------------------------------------------------
int nxpsc_get_file_ids(nxpsc_card_t *card, uint8_t *ids, size_t cap, size_t *count) {
    if (card == NULL || ids == NULL || count == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[NXPSC_MAX_FILES + 16] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_exchange(card, DF_GET_FILE_IDS, NULL, 0, eff(card, MODE_MAC),
                            eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (resp_len > cap) {
        return NXPSC_E_LENGTH;
    }

    memcpy(ids, resp, resp_len);
    *count = resp_len;
    return NXPSC_OK;
}

int nxpsc_get_iso_file_ids(nxpsc_card_t *card, uint16_t *ids, size_t cap, size_t *count) {
    if (card == NULL || ids == NULL || count == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[NXPSC_MAX_FILES * 2 + 16] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_exchange(card, DF_GET_ISO_FILE_IDS, NULL, 0, eff(card, MODE_MAC),
                            eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    size_t n = resp_len / 2;
    if (n > cap) {
        return NXPSC_E_LENGTH;
    }

    for (size_t i = 0; i < n; i++) {
        ids[i] = (uint16_t)(resp[i * 2] | (resp[i * 2 + 1] << 8));
    }
    *count = n;
    return NXPSC_OK;
}

int nxpsc_get_file_settings(nxpsc_card_t *card, uint8_t file_no, nxpsc_file_settings_t *settings) {
    if (card == NULL || settings == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[64] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_exchange(card, DF_GET_FILE_SETTINGS, &file_no, 1, eff(card, MODE_MAC),
                            eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (resp_len < 4) {
        return NXPSC_E_LENGTH;
    }

    memset(settings, 0, sizeof(*settings));
    settings->type = (nxpsc_filetype_t)resp[0];
    settings->options = resp[1];
    settings->comm = comm_from_file(resp[1]);
    settings->sdm_enabled = (resp[1] & 0x40) != 0;
    nxpsc_unpack_access((uint16_t)(resp[2] | (resp[3] << 8)), &settings->access);

    switch (settings->type) {
        case NXPSC_FILE_STD:
        case NXPSC_FILE_BACKUP:
            if (resp_len < 7) {
                return NXPSC_E_LENGTH;
            }
            settings->size = get_u24(resp + 4);
            break;

        case NXPSC_FILE_VALUE:
            if (resp_len < 21) {
                return NXPSC_E_LENGTH;
            }
            settings->lower_limit = get_i32(resp + 4);
            settings->upper_limit = get_i32(resp + 8);
            settings->value = get_i32(resp + 12);
            settings->limited_credit = resp[16];
            break;

        case NXPSC_FILE_LINEAR:
        case NXPSC_FILE_CYCLIC:
            if (resp_len < 13) {
                return NXPSC_E_LENGTH;
            }
            settings->record_size = get_u24(resp + 4);
            settings->max_records = get_u24(resp + 7);
            settings->cur_records = get_u24(resp + 10);
            break;

        default:
            break;
    }
    return NXPSC_OK;
}

int nxpsc_change_file_settings_raw(nxpsc_card_t *card, uint8_t file_no,
                                   const uint8_t *data, size_t len) {
    if (card == NULL || (len > 0 && data == NULL) || len > 128) {
        return NXPSC_E_PARAM;
    }
    if (card->authenticated == false) {
        return NXPSC_E_AUTH;
    }

    uint8_t buf[144] = {0};
    buf[0] = file_no;
    if (len > 0) {
        memcpy(buf + 1, data, len);
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    return nxpsc_exchange(card, DF_CHANGE_FILE_SETTINGS, buf, len + 1, MODE_ENC, MODE_MAC,
                          resp, sizeof(resp), &resp_len);
}

int nxpsc_change_file_settings(nxpsc_card_t *card, uint8_t file_no, nxpsc_commmode_t comm,
                               const nxpsc_access_t *access) {
    if (access == NULL) {
        return NXPSC_E_PARAM;
    }

    uint16_t raw = nxpsc_pack_access(access);
    uint8_t data[3] = {
        comm_to_file(comm),
        (uint8_t)(raw & 0xFF),
        (uint8_t)((raw >> 8) & 0xFF)
    };
    return nxpsc_change_file_settings_raw(card, file_no, data, sizeof(data));
}

static int create_file(nxpsc_card_t *card, uint8_t cmd, uint8_t file_no, uint16_t iso_fid,
                       bool has_iso_fid, nxpsc_commmode_t comm, const nxpsc_access_t *access,
                       const uint8_t *tail, size_t tail_len) {
    if (card == NULL || access == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t data[32] = {0};
    size_t len = 0;

    data[len++] = file_no;
    if (has_iso_fid) {
        data[len++] = (uint8_t)(iso_fid & 0xFF);
        data[len++] = (uint8_t)((iso_fid >> 8) & 0xFF);
    }
    data[len++] = comm_to_file(comm);

    uint16_t raw = nxpsc_pack_access(access);
    data[len++] = (uint8_t)(raw & 0xFF);
    data[len++] = (uint8_t)((raw >> 8) & 0xFF);

    if (tail_len > 0) {
        memcpy(data + len, tail, tail_len);
        len += tail_len;
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    return nxpsc_exchange(card, cmd, data, len, eff(card, MODE_MAC), eff(card, MODE_MAC),
                          resp, sizeof(resp), &resp_len);
}

int nxpsc_create_std_file(nxpsc_card_t *card, uint8_t file_no, uint16_t iso_fid,
                          nxpsc_commmode_t comm, const nxpsc_access_t *access, uint32_t size) {
    if (fits_u24(size) == false) {
        return NXPSC_E_LENGTH;
    }
    uint8_t tail[3];
    put_u24(tail, size);
    return create_file(card, DF_CREATE_STD_DATA_FILE, file_no, iso_fid, iso_fid != 0,
                       comm, access, tail, sizeof(tail));
}

int nxpsc_create_backup_file(nxpsc_card_t *card, uint8_t file_no, uint16_t iso_fid,
                             nxpsc_commmode_t comm, const nxpsc_access_t *access, uint32_t size) {
    if (fits_u24(size) == false) {
        return NXPSC_E_LENGTH;
    }
    uint8_t tail[3];
    put_u24(tail, size);
    return create_file(card, DF_CREATE_BACKUP_DATA_FILE, file_no, iso_fid, iso_fid != 0,
                       comm, access, tail, sizeof(tail));
}

int nxpsc_create_value_file(nxpsc_card_t *card, uint8_t file_no, nxpsc_commmode_t comm,
                            const nxpsc_access_t *access, int32_t lower, int32_t upper,
                            int32_t value, bool limited_credit) {
    uint8_t tail[13];
    put_u32(tail, (uint32_t)lower);
    put_u32(tail + 4, (uint32_t)upper);
    put_u32(tail + 8, (uint32_t)value);
    tail[12] = limited_credit ? 0x01 : 0x00;
    return create_file(card, DF_CREATE_VALUE_FILE, file_no, 0, false, comm, access,
                       tail, sizeof(tail));
}

int nxpsc_create_record_file(nxpsc_card_t *card, bool cyclic, uint8_t file_no, uint16_t iso_fid,
                             nxpsc_commmode_t comm, const nxpsc_access_t *access,
                             uint32_t record_size, uint32_t max_records) {
    if (fits_u24(record_size) == false || fits_u24(max_records) == false) {
        return NXPSC_E_LENGTH;
    }
    uint8_t tail[6];
    put_u24(tail, record_size);
    put_u24(tail + 3, max_records);
    return create_file(card, cyclic ? DF_CREATE_CYCLIC_RECORD : DF_CREATE_LINEAR_RECORD,
                       file_no, iso_fid, iso_fid != 0, comm, access, tail, sizeof(tail));
}

int nxpsc_delete_file(nxpsc_card_t *card, uint8_t file_no) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    return nxpsc_exchange(card, DF_DELETE_FILE, &file_no, 1, eff(card, MODE_MAC),
                          eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
}

//-----------------------------------------------------------------------------
// data files
//-----------------------------------------------------------------------------
int nxpsc_read_data(nxpsc_card_t *card, uint8_t file_no, uint32_t offset, uint32_t length,
                    nxpsc_commmode_t comm, uint8_t *out, size_t cap, size_t *out_len) {
    if (card == NULL || out == NULL || out_len == NULL) {
        return NXPSC_E_PARAM;
    }
    if (fits_u24(offset) == false || fits_u24(length) == false) {
        return NXPSC_E_LENGTH;
    }

    uint8_t data[7];
    data[0] = file_no;
    put_u24(data + 1, offset);
    put_u24(data + 4, length);

    nxpsc_mode_t mode = eff(card, nxpsc_mode_from_public(comm));
    return nxpsc_exchange(card, file_cmd(card, DF_READ_DATA, DF_READ_DATA2),
                          data, sizeof(data), mode, mode, out, cap, out_len);
}

int nxpsc_write_data(nxpsc_card_t *card, uint8_t file_no, uint32_t offset,
                     const uint8_t *data, size_t len, nxpsc_commmode_t comm) {
    if (card == NULL || (len > 0 && data == NULL)) {
        return NXPSC_E_PARAM;
    }
    if (fits_u24(offset) == false || fits_u24((uint32_t)len) == false) {
        return NXPSC_E_LENGTH;
    }
    if (len > NXPSC_MAX_RESPONSE - 16) {
        return NXPSC_E_LENGTH;
    }

    uint8_t *buf = calloc(len + 7, 1);
    if (buf == NULL) {
        return NXPSC_E_MEMORY;
    }

    buf[0] = file_no;
    put_u24(buf + 1, offset);
    put_u24(buf + 4, (uint32_t)len);
    memcpy(buf + 7, data, len);

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    nxpsc_mode_t mode = eff(card, nxpsc_mode_from_public(comm));

    int rc = nxpsc_exchange(card, file_cmd(card, DF_WRITE_DATA, DF_WRITE_DATA2), buf, len + 7, mode,
                            (mode == MODE_PLAIN) ? MODE_PLAIN : MODE_MAC,
                            resp, sizeof(resp), &resp_len);
    free(buf);
    return rc;
}

//-----------------------------------------------------------------------------
// value files
//-----------------------------------------------------------------------------
int nxpsc_get_value(nxpsc_card_t *card, uint8_t file_no, nxpsc_commmode_t comm, int32_t *value) {
    if (card == NULL || value == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[32] = {0};
    size_t resp_len = 0;
    nxpsc_mode_t mode = eff(card, nxpsc_mode_from_public(comm));

    int rc = nxpsc_exchange(card, DF_GET_VALUE, &file_no, 1, mode, mode,
                            resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (resp_len < 4) {
        return NXPSC_E_LENGTH;
    }

    *value = get_i32(resp);
    return NXPSC_OK;
}

static int value_op(nxpsc_card_t *card, uint8_t cmd, uint8_t file_no, int32_t delta,
                    nxpsc_commmode_t comm) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t data[5];
    data[0] = file_no;
    put_u32(data + 1, (uint32_t)delta);

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    nxpsc_mode_t mode = eff(card, nxpsc_mode_from_public(comm));

    return nxpsc_exchange(card, cmd, data, sizeof(data), mode,
                          (mode == MODE_PLAIN) ? MODE_PLAIN : MODE_MAC,
                          resp, sizeof(resp), &resp_len);
}

int nxpsc_credit(nxpsc_card_t *card, uint8_t file_no, int32_t delta, nxpsc_commmode_t comm) {
    return value_op(card, DF_CREDIT, file_no, delta, comm);
}

int nxpsc_limited_credit(nxpsc_card_t *card, uint8_t file_no, int32_t delta, nxpsc_commmode_t comm) {
    return value_op(card, DF_LIMITED_CREDIT, file_no, delta, comm);
}

int nxpsc_debit(nxpsc_card_t *card, uint8_t file_no, int32_t delta, nxpsc_commmode_t comm) {
    return value_op(card, DF_DEBIT, file_no, delta, comm);
}

//-----------------------------------------------------------------------------
// record files
//-----------------------------------------------------------------------------
int nxpsc_write_record(nxpsc_card_t *card, uint8_t file_no, uint32_t offset,
                       const uint8_t *data, size_t len, nxpsc_commmode_t comm) {
    if (card == NULL || (len > 0 && data == NULL)) {
        return NXPSC_E_PARAM;
    }
    if (fits_u24(offset) == false || fits_u24((uint32_t)len) == false) {
        return NXPSC_E_LENGTH;
    }
    if (len > NXPSC_MAX_RESPONSE - 16) {
        return NXPSC_E_LENGTH;
    }

    uint8_t *buf = calloc(len + 7, 1);
    if (buf == NULL) {
        return NXPSC_E_MEMORY;
    }

    buf[0] = file_no;
    put_u24(buf + 1, offset);
    put_u24(buf + 4, (uint32_t)len);
    memcpy(buf + 7, data, len);

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    nxpsc_mode_t mode = eff(card, nxpsc_mode_from_public(comm));

    int rc = nxpsc_exchange(card, file_cmd(card, DF_WRITE_RECORD, DF_WRITE_RECORD2), buf, len + 7, mode,
                            (mode == MODE_PLAIN) ? MODE_PLAIN : MODE_MAC,
                            resp, sizeof(resp), &resp_len);
    free(buf);
    return rc;
}

int nxpsc_update_record(nxpsc_card_t *card, uint8_t file_no, uint32_t record_no,
                        uint32_t offset, const uint8_t *data, size_t len,
                        nxpsc_commmode_t comm) {
    if (card == NULL || (len > 0 && data == NULL)) {
        return NXPSC_E_PARAM;
    }
    if (fits_u24(record_no) == false || fits_u24(offset) == false || fits_u24((uint32_t)len) == false) {
        return NXPSC_E_LENGTH;
    }
    if (len > NXPSC_MAX_RESPONSE - 16) {
        return NXPSC_E_LENGTH;
    }

    uint8_t *buf = calloc(len + 10, 1);
    if (buf == NULL) {
        return NXPSC_E_MEMORY;
    }

    buf[0] = file_no;
    put_u24(buf + 1, record_no);
    put_u24(buf + 4, offset);
    put_u24(buf + 7, (uint32_t)len);
    memcpy(buf + 10, data, len);

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    nxpsc_mode_t mode = eff(card, nxpsc_mode_from_public(comm));

    int rc = nxpsc_exchange(card, file_cmd(card, DF_UPDATE_RECORD, DF_UPDATE_RECORD2),
                            buf, len + 10, mode,
                            (mode == MODE_PLAIN) ? MODE_PLAIN : MODE_MAC,
                            resp, sizeof(resp), &resp_len);
    free(buf);
    return rc;
}

int nxpsc_read_records(nxpsc_card_t *card, uint8_t file_no, uint32_t record_no,
                       uint32_t record_count, nxpsc_commmode_t comm,
                       uint8_t *out, size_t cap, size_t *out_len) {
    if (card == NULL || out == NULL || out_len == NULL) {
        return NXPSC_E_PARAM;
    }
    if (fits_u24(record_no) == false || fits_u24(record_count) == false) {
        return NXPSC_E_LENGTH;
    }

    uint8_t data[7];
    data[0] = file_no;
    put_u24(data + 1, record_no);
    put_u24(data + 4, record_count);

    nxpsc_mode_t mode = eff(card, nxpsc_mode_from_public(comm));
    return nxpsc_exchange(card, file_cmd(card, DF_READ_RECORDS, DF_READ_RECORDS2),
                          data, sizeof(data), mode, mode, out, cap, out_len);
}

int nxpsc_clear_record_file(nxpsc_card_t *card, uint8_t file_no) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    return nxpsc_exchange(card, DF_CLEAR_RECORD_FILE, &file_no, 1, eff(card, MODE_MAC),
                          eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
}

//-----------------------------------------------------------------------------
// transactions
//-----------------------------------------------------------------------------
int nxpsc_commit_transaction(nxpsc_card_t *card) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[32] = {0};
    size_t resp_len = 0;
    return nxpsc_exchange(card, DF_COMMIT_TRANSACTION, NULL, 0, eff(card, MODE_MAC),
                          eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
}

// CommitTransaction with option 0x01: the card returns TMC (4) || TMV (8).
// Requires an application with a TMAC file. tmc and tmv are written only on
// NXPSC_OK.
int nxpsc_commit_transaction_tmac(nxpsc_card_t *card, uint8_t tmc[4], uint8_t tmv[8]) {
    if (card == NULL || tmc == NULL || tmv == NULL) {
        return NXPSC_E_PARAM;
    }

    // Option 0x01 requests TMC and TMV in the response
    uint8_t payload[1] = { 0x01 };

    // TMC (4 bytes) + TMV (8 bytes) = 12 + OVERHEAD bytes
    uint8_t resp[32] = {0};
    size_t resp_len = 0;

    int status = nxpsc_exchange(card, DF_COMMIT_TRANSACTION, payload, sizeof(payload),
                               eff(card, MODE_MAC), eff(card, MODE_MAC),
                               resp, sizeof(resp), &resp_len);

    // Only write output parameters if the transaction succeeds
    if (status == NXPSC_OK) {
        // TMC (4) + TMV (8) = 12
        if (resp_len != 12) {
            return NXPSC_E_LENGTH;
        }

        memcpy(tmc, &resp[0], 4);
        memcpy(tmv, &resp[4], 8);
    }

    return status;
}


int nxpsc_abort_transaction(nxpsc_card_t *card) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;
    return nxpsc_exchange(card, DF_ABORT_TRANSACTION, NULL, 0, eff(card, MODE_MAC),
                          eff(card, MODE_MAC), resp, sizeof(resp), &resp_len);
}

int nxpsc_commit_reader_id(nxpsc_card_t *card, const uint8_t *reader_id, size_t len,
                           uint8_t *enc_prev_reader_id, size_t cap, size_t *out_len) {
    if (card == NULL || reader_id == NULL || len != 16) {
        return NXPSC_E_PARAM;
    }
    if (card->authenticated == false) {
        return NXPSC_E_AUTH;
    }

    uint8_t resp[64] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_exchange(card, DF_COMMIT_READER_ID, reader_id, len, MODE_MAC, MODE_MAC,
                            resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    if (enc_prev_reader_id != NULL && out_len != NULL) {
        if (resp_len > cap) {
            return NXPSC_E_LENGTH;
        }
        memcpy(enc_prev_reader_id, resp, resp_len);
        *out_len = resp_len;
    }
    return NXPSC_OK;
}

//-----------------------------------------------------------------------------
// ISO 7816-4 level access
//-----------------------------------------------------------------------------
int nxpsc_iso_select_df_name(nxpsc_card_t *card, const uint8_t *df_name, size_t len) {
    if (card == NULL || df_name == NULL || len == 0 || len > 16) {
        return NXPSC_E_PARAM;
    }

    uint16_t sw = 0;
    uint8_t resp[64] = {0};
    size_t resp_len = 0;

    return nxpsc_iso_exchange(card, 0x00, ISO_INS_SELECT, 0x04, 0x0C, df_name, len,
                              false, 0, resp, sizeof(resp), &resp_len, &sw);
}

int nxpsc_iso_select_fid(nxpsc_card_t *card, uint16_t fid, bool is_ef) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t data[2] = {(uint8_t)((fid >> 8) & 0xFF), (uint8_t)(fid & 0xFF)};
    uint16_t sw = 0;
    uint8_t resp[64] = {0};
    size_t resp_len = 0;

    return nxpsc_iso_exchange(card, 0x00, ISO_INS_SELECT, is_ef ? 0x02 : 0x01, 0x0C,
                              data, sizeof(data), false, 0, resp, sizeof(resp), &resp_len, &sw);
}

int nxpsc_iso_read_binary(nxpsc_card_t *card, uint8_t sfi, uint16_t offset, size_t length,
                          uint8_t *out, size_t cap, size_t *out_len) {
    if (card == NULL || out == NULL || out_len == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t p1;
    uint8_t p2;

    if (sfi != 0) {
        // short file id addressing, offset is limited to one byte
        if (offset > 0xFF) {
            return NXPSC_E_PARAM;
        }
        p1 = (uint8_t)(0x80 | (sfi & 0x1F));
        p2 = (uint8_t)(offset & 0xFF);
    } else {
        p1 = (uint8_t)((offset >> 8) & 0x7F);
        p2 = (uint8_t)(offset & 0xFF);
    }

    uint16_t sw = 0;
    return nxpsc_iso_exchange(card, 0x00, ISO_INS_READ_BINARY, p1, p2, NULL, 0,
                              true, length, out, cap, out_len, &sw);
}

int nxpsc_iso_update_binary(nxpsc_card_t *card, uint8_t sfi, uint16_t offset,
                            const uint8_t *data, size_t len) {
    if (card == NULL || data == NULL || len == 0) {
        return NXPSC_E_PARAM;
    }

    uint8_t p1;
    uint8_t p2;

    if (sfi != 0) {
        if (offset > 0xFF) {
            return NXPSC_E_PARAM;
        }
        p1 = (uint8_t)(0x80 | (sfi & 0x1F));
        p2 = (uint8_t)(offset & 0xFF);
    } else {
        p1 = (uint8_t)((offset >> 8) & 0x7F);
        p2 = (uint8_t)(offset & 0xFF);
    }

    uint16_t sw = 0;
    uint8_t resp[16] = {0};
    size_t resp_len = 0;

    return nxpsc_iso_exchange(card, 0x00, ISO_INS_UPDATE_BINARY, p1, p2, data, len,
                              false, 0, resp, sizeof(resp), &resp_len, &sw);
}
