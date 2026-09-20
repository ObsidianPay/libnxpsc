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
// libnxpsc - mock card used by the protocol tests. it answers GetVersion with
// the identification bytes of a chosen card family and records what the
// library transmitted, so the tests can assert on the framing
//-----------------------------------------------------------------------------

#include "mockcard.h"
#include "nxpsc_internal.h"
#include "nxpsc_crypto.h"

#include <stdlib.h>
#include <string.h>

// the proximity check key the mock answers with, the tests use the same one
const uint8_t mock_pc_key[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

typedef struct {
    nxpsc_cardtype_t type;
    uint8_t hw_type;
    uint8_t hw_major;
    uint8_t hw_minor;
    uint8_t sw_major;
    uint8_t sw_minor;
    uint8_t storage;
} family_t;

static const family_t families[] = {
    {DESFIRE_MF3ICD40, 0x01, 0x00, 0x02, 0x00, 0x02, 0x18},
    {DESFIRE_EV1,      0x01, 0x01, 0x00, 0x00, 0x01, 0x18},
    {DESFIRE_EV2,      0x01, 0x12, 0x00, 0x02, 0x00, 0x18},
    {DESFIRE_EV2_XL,   0x01, 0x22, 0x00, 0x02, 0x01, 0x1A},
    {DESFIRE_EV3,      0x01, 0x33, 0x00, 0x03, 0x00, 0x18},
    {DESFIRE_LIGHT,    0x08, 0x30, 0x00, 0x03, 0x01, 0x13},
    {PLUS_EV1,         0x02, 0x11, 0x00, 0x01, 0x00, 0x18},
    {PLUS_EV2,         0x02, 0x22, 0x00, 0x02, 0x00, 0x18},
    {NTAG413DNA,       0x04, 0x10, 0x00, 0x01, 0x00, 0x0F},
    {NTAG424,          0x04, 0x30, 0x00, 0x03, 0x00, 0x11},
    {DUOX,             0x01, 0xA0, 0x00, 0x0A, 0x00, 0x1A},
};

size_t mock_family_count(void) {
    return sizeof(families) / sizeof(families[0]);
}

nxpsc_cardtype_t mock_family_type(size_t index) {
    return families[index].type;
}

static const family_t *find_family(nxpsc_cardtype_t type) {
    for (size_t i = 0; i < mock_family_count(); i++) {
        if (families[i].type == type) {
            return &families[i];
        }
    }
    return &families[1];
}

void mock_init(mock_card_t *mock, nxpsc_cardtype_t type) {
    memset(mock, 0, sizeof(*mock));
    mock->type = type;

    static const uint8_t uid[7] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(mock->uid, uid, sizeof(uid));
    memcpy(mock->auth_ti, "\xDE\xAD\xBE\xEF", sizeof(mock->auth_ti));
}

static void mock_secure_ctx(const mock_card_t *mock, nxpsc_card_t *card) {
    memset(card, 0, sizeof(*card));
    card->authenticated = mock->secure_active;
    card->channel = mock->secure_channel;
    card->key_type = mock->secure_key_type;
    memcpy(card->session_enc, mock->secure_session_enc, sizeof(card->session_enc));
    memcpy(card->session_mac, mock->secure_session_mac, sizeof(card->session_mac));
    memcpy(card->iv, mock->secure_iv, sizeof(card->iv));
    memcpy(card->ti, mock->secure_ti, sizeof(card->ti));
    card->cmd_ctr = mock->secure_cmd_ctr;
}

// the PICC throws the secure messaging session away as soon as it answers an
// in session command with an error, everything after that is unauthenticated
static void mock_secure_abort(mock_card_t *mock) {
    mock->secure_active = false;
    mock->secure_channel = NXPSC_CHAN_AUTO;
    mock->secure_cmd_ctr = 0;
    memset(mock->secure_session_enc, 0, sizeof(mock->secure_session_enc));
    memset(mock->secure_session_mac, 0, sizeof(mock->secure_session_mac));
    memset(mock->secure_iv, 0, sizeof(mock->secure_iv));
    memset(mock->secure_ti, 0, sizeof(mock->secure_ti));
}

// the PICC derives the session key on its own. a 2TDEA key whose two halves
// are equal is a DES key to the silicon, which is the rule the library has to
// mirror and the only place a wrong derivation ever shows up
static void mock_secure_establish_legacy(mock_card_t *mock, const uint8_t *rnd_a) {
    uint8_t session[NXPSC_MAX_KEY_SIZE] = {0};
    nxpsc_keytype_t type = mock->auth_key_type;

    if (type == NXPSC_KEY_2K3DES && nxpsc_memeq(mock->auth_key, mock->auth_key + 8, 8)) {
        nxpsc_session_key_d40(rnd_a, mock->auth_rnd_b, NXPSC_KEY_DES, session);
        memcpy(session + 8, session, 8);
    } else {
        nxpsc_session_key_d40(rnd_a, mock->auth_rnd_b, type, session);
    }

    mock->secure_active = true;
    mock->secure_key_no = mock->auth_key_no;
    mock->secure_channel = (mock->auth_cmd == DF_AUTHENTICATE) ? NXPSC_CHAN_D40 : NXPSC_CHAN_EV1;
    mock->secure_key_type = type;
    memcpy(mock->secure_session_enc, session, nxpsc_key_size(type));
    memcpy(mock->secure_session_mac, session, nxpsc_key_size(type));
    memset(mock->secure_iv, 0, sizeof(mock->secure_iv));
    mock->secure_cmd_ctr = 0;
}

static void mock_secure_establish_ev2(mock_card_t *mock, const uint8_t *rnd_a) {
    mock->secure_active = true;
    mock->secure_key_no = mock->auth_key_no;
    mock->secure_channel = NXPSC_CHAN_EV2;
    mock->secure_key_type = NXPSC_KEY_AES128;
    nxpsc_session_key_ev2(mock->auth_key, rnd_a, mock->auth_rnd_b, true, mock->secure_session_enc);
    nxpsc_session_key_ev2(mock->auth_key, rnd_a, mock->auth_rnd_b, false, mock->secure_session_mac);
    memset(mock->secure_iv, 0, sizeof(mock->secure_iv));
    if (mock->auth_first) {
        memcpy(mock->secure_ti, mock->auth_ti, sizeof(mock->secure_ti));
        mock->secure_cmd_ctr = 0;
    }
}

static void mock_secure_advance(mock_card_t *mock) {
    if (mock->secure_active &&
            (mock->secure_channel == NXPSC_CHAN_EV2 || mock->secure_channel == NXPSC_CHAN_LRP)) {
        mock->secure_cmd_ctr++;
    }
}

//-----------------------------------------------------------------------------
// files
//
// The mock keeps what it saw created so that GetFileIDs and GetFileSettings
// answer the truth rather than a fixture. Create commands carry their settings
// in the clear; CreateTransactionMACFile does not, because it carries a key, so
// that one file is stated through mock_card_t like the key itself.
//-----------------------------------------------------------------------------
static uint32_t mock_u24(const uint8_t *p);

// How long the data of a write is, given the length its header declares. A
// command MAC may follow the data (EV2 always, the legacy channel in MAC mode)
// or not (EV1 chains its CMAC without sending it), so rather than keeping a
// rule per channel the frame is measured against what the header claims.
// Returns false when neither fits, which means the data was enciphered.
static bool mock_write_payload(const mock_card_t *mock, const uint8_t *tx, size_t tx_len,
                               size_t header, size_t *data_len) {
    if (tx_len < 1 + header) {
        return false;
    }
    size_t declared = mock_u24(tx + 1 + header - 3);
    size_t present = tx_len - 1 - header;
    if (present == declared) {
        *data_len = declared;
        return true;
    }

    nxpsc_card_t ctx;
    mock_secure_ctx(mock, &ctx);
    size_t mac_len = mock->secure_active ? nxpsc_mac_length(&ctx) : 0;
    if (mac_len > 0 && present >= mac_len && present - mac_len == declared) {
        *data_len = declared;
        return true;
    }
    return false;
}

static mock_file_t *mock_find_file(mock_card_t *mock, uint8_t file_no) {
    for (size_t i = 0; i < mock->file_count; i++) {
        if (mock->files[i].file_no == file_no) {
            return &mock->files[i];
        }
    }
    return NULL;
}

static mock_file_t *mock_add_file(mock_card_t *mock, uint8_t file_no) {
    mock_file_t *file = mock_find_file(mock, file_no);
    if (file != NULL) {
        return file;
    }
    if (mock->file_count >= MOCK_MAX_FILES) {
        return NULL;
    }
    file = &mock->files[mock->file_count++];
    memset(file, 0, sizeof(*file));
    file->file_no = file_no;
    return file;
}

static uint32_t mock_u24(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

// CreateStdDataFile and friends: FileNo || [ISO FID] || CommMode || AccessRights
// || the type's own fields. The ISO file id is present when bit 5 of the file
// option byte was set at creation, which the library only does when asked
static void mock_note_file(mock_card_t *mock, uint8_t cmd, const uint8_t *data, size_t len) {
    static const size_t header = 1 + 1 + 2;     // file, comm, rights
    if (len < header) {
        return;
    }

    uint8_t type;
    size_t need = header;
    switch (cmd) {
        case 0xCD: type = 0x00; need += 3; break;       // standard data
        case 0xCB: type = 0x01; need += 3; break;       // backup data
        case 0xCC: type = 0x02; need += 13; break;      // value
        case 0xC1: type = 0x03; need += 6; break;       // linear record
        case 0xC0: type = 0x04; need += 6; break;       // cyclic record
        default: return;
    }
    if (len < need) {
        return;
    }

    mock_file_t *file = mock_add_file(mock, data[0]);
    if (file == NULL) {
        return;
    }
    file->type = type;
    file->comm = (data[1] == 0x03) ? NXPSC_COMM_FULL
               : (data[1] == 0x01) ? NXPSC_COMM_MAC : NXPSC_COMM_PLAIN;
    file->access = (uint16_t)((uint16_t)data[2] | ((uint16_t)data[3] << 8));
    if (type == 0x00 || type == 0x01) {
        file->size = mock_u24(data + header);
    }
    else if (type == 0x02) {
        // lower limit (4) || upper limit (4) || initial value (4) || limited credit
        file->value = (int32_t)((uint32_t)data[header + 8] | ((uint32_t)data[header + 9] << 8)
                                | ((uint32_t)data[header + 10] << 16) | ((uint32_t)data[header + 11] << 24));
    }
    else if (type == 0x03 || type == 0x04) {
        file->record_size = mock_u24(data + header);
        file->max_records = mock_u24(data + header + 3);
    }
}

// A record written during a transaction is pending until CommitTransaction
// applies it, and AbortTransaction throws it away. The file is cyclic: once it
// holds max_records, the oldest goes
static void mock_commit_files(mock_card_t *mock) {
    for (size_t i = 0; i < mock->file_count; i++) {
        mock_file_t *file = &mock->files[i];

        if (file->has_pending_record) {
            size_t cap = (file->max_records > MOCK_MAX_RECORDS) ? MOCK_MAX_RECORDS : file->max_records;
            if (cap == 0) {
                cap = 1;
            }
            if (file->record_count == cap) {
                memmove(file->records[0], file->records[1], (cap - 1) * MOCK_RECORD_SIZE);
                file->record_count--;
            }
            memcpy(file->records[file->record_count], file->pending_record, MOCK_RECORD_SIZE);
            file->record_count++;
            file->has_pending_record = false;
        }

        if (file->has_pending_value) {
            file->value = file->pending_value;
            file->has_pending_value = false;
        }

        if (file->has_pending_data) {
            memcpy(file->data, file->pending_data, MOCK_FILE_DATA);
            file->has_pending_data = false;
        }
    }
}

static void mock_abort_files(mock_card_t *mock) {
    for (size_t i = 0; i < mock->file_count; i++) {
        mock->files[i].has_pending_record = false;
        mock->files[i].has_pending_value = false;
        mock->files[i].has_pending_data = false;
    }
}

// where a data file's writes land: a standard file takes them at once, a backup
// file stages them for CommitTransaction
static uint8_t *mock_write_target(mock_file_t *file) {
    if (file->type != 0x01) {
        return file->data;
    }
    if (file->has_pending_data == false) {
        memcpy(file->pending_data, file->data, MOCK_FILE_DATA);
        file->has_pending_data = true;
    }
    return file->pending_data;
}

// the answer to GetFileSettings, in the wire layout the library decodes
static size_t mock_file_settings(const mock_file_t *file, uint8_t *out) {
    size_t len = 0;
    out[len++] = file->type;
    out[len++] = (file->comm == NXPSC_COMM_FULL) ? 0x03
               : (file->comm == NXPSC_COMM_MAC) ? 0x01 : 0x00;
    out[len++] = (uint8_t)(file->access & 0xFF);
    out[len++] = (uint8_t)(file->access >> 8);

    if (file->type == 0x03 || file->type == 0x04) {
        out[len++] = (uint8_t)(file->record_size & 0xFF);
        out[len++] = (uint8_t)((file->record_size >> 8) & 0xFF);
        out[len++] = (uint8_t)((file->record_size >> 16) & 0xFF);
        out[len++] = (uint8_t)(file->max_records & 0xFF);
        out[len++] = (uint8_t)((file->max_records >> 8) & 0xFF);
        out[len++] = (uint8_t)((file->max_records >> 16) & 0xFF);
        // current records: the mock does not keep record contents, so a freshly
        // created file reports none
        out[len++] = 0x00;
        out[len++] = 0x00;
        out[len++] = 0x00;
    }
    else if (file->type == 0x05) {
        // a transaction MAC file reports nothing beyond its rights
    }
    else {
        out[len++] = (uint8_t)(file->size & 0xFF);
        out[len++] = (uint8_t)((file->size >> 8) & 0xFF);
        out[len++] = (uint8_t)((file->size >> 16) & 0xFF);
    }
    return len;
}

//-----------------------------------------------------------------------------
// transaction MAC, the card's side
//
// Written from the MF2DL(H)x0 data sheet rev 3.3 section 10.3 on its own, so
// that a test comparing it with nxpsc_tmac_compute compares two readings of the
// data sheet rather than one function with itself. Only the AES-CMAC primitive
// is shared, and that has its own known answer vectors in test_crypto.
//-----------------------------------------------------------------------------

// TMI || Cmd || FileNo || Offset || Length || ZeroPadding || Data, the whole
// thing kept on a 16 byte boundary (10.3.4.2, WriteRecord)
static void mock_tmi_write_record(mock_card_t *mock, const uint8_t *header,
                                  const uint8_t *data, size_t data_len) {
    size_t block = 16 + (data_len + 15) / 16 * 16;
    if (mock->tmi_len + block > sizeof(mock->tmi)) {
        return;
    }

    uint8_t *at = mock->tmi + mock->tmi_len;
    memset(at, 0, block);
    at[0] = DF_WRITE_RECORD;
    memcpy(at + 1, header, 7);          // FileNo || Offset (3) || Length (3)
    memcpy(at + 16, data, data_len);    // the eight bytes before it stay zero
    mock->tmi_len += block;
}

// SesTMMACKey = CMAC(AppTransactionMACKey, 5Ah||00h||01h||00h||80h||(TMC+1)||UID)
// TMV = the odd bytes of CMAC(SesTMMACKey, TMI)                    (10.3.2.3-4)
static int mock_tmac_value(const mock_card_t *mock, uint32_t tmc, uint8_t tmv[8]) {
    uint8_t sv1[16] = {0};
    sv1[0] = 0x5A;
    sv1[1] = 0x00;
    sv1[2] = 0x01;
    sv1[3] = 0x00;
    sv1[4] = 0x80;
    sv1[5] = (uint8_t)(tmc & 0xFF);             // TMC is LSB first
    sv1[6] = (uint8_t)((tmc >> 8) & 0xFF);
    sv1[7] = (uint8_t)((tmc >> 16) & 0xFF);
    sv1[8] = (uint8_t)((tmc >> 24) & 0xFF);
    memcpy(sv1 + 9, mock->uid, 7);

    uint8_t session[16] = {0};
    if (nxpsc_cmac(NXPSC_KEY_AES128, mock->tm_key, NULL, sv1, sizeof(sv1), 0, session)
            != NXPSC_OK) {
        return NXPSC_E_CRYPTO;
    }

    uint8_t full[16] = {0};
    if (nxpsc_cmac(NXPSC_KEY_AES128, session, NULL, mock->tmi, mock->tmi_len, 0, full)
            != NXPSC_OK) {
        return NXPSC_E_CRYPTO;
    }

    for (int i = 0; i < 8; i++) {
        tmv[i] = full[i * 2 + 1];
    }
    return NXPSC_OK;
}

static int mock_secure_reply(mock_card_t *mock, uint8_t cmd, nxpsc_commmode_t comm,
                             const uint8_t *payload, size_t payload_len, uint8_t status,
                             bool d40_ev1_style, uint8_t *rx, size_t cap, size_t *rx_len) {
    (void)cmd;

    nxpsc_card_t ctx;
    mock_secure_ctx(mock, &ctx);
    size_t bs = nxpsc_block_size(ctx.key_type);
    size_t mac_len = nxpsc_mac_length(&ctx);

    if (ctx.channel == NXPSC_CHAN_EV2 || ctx.channel == NXPSC_CHAN_LRP) {
        ctx.cmd_ctr++;
    }

    if (cap < 1) {
        return NXPSC_E_LENGTH;
    }

    rx[0] = status;

    switch (comm) {
        case NXPSC_COMM_PLAIN:
            if (payload_len > cap - 1) {
                return NXPSC_E_LENGTH;
            }
            if (payload_len > 0) {
                memcpy(rx + 1, payload, payload_len);
            }
            *rx_len = payload_len + 1;
            return NXPSC_OK;

        case NXPSC_COMM_MAC:
            if (payload_len + mac_len > cap - 1) {
                return NXPSC_E_LENGTH;
            }
            if (payload_len > 0) {
                memcpy(rx + 1, payload, payload_len);
            }

            if (ctx.channel == NXPSC_CHAN_D40) {
                size_t plen = nxpsc_padded_len(payload_len, bs);
                uint8_t buf[NXPSC_MAX_RESPONSE] = {0};
                uint8_t iv[NXPSC_MAX_BLOCK] = {0};

                if (payload_len > 0) {
                    memcpy(buf, payload, payload_len);
                }
                int rc = nxpsc_cbc_crypt_ex(ctx.key_type, ctx.session_mac, iv, buf, plen, buf,
                                            true, true);
                if (rc != NXPSC_OK) {
                    return rc;
                }
                memcpy(rx + 1 + payload_len, iv, mac_len);
            } else if (ctx.channel == NXPSC_CHAN_EV1) {
                uint8_t *buf = calloc(payload_len + 1, 1);
                if (buf == NULL) {
                    return NXPSC_E_MEMORY;
                }
                if (payload_len > 0) {
                    memcpy(buf, payload, payload_len);
                }
                buf[payload_len] = status;

                uint8_t cmac[NXPSC_MAX_BLOCK] = {0};
                int rc = nxpsc_cmac(ctx.key_type, ctx.session_mac, ctx.iv, buf, payload_len + 1,
                                    0, cmac);
                free(buf);
                if (rc != NXPSC_OK) {
                    return rc;
                }
                // the EV1 chain runs through the answer as well as the command,
                // so the card keeps the IV this MAC left behind
                memcpy(mock->secure_iv, ctx.iv, sizeof(mock->secure_iv));
                memcpy(rx + 1 + payload_len, cmac, mac_len);
            } else {
                uint8_t mac[8] = {0};
                int rc = nxpsc_ev2_cmac(&ctx, 0x00, payload, payload_len, mac);
                if (rc != NXPSC_OK) {
                    return rc;
                }
                memcpy(rx + 1 + payload_len, mac, mac_len);
            }

            *rx_len = 1 + payload_len + mac_len;
            return NXPSC_OK;

        case NXPSC_COMM_FULL:
            break;
    }

    if (ctx.channel == NXPSC_CHAN_D40) {
        size_t crc_len = d40_ev1_style ? 4 : 2;
        size_t plen = nxpsc_padded_len(payload_len + crc_len, bs);
        uint8_t buf[NXPSC_MAX_RESPONSE] = {0};

        if (plen > cap - 1) {
            return NXPSC_E_LENGTH;
        }
        if (payload_len > 0) {
            memcpy(buf, payload, payload_len);
        }

        // the enciphering is the legacy one either way, only the checksum
        // differs. EV1 and later silicon answers GetCardUID with a CRC32 over
        // data || status even while the session is a legacy one
        if (d40_ev1_style) {
            uint8_t crc_input[NXPSC_MAX_RESPONSE + 1] = {0};

            if (payload_len > 0) {
                memcpy(crc_input, payload, payload_len);
            }
            crc_input[payload_len] = status;
            nxpsc_crc32(crc_input, payload_len + 1, buf + payload_len);
        } else {
            nxpsc_crc16(buf, payload_len, buf + payload_len);
        }

        uint8_t iv[NXPSC_MAX_BLOCK] = {0};
        int rc = nxpsc_cbc_crypt_ex(ctx.key_type, ctx.session_enc, iv, buf, plen, rx + 1,
                                    true, true);
        if (rc != NXPSC_OK) {
            return rc;
        }
        *rx_len = 1 + plen;
        return NXPSC_OK;
    }

    if (ctx.channel == NXPSC_CHAN_EV1) {
        size_t plen = nxpsc_padded_len(payload_len + 4, bs);
        uint8_t buf[NXPSC_MAX_RESPONSE] = {0};
        uint8_t crc_input[NXPSC_MAX_RESPONSE + 1] = {0};

        if (plen > cap - 1) {
            return NXPSC_E_LENGTH;
        }
        if (payload_len > 0) {
            memcpy(buf, payload, payload_len);
            memcpy(crc_input, payload, payload_len);
        }
        crc_input[payload_len] = status;
        nxpsc_crc32(crc_input, payload_len + 1, buf + payload_len);

        uint8_t iv[NXPSC_MAX_BLOCK] = {0};
        memcpy(iv, mock->secure_iv, sizeof(iv));
        int rc = nxpsc_cbc_crypt(ctx.key_type, ctx.session_enc, iv, buf, plen, rx + 1, true);
        if (rc != NXPSC_OK) {
            return rc;
        }
        *rx_len = 1 + plen;
        return NXPSC_OK;
    }

    size_t plen = nxpsc_padded_len(payload_len + 1, NXPSC_AES_BLOCK);
    uint8_t buf[NXPSC_MAX_RESPONSE] = {0};
    if (plen + mac_len > cap - 1) {
        return NXPSC_E_LENGTH;
    }
    if (payload_len > 0) {
        memcpy(buf, payload, payload_len);
    }
    buf[payload_len] = 0x80;

    int rc = NXPSC_OK;
    if (ctx.channel == NXPSC_CHAN_LRP) {
        size_t out_len = 0;
        nxpsc_lrp_ctx_t lrp;
        nxpsc_lrp_init(&lrp, ctx.session_enc, 1, false);
        nxpsc_lrp_set_counter(&lrp, ctx.iv, 4 * 2);
        rc = nxpsc_lrp_encode(&lrp, buf, plen, rx + 1, cap - 1, &out_len);
    } else {
        uint8_t iv[NXPSC_AES_BLOCK] = {0};
        nxpsc_ev2_fill_iv(&ctx, false, iv);
        rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, ctx.session_enc, iv, buf, plen, rx + 1, true);
    }
    if (rc != NXPSC_OK) {
        return rc;
    }

    uint8_t mac[8] = {0};
    rc = nxpsc_ev2_cmac(&ctx, 0x00, rx + 1, plen, mac);
    if (rc != NXPSC_OK) {
        return rc;
    }
    memcpy(rx + 1 + plen, mac, mac_len);
    *rx_len = 1 + plen + mac_len;
    return NXPSC_OK;
}

static void mock_update_ev1_request_iv(mock_card_t *mock, uint8_t cmd,
                                       const uint8_t *tx, size_t tx_len) {
    if (mock->secure_active == false || mock->secure_channel != NXPSC_CHAN_EV1 || tx_len < 1) {
        return;
    }

    nxpsc_card_t ctx;
    mock_secure_ctx(mock, &ctx);

    uint8_t *buf = calloc(tx_len, 1);
    if (buf == NULL) {
        return;
    }
    buf[0] = cmd;
    if (tx_len > 1) {
        memcpy(buf + 1, tx + 1, tx_len - 1);
    }

    uint8_t cmac[NXPSC_MAX_BLOCK] = {0};
    if (nxpsc_cmac(ctx.key_type, ctx.session_mac, ctx.iv, buf, tx_len, 0, cmac) == NXPSC_OK) {
        memcpy(mock->secure_iv, ctx.iv, sizeof(mock->secure_iv));
    }
    free(buf);
}

static bool mock_has_valid_ev2_request_mac(mock_card_t *mock, const uint8_t *tx, size_t tx_len) {
    if (mock->secure_active == false || mock->validate_secure_requests == false ||
            (mock->secure_channel != NXPSC_CHAN_EV2 && mock->secure_channel != NXPSC_CHAN_LRP)) {
        return true;
    }

    size_t mac_len = 8;
    if (tx_len < 1 + mac_len) {
        return true;
    }

    nxpsc_card_t ctx;
    mock_secure_ctx(mock, &ctx);

    size_t data_len = tx_len - 1 - mac_len;
    uint8_t mac[8] = {0};
    if (nxpsc_ev2_cmac(&ctx, tx[0], tx + 1, data_len, mac) != NXPSC_OK) {
        return false;
    }
    return nxpsc_memeq(tx + 1 + data_len, mac, mac_len);
}

// GetDFNames answers one application per frame, each AID(3) || ISO fid(2) ||
// DF name, and asks for the next with 0xAF. The name length is only knowable
// from the frame length, so a reader that concatenates the frames first cannot
// tell where one name ends and the next entry begins
// The answer to a command that returns no data. Only the EV2 and LRP channels
// MAC such an answer; on the earlier ones it is a bare status, and building it
// through the secure path would advance a CMAC chain the library never
// advanced for it
static int mock_ack(mock_card_t *mock, uint8_t cmd, uint8_t *rx, size_t cap, size_t *rx_len) {
    if (mock->secure_active && mock->secure_channel != NXPSC_CHAN_D40) {
        int rc = mock_secure_reply(mock, cmd, NXPSC_COMM_MAC, NULL, 0, 0x00, false, rx, cap, rx_len);
        mock_secure_advance(mock);
        return rc;
    }
    if (cap < 1) {
        return NXPSC_E_LENGTH;
    }
    rx[0] = 0x00;
    *rx_len = 1;
    return NXPSC_OK;
}

static int df_names_frame(mock_card_t *mock, uint8_t *rx, size_t cap, size_t *rx_len) {
    static const struct {
        uint8_t aid[3];
        uint8_t fid[2];
        const char *name;
    } entries[2] = {
        {{0x01, 0x02, 0x03}, {0x10, 0xE1}, "first"},
        {{0x11, 0x22, 0x33}, {0x20, 0xE1}, "second.app"},
    };

    if (mock->df_names_step >= 2) {
        if (cap < 1) {
            return NXPSC_E_LENGTH;
        }
        rx[0] = 0x00;
        *rx_len = 1;
        return NXPSC_OK;
    }

    int i = mock->df_names_step++;
    size_t name_len = strlen(entries[i].name);
    if (cap < 6 + name_len) {
        return NXPSC_E_LENGTH;
    }

    rx[0] = (mock->df_names_step < 2) ? 0xAF : 0x00;
    memcpy(rx + 1, entries[i].aid, 3);
    memcpy(rx + 4, entries[i].fid, 2);
    memcpy(rx + 6, entries[i].name, name_len);
    *rx_len = 6 + name_len;
    return NXPSC_OK;
}

// GetVersion answers in three frames, the first two ask for continuation
static int version_frame(const mock_card_t *mock, uint8_t *rx, size_t cap, size_t *rx_len) {
    const family_t *fam = find_family(mock->type);

    if (cap < 9) {
        return NXPSC_E_LENGTH;
    }

    switch (mock->version_step) {
        case 0:
            rx[0] = 0xAF;
            rx[1] = 0x04;               // NXP
            rx[2] = fam->hw_type;
            rx[3] = 0x01;               // subtype
            rx[4] = fam->hw_major;
            rx[5] = fam->hw_minor;
            rx[6] = fam->storage;
            rx[7] = 0x05;               // protocol
            *rx_len = 8;
            return NXPSC_OK;

        case 1:
            rx[0] = 0xAF;
            rx[1] = 0x04;
            rx[2] = fam->hw_type;
            rx[3] = 0x01;
            rx[4] = fam->sw_major;
            rx[5] = fam->sw_minor;
            rx[6] = fam->storage;
            rx[7] = 0x05;
            *rx_len = 8;
            return NXPSC_OK;

        default:
            break;
    }

    if (cap < 15) {
        return NXPSC_E_LENGTH;
    }

    rx[0] = 0x00;
    memcpy(rx + 1, mock->uid, 7);
    memset(rx + 8, 0xAA, 5);            // batch number
    rx[13] = 0x01;                      // production week
    rx[14] = 0x18;                      // production year
    *rx_len = 15;
    return NXPSC_OK;
}

static bool is_plus(const mock_card_t *mock) {
    return (mock->type == PLUS_EV1) || (mock->type == PLUS_EV2);
}

static void rol(uint8_t *data, size_t len) {
    uint8_t first = data[0];
    memmove(data, data + 1, len - 1);
    data[len - 1] = first;
}

static size_t auth_rnd_len(const mock_card_t *mock) {
    switch (mock->auth_key_type) {
        case NXPSC_KEY_3K3DES:
        case NXPSC_KEY_AES128:
        case NXPSC_KEY_AES256:
            return NXPSC_AES_BLOCK;
        case NXPSC_KEY_DES:
        case NXPSC_KEY_2K3DES:
            return NXPSC_DES_BLOCK;
        default:
            break;
    }
    return 0;
}

static void auth_abort(mock_card_t *mock) {
    mock->auth_pending = false;
    mock->auth_first = false;
    mock->auth_cmd = 0;
}

static int auth_length_error(mock_card_t *mock, uint8_t *rx, size_t cap, size_t *rx_len) {
    auth_abort(mock);
    if (cap < 1) {
        return NXPSC_E_LENGTH;
    }
    rx[0] = 0x7E;
    *rx_len = 1;
    return NXPSC_OK;
}

static int auth_begin_legacy(mock_card_t *mock, uint8_t cmd,
                             uint8_t *rx, size_t cap, size_t *rx_len) {
    size_t rnd_len = auth_rnd_len(mock);
    uint8_t iv[NXPSC_MAX_BLOCK] = {0};

    if (rnd_len == 0 || cap < rnd_len + 1) {
        return NXPSC_E_LENGTH;
    }

    rx[0] = 0xAF;
    int rc = nxpsc_cbc_crypt_ex(mock->auth_key_type, mock->auth_key, iv,
                                mock->auth_rnd_b, rnd_len, rx + 1, true, true);
    if (rc != NXPSC_OK) {
        return rc;
    }
    // the ISO handshake chains its IV across the frames, so keep where the
    // RndB it just sent left it
    memcpy(mock->auth_iv, iv, sizeof(mock->auth_iv));

    mock->auth_scheme = MOCK_AUTH_LEGACY;
    mock->auth_pending = true;
    mock->auth_cmd = cmd;
    *rx_len = rnd_len + 1;
    return NXPSC_OK;
}

static int auth_begin_ev2(mock_card_t *mock, bool first, uint8_t *rx, size_t cap, size_t *rx_len) {
    uint8_t iv[NXPSC_AES_BLOCK] = {0};

    if (cap < NXPSC_AES_BLOCK + 1) {
        return NXPSC_E_LENGTH;
    }

    rx[0] = 0xAF;
    int rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, mock->auth_key, iv,
                             mock->auth_rnd_b, NXPSC_AES_BLOCK, rx + 1, true);
    if (rc != NXPSC_OK) {
        return rc;
    }

    mock->auth_pending = true;
    mock->auth_first = first;
    *rx_len = NXPSC_AES_BLOCK + 1;
    return NXPSC_OK;
}

static int auth_begin_lrp(mock_card_t *mock, bool first, uint8_t *rx, size_t cap, size_t *rx_len) {
    (void)first;
    if (cap < NXPSC_AES_BLOCK + 2) {
        return NXPSC_E_LENGTH;
    }

    rx[0] = 0xAF;
    rx[1] = 0x01;
    memcpy(rx + 2, mock->auth_rnd_b, NXPSC_AES_BLOCK);
    mock->auth_pending = true;
    mock->auth_first = first;
    *rx_len = NXPSC_AES_BLOCK + 2;
    return NXPSC_OK;
}

static int auth_continue_legacy(mock_card_t *mock, const uint8_t *tx, size_t tx_len,
                                uint8_t *rx, size_t cap, size_t *rx_len) {
    (void)tx;
    size_t rnd_len = auth_rnd_len(mock);
    uint8_t rnd_a[NXPSC_AES_BLOCK] = {0};
    uint8_t rot_a[NXPSC_AES_BLOCK] = {0};
    uint8_t iv[NXPSC_MAX_BLOCK] = {0};

    if (rnd_len == 0 || tx_len != 1 + (rnd_len * 2) || cap < rnd_len + 1) {
        return auth_length_error(mock, rx, cap, rx_len);
    }

    for (size_t i = 0; i < rnd_len; i++) {
        rnd_a[i] = (uint8_t)(0x10 + i);
    }
    memcpy(rot_a, rnd_a, rnd_len);
    rol(rot_a, rnd_len);

    if (mock->auth_cmd == DF_AUTHENTICATE_ISO || mock->auth_cmd == DF_AUTHENTICATE_AES) {
        // pick the chain up where the RndB frame left it. the legacy 0x0A
        // handshake starts each operation from zero instead
        memcpy(iv, mock->auth_iv, sizeof(iv));

        uint8_t tmp[NXPSC_AES_BLOCK * 2] = {0};
        uint8_t rot_b[NXPSC_AES_BLOCK] = {0};
        memcpy(tmp, rnd_a, rnd_len);
        memcpy(rot_b, mock->auth_rnd_b, rnd_len);
        rol(rot_b, rnd_len);
        memcpy(tmp + rnd_len, rot_b, rnd_len);

        int rc = nxpsc_cbc_crypt_ex(mock->auth_key_type, mock->auth_key, iv,
                                    tmp, rnd_len * 2, tmp, true, true);
        if (rc != NXPSC_OK) {
            return rc;
        }
    }

    rx[0] = 0x00;
    int rc = nxpsc_cbc_crypt_ex(mock->auth_key_type, mock->auth_key, iv,
                                rot_a, rnd_len, rx + 1, true, true);
    if (rc != NXPSC_OK) {
        return rc;
    }

    *rx_len = rnd_len + 1;
    mock_secure_establish_legacy(mock, rnd_a);
    auth_abort(mock);
    return NXPSC_OK;
}

static int auth_continue_ev2(mock_card_t *mock, const uint8_t *tx, size_t tx_len,
                             uint8_t *rx, size_t cap, size_t *rx_len) {
    (void)tx;
    uint8_t rnd_a[NXPSC_AES_BLOCK] = {0};
    uint8_t plain[NXPSC_AES_BLOCK * 2] = {0};
    uint8_t iv[NXPSC_AES_BLOCK] = {0};
    size_t plain_len = mock->auth_first ? (NXPSC_AES_BLOCK * 2) : NXPSC_AES_BLOCK;

    if (tx_len != NXPSC_AES_BLOCK * 2 + 1 || cap < plain_len + 1) {
        return auth_length_error(mock, rx, cap, rx_len);
    }

    for (size_t i = 0; i < sizeof(rnd_a); i++) {
        rnd_a[i] = (uint8_t)(0x10 + i);
    }

    if (mock->auth_first) {
        memcpy(plain, mock->auth_ti, sizeof(mock->auth_ti));
        memcpy(plain + 4, rnd_a + 1, NXPSC_AES_BLOCK - 1);
        plain[19] = rnd_a[0];
    } else {
        memcpy(plain, rnd_a + 1, NXPSC_AES_BLOCK - 1);
        plain[15] = rnd_a[0];
    }

    rx[0] = 0x00;
    int rc = nxpsc_cbc_crypt(NXPSC_KEY_AES128, mock->auth_key, iv,
                             plain, plain_len, rx + 1, true);
    if (rc != NXPSC_OK) {
        return rc;
    }

    *rx_len = plain_len + 1;
    mock_secure_establish_ev2(mock, rnd_a);
    auth_abort(mock);
    return NXPSC_OK;
}

static int auth_continue_lrp(mock_card_t *mock, const uint8_t *tx, size_t tx_len,
                             uint8_t *rx, size_t cap, size_t *rx_len) {
    (void)tx;
    uint8_t rnd_a[NXPSC_AES_BLOCK] = {0};
    uint8_t session[NXPSC_AES_BLOCK] = {0};
    uint8_t input[NXPSC_AES_BLOCK * 3] = {0};
    uint8_t cmac[NXPSC_AES_BLOCK] = {0};
    uint8_t ti_block[NXPSC_AES_BLOCK] = {0};
    nxpsc_lrp_ctx_t lrp;
    size_t total = mock->auth_first ? (NXPSC_AES_BLOCK * 2) : NXPSC_AES_BLOCK;

    if (tx_len != NXPSC_AES_BLOCK * 2 + 1 || cap < total + 1) {
        return auth_length_error(mock, rx, cap, rx_len);
    }

    for (size_t i = 0; i < sizeof(rnd_a); i++) {
        rnd_a[i] = (uint8_t)(0x10 + i);
    }

    int rc = nxpsc_session_key_lrp(mock->auth_key, rnd_a, mock->auth_rnd_b, false, session);
    if (rc != NXPSC_OK) {
        return rc;
    }

    memcpy(input, mock->auth_rnd_b, NXPSC_AES_BLOCK);
    memcpy(input + NXPSC_AES_BLOCK, rnd_a, NXPSC_AES_BLOCK);
    if (mock->auth_first) {
        memcpy(ti_block, mock->auth_ti, sizeof(mock->auth_ti));
        memcpy(input + (NXPSC_AES_BLOCK * 2), ti_block, NXPSC_AES_BLOCK);
    }

    nxpsc_lrp_init(&lrp, session, 0, true);
    nxpsc_lrp_cmac(&lrp, input, mock->auth_first ? (NXPSC_AES_BLOCK * 3) : (NXPSC_AES_BLOCK * 2), cmac);

    rx[0] = 0x00;
    if (mock->auth_first) {
        memcpy(rx + 1, ti_block, NXPSC_AES_BLOCK);
        memcpy(rx + 1 + NXPSC_AES_BLOCK, cmac, NXPSC_AES_BLOCK);
    } else {
        memcpy(rx + 1, cmac, NXPSC_AES_BLOCK);
    }

    *rx_len = total + 1;
    auth_abort(mock);
    return NXPSC_OK;
}

static int auth_continue(mock_card_t *mock, const uint8_t *tx, size_t tx_len,
                         uint8_t *rx, size_t cap, size_t *rx_len) {
    if (tx_len <= 1) {
        return auth_length_error(mock, rx, cap, rx_len);
    }

    switch (mock->auth_scheme) {
        case MOCK_AUTH_LEGACY:
            return auth_continue_legacy(mock, tx, tx_len, rx, cap, rx_len);
        case MOCK_AUTH_EV2:
            return auth_continue_ev2(mock, tx, tx_len, rx, cap, rx_len);
        case MOCK_AUTH_LRP:
            return auth_continue_lrp(mock, tx, tx_len, rx, cap, rx_len);
        case MOCK_AUTH_NONE:
        default:
            break;
    }
    return auth_length_error(mock, rx, cap, rx_len);
}

// MIFARE Plus answers 0x90 on success, the SL3 opcodes overlap with the
// DESFire ones so the family decides which handler runs
static int plus_frame(mock_card_t *mock, const uint8_t *tx, size_t tx_len,
                      uint8_t *rx, size_t cap, size_t *rx_len) {
    (void)tx_len;

    switch (tx[0]) {
        case 0x70:                      // AuthenticateFirst
        case 0x76: {                    // AuthenticateNonFirst
            if (cap < 17) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x90;
            memset(rx + 1, 0x5A, 16);   // enciphered RndB, the tests do not verify it
            *rx_len = 17;
            return NXPSC_OK;
        }

        default:
            break;
    }

    if (cap < 1) {
        return NXPSC_E_LENGTH;
    }

    mock->plus_last_op = tx[0];
    rx[0] = 0x90;
    *rx_len = 1;
    return NXPSC_OK;
}

static int native_frame(mock_card_t *mock, const uint8_t *tx, size_t tx_len,
                        uint8_t *rx, size_t cap, size_t *rx_len);

static int iso_status(uint8_t sw2, uint8_t *rx, size_t cap, size_t *rx_len) {
    if (cap < 2) {
        return NXPSC_E_LENGTH;
    }
    rx[0] = 0x91;
    rx[1] = sw2;
    *rx_len = 2;
    return NXPSC_OK;
}

static int unwrap_wrapped_native(const uint8_t *tx, size_t tx_len,
                                 uint8_t *inner, size_t cap, size_t *inner_len) {
    if (tx_len < 5 || cap < 1) {
        return NXPSC_E_PARAM;
    }

    inner[0] = tx[1];
    if (tx_len == 5) {
        *inner_len = 1;
        return NXPSC_OK;
    }

    size_t lc = tx[4];
    if (lc == 0 || tx_len != 6 + lc || lc > cap - 1) {
        return NXPSC_E_LENGTH;
    }

    memcpy(inner + 1, tx + 5, lc);
    *inner_len = 1 + lc;
    return NXPSC_OK;
}

int mock_transceive(void *ctx, const uint8_t *tx, size_t tx_len,
                    uint8_t *rx, size_t cap, size_t *rx_len) {
    mock_card_t *mock = (mock_card_t *)ctx;

    if (tx_len == 0 || cap < 1) {
        return NXPSC_E_PARAM;
    }

    if (mock->tx_count < MOCK_MAX_FRAMES) {
        size_t n = (tx_len > MOCK_FRAME_SIZE) ? MOCK_FRAME_SIZE : tx_len;
        memcpy(mock->tx[mock->tx_count], tx, n);
        mock->tx_len[mock->tx_count] = n;
    }
    mock->tx_count++;

    return native_frame(mock, tx, tx_len, rx, cap, rx_len);
}

#define MOCK_TX_FRAME_MAX   54

static int native_frame(mock_card_t *mock, const uint8_t *tx, size_t tx_len,
                        uint8_t *rx, size_t cap, size_t *rx_len) {
    // a full frame means the library is chaining, ask for the next one
    if (mock->in_version == false && tx_len == MOCK_TX_FRAME_MAX + 1) {
        // the mock does not reassemble a chained write, so it stops claiming to
        // know what the file holds rather than keeping a half written copy
        if (tx[0] == DF_WRITE_DATA || tx[0] == DF_WRITE_RECORD || tx[0] == DF_UPDATE_RECORD) {
            mock_file_t *file = mock_find_file(mock, tx[1]);
            if (file != NULL) {
                file->contents_unknown = true;
            }
        }
        rx[0] = 0xAF;
        *rx_len = 1;
        return NXPSC_OK;
    }

    if (is_plus(mock) && tx[0] != 0x60 && tx[0] != 0xAF && tx[0] != 0x00) {
        return plus_frame(mock, tx, tx_len, rx, cap, rx_len);
    }

    if (mock_has_valid_ev2_request_mac(mock, tx, tx_len) == false) {
        int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0x1E, false,
                                   rx, cap, rx_len);
        mock_secure_abort(mock);
        return rc;
    }

    mock_update_ev1_request_iv(mock, tx[0], tx, tx_len);

    // ISO 7816-4 wrapped frame, answer with a plain 0x9000
    if (tx[0] == 0x00 || tx[0] == 0x90) {
        if (tx[0] == 0x90 && tx_len >= 2) {
            // wrapped native command, unwrap and fall through
            uint8_t inner[64] = {0};
            size_t inner_len = 0;
            int rc = unwrap_wrapped_native(tx, tx_len, inner, sizeof(inner), &inner_len);
            if (rc != NXPSC_OK) {
                return iso_status(0x7E, rx, cap, rx_len);
            }

            uint8_t native[MOCK_FRAME_SIZE] = {0};
            size_t native_len = 0;
            rc = native_frame(mock, inner, inner_len, native, sizeof(native), &native_len);
            if (rc != NXPSC_OK || native_len < 1) {
                return rc;
            }
            if (cap < native_len + 1) {
                return NXPSC_E_LENGTH;
            }

            memcpy(rx, native + 1, native_len - 1);
            rx[native_len - 1] = 0x91;
            rx[native_len] = native[0];
            *rx_len = native_len + 1;
            return NXPSC_OK;
        }

        // a real ISO 7816-4 command. SELECT and UPDATE BINARY only answer a
        // status word, READ BINARY answers Le bytes before it
        if (tx[0] == 0x00 && tx_len >= 4 && tx[1] == ISO_INS_READ_BINARY) {
            size_t want = (tx_len >= 5) ? tx[tx_len - 1] : 0;
            if (want == 0) {
                want = 256;
            }
            if (cap < want + 2) {
                return NXPSC_E_LENGTH;
            }
            for (size_t i = 0; i < want; i++) {
                rx[i] = (uint8_t)(0x50 + i);
            }
            rx[want] = 0x90;
            rx[want + 1] = 0x00;
            *rx_len = want + 2;
            return NXPSC_OK;
        }

        if (cap < 2) {
            return NXPSC_E_LENGTH;
        }
        rx[0] = 0x90;
        rx[1] = 0x00;
        *rx_len = 2;
        return NXPSC_OK;
    }

    switch (tx[0]) {
        case 0x60:                      // GetVersion
            mock->version_step = 0;
            mock->in_version = true;
            return version_frame(mock, rx, cap, rx_len);

        case 0xAF:                      // additional frame
            if (mock->auth_pending) {
                return auth_continue(mock, tx, tx_len, rx, cap, rx_len);
            }
            if (mock->df_names_step > 0 && mock->df_names_step < 2) {
                return df_names_frame(mock, rx, cap, rx_len);
            }
            if (mock->in_version == false) {
                // continuation of a long command, just acknowledge it
                rx[0] = 0x00;
                *rx_len = 1;
                return NXPSC_OK;
            }
            mock->version_step++;
            if (mock->version_step >= 2) {
                mock->in_version = false;
            }
            return version_frame(mock, rx, cap, rx_len);

        case 0x0A:
        case 0x1A:
        case 0xAA:
            mock->auth_key_no = (tx_len > 1) ? (uint8_t)(tx[1] & 0x3F) : 0;
            return auth_begin_legacy(mock, tx[0], rx, cap, rx_len);

        case 0x71:
        case 0x77:
            mock->auth_key_no = (tx_len > 1) ? (uint8_t)(tx[1] & 0x3F) : 0;
            if (mock->auth_scheme == MOCK_AUTH_LRP) {
                return auth_begin_lrp(mock, tx_len > 2, rx, cap, rx_len);
            }
            mock->auth_scheme = MOCK_AUTH_EV2;
            return auth_begin_ev2(mock, tx_len > 2, rx, cap, rx_len);

        case 0x5A:                      // SelectApplication
            if (tx_len >= 4) {
                mock->selected_aid = (uint32_t)tx[1] | ((uint32_t)tx[2] << 8) |
                                     ((uint32_t)tx[3] << 16);
            }
            rx[0] = 0x00;
            *rx_len = 1;
            return NXPSC_OK;

        case 0x6A:                      // GetApplicationIDs
            if (cap < 7) {
                return NXPSC_E_LENGTH;
            }
            if (mock->secure_active && tx_len >= 9 &&
                    (mock->secure_channel == NXPSC_CHAN_EV2 || mock->secure_channel == NXPSC_CHAN_LRP)) {
                uint8_t payload[6] = {0x01, 0x02, 0x03, 0x11, 0x22, 0x33};
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_MAC, payload, sizeof(payload),
                                           0x00, false, rx, cap, rx_len);
                mock_secure_advance(mock);
                return rc;
            }
            rx[0] = 0x00;
            rx[1] = 0x01;
            rx[2] = 0x02;
            rx[3] = 0x03;
            rx[4] = 0x11;
            rx[5] = 0x22;
            rx[6] = 0x33;
            *rx_len = 7;
            return NXPSC_OK;

        case 0x61:                      // GetISOFileIDs, two byte ids little endian
            if (cap < 5) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            rx[1] = 0x10; rx[2] = 0xE1;     // 0xE110
            rx[3] = 0x11; rx[4] = 0xE1;     // 0xE111
            *rx_len = 5;
            return NXPSC_OK;

        case 0x6D:                      // GetDFNames
            // the card answers one application per frame and asks for another
            // with 0xAF, so the entries arrive with their boundaries intact
            mock->df_names_step = 0;
            return df_names_frame(mock, rx, cap, rx_len);

        case 0x45:                      // GetKeySettings
            if (cap < 3) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            rx[1] = 0x0F;                   // settings
            rx[2] = 0x83;                   // 3 keys, AES
            *rx_len = 3;
            return NXPSC_OK;

        case 0x64:                      // GetKeyVersion
            if (cap < 2) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            rx[1] = 0x42;
            *rx_len = 2;
            return NXPSC_OK;

        case 0x3C:                      // Read_Sig
            if (cap < 57) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            for (size_t i = 0; i < 56; i++) {
                rx[1 + i] = (uint8_t)(0xA0 + i);
            }
            *rx_len = 57;
            return NXPSC_OK;

        case 0xBB: {                    // ReadRecords, oldest first
            // FileNo || RecNo (3) || RecCount (3), the count 0 meaning all of
            // them from RecNo on
            const mock_file_t *file = (tx_len >= 8) ? mock_find_file(mock, tx[1]) : NULL;
            if (file != NULL && file->contents_unknown) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0x9D, false,
                                           rx, cap, rx_len);
                mock_secure_abort(mock);
                return rc;
            }
            if (file == NULL || (file->type != 0x03 && file->type != 0x04)) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0xF0, false,
                                           rx, cap, rx_len);
                mock_secure_abort(mock);
                return rc;
            }

            uint32_t first = mock_u24(tx + 2);
            uint32_t want = mock_u24(tx + 5);
            if (want == 0) {
                want = (first < file->record_count) ? (uint32_t)file->record_count - first : 0;
            }
            if (first + want > file->record_count) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0xBE, false,
                                           rx, cap, rx_len);       // BOUNDARY_ERROR
                mock_secure_abort(mock);
                return rc;
            }

            size_t size = (file->record_size > MOCK_RECORD_SIZE) ? MOCK_RECORD_SIZE : file->record_size;
            uint8_t payload[MOCK_MAX_RECORDS * MOCK_RECORD_SIZE] = {0};
            size_t payload_len = 0;
            // record 0 is the most recent, so walk back from the newest
            for (uint32_t r = 0; r < want; r++) {
                size_t index = file->record_count - 1 - first - r;
                memcpy(payload + payload_len, file->records[index], size);
                payload_len += size;
            }

            if (mock->secure_active) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_MAC, payload, payload_len, 0x00,
                                           false, rx, cap, rx_len);
                mock_secure_advance(mock);
                return rc;
            }
            if (cap < payload_len + 1) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            memcpy(rx + 1, payload, payload_len);
            *rx_len = payload_len + 1;
            return NXPSC_OK;
        }

        case 0xC8: {                    // CommitReaderID, returns the previous one
            uint8_t prev[16];
            for (size_t i = 0; i < sizeof(prev); i++) {
                prev[i] = (uint8_t)(0xC0 + i);
            }
            if (mock->secure_active) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_MAC, prev, sizeof(prev),
                                           0x00, false, rx, cap, rx_len);
                mock_secure_advance(mock);
                return rc;
            }
            if (cap < 17) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            memcpy(rx + 1, prev, sizeof(prev));
            *rx_len = 17;
            return NXPSC_OK;
        }

        case 0xC0:                      // CreateCyclicRecordFile
        case 0xC1:                      // CreateLinearRecordFile
        case 0xCB:                      // CreateBackupDataFile
        case 0xCC:                      // CreateValueFile
        case 0xCD: {                    // CreateStdDataFile
            // the settings travel in the clear, so the mock can remember them
            size_t len = tx_len - 1;
            if (mock->secure_active && len >= 8) {
                len -= 8;
            }
            mock_note_file(mock, tx[0], tx + 1, len);
            return mock_ack(mock, tx[0], rx, cap, rx_len);
        }

        case 0xDF: {                    // DeleteFile
            uint8_t file_no = (tx_len > 1) ? tx[1] : 0;
            for (size_t i = 0; i < mock->file_count; i++) {
                if (mock->files[i].file_no == file_no) {
                    mock->files[i] = mock->files[mock->file_count - 1];
                    mock->file_count--;
                    break;
                }
            }
            break;                      // the acknowledgement follows below
        }

        case 0x6F: {                    // GetFileIDs, the files the mock holds
            uint8_t ids[MOCK_MAX_FILES] = {0};
            size_t count = mock->file_count;
            for (size_t i = 0; i < count; i++) {
                ids[i] = mock->files[i].file_no;
            }
            if (mock->secure_active) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_MAC, ids, count,
                                           0x00, false, rx, cap, rx_len);
                mock_secure_advance(mock);
                return rc;
            }
            if (cap < count + 1) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            memcpy(rx + 1, ids, count);
            *rx_len = count + 1;
            return NXPSC_OK;
        }

        case 0xF5: {                    // GetFileSettings
            uint8_t file_no = (tx_len > 1) ? tx[1] : 0;
            const mock_file_t *file = mock_find_file(mock, file_no);
            if (file == NULL) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0xF0, false,
                                           rx, cap, rx_len);       // FILE_NOT_FOUND
                mock_secure_abort(mock);
                return rc;
            }

            uint8_t payload[24] = {0};
            size_t payload_len = mock_file_settings(file, payload);
            if (mock->secure_active) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_MAC, payload, payload_len,
                                           0x00, false, rx, cap, rx_len);
                mock_secure_advance(mock);
                return rc;
            }
            if (cap < payload_len + 1) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            memcpy(rx + 1, payload, payload_len);
            *rx_len = payload_len + 1;
            return NXPSC_OK;
        }

        case 0x6C: {                    // GetValue
            const mock_file_t *file = (tx_len >= 2) ? mock_find_file(mock, tx[1]) : NULL;
            if (file == NULL || file->type != 0x02) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0xF0, false,
                                           rx, cap, rx_len);
                mock_secure_abort(mock);
                return rc;
            }

            // the committed value: a credit or debit in flight is not visible
            // until CommitTransaction
            uint8_t payload[4];
            payload[0] = (uint8_t)(file->value & 0xFF);
            payload[1] = (uint8_t)((file->value >> 8) & 0xFF);
            payload[2] = (uint8_t)((file->value >> 16) & 0xFF);
            payload[3] = (uint8_t)((file->value >> 24) & 0xFF);

            if (mock->secure_active) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_MAC, payload, sizeof(payload),
                                           0x00, false, rx, cap, rx_len);
                mock_secure_advance(mock);
                return rc;
            }
            if (cap < sizeof(payload) + 1) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            memcpy(rx + 1, payload, sizeof(payload));
            *rx_len = sizeof(payload) + 1;
            return NXPSC_OK;
        }

        case 0x0C:                      // Credit
        case 0xDC:                      // Debit
        case 0x1C: {                    // LimitedCredit
            size_t len = tx_len - 1;
            if (mock->secure_active && len >= 8) {
                len -= 8;
            }
            mock_file_t *file = (len >= 5) ? mock_find_file(mock, tx[1]) : NULL;
            if (file == NULL || file->type != 0x02) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0xF0, false,
                                           rx, cap, rx_len);
                mock_secure_abort(mock);
                return rc;
            }

            int32_t delta = (int32_t)((uint32_t)tx[2] | ((uint32_t)tx[3] << 8)
                                      | ((uint32_t)tx[4] << 16) | ((uint32_t)tx[5] << 24));
            if (file->has_pending_value == false) {
                file->pending_value = file->value;
                file->has_pending_value = true;
            }
            file->pending_value += (tx[0] == 0xDC) ? -delta : delta;

            return mock_ack(mock, tx[0], rx, cap, rx_len);
        }

        case 0xBD: {                    // ReadData
            // FileNo || Offset (3) || Length (3), the length 0 meaning the rest
            // of the file
            const mock_file_t *file = (tx_len >= 8) ? mock_find_file(mock, tx[1]) : NULL;
            if (file != NULL && file->contents_unknown) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0x9D, false,
                                           rx, cap, rx_len);
                mock_secure_abort(mock);
                return rc;
            }
            if (file == NULL || file->type == 0x02 || file->type == 0x03 || file->type == 0x04) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0xF0, false,
                                           rx, cap, rx_len);
                mock_secure_abort(mock);
                return rc;
            }

            uint32_t offset = mock_u24(tx + 2);
            uint32_t length = mock_u24(tx + 5);
            uint32_t size = (file->size > MOCK_FILE_DATA) ? MOCK_FILE_DATA : file->size;
            if (length == 0) {
                length = (offset < size) ? size - offset : 0;
            }
            // mock_card_t::read_len shortens the answer, for the chaining tests
            if (mock->read_len > 0 && mock->read_len < length) {
                length = (uint32_t)mock->read_len;
            }
            if (offset + length > size) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0xBE, false,
                                           rx, cap, rx_len);
                mock_secure_abort(mock);
                return rc;
            }

            if (mock->secure_active && mock->read_comm != NXPSC_COMM_PLAIN) {
                int rc = mock_secure_reply(mock, tx[0], mock->read_comm, file->data + offset,
                                           length, 0x00, false, rx, cap, rx_len);
                mock_secure_advance(mock);
                return rc;
            }
            if (cap < length + 1) {
                return NXPSC_E_LENGTH;
            }

            rx[0] = 0x00;
            memcpy(rx + 1, file->data + offset, length);
            *rx_len = length + 1;
            return NXPSC_OK;
        }

        case 0x6E:                      // GetFreeMemory
            if (cap < 4) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            rx[1] = 0x00;
            rx[2] = 0x08;
            rx[3] = 0x00;
            *rx_len = 4;
            return NXPSC_OK;

        case 0x69:                      // GetDelegatedInfo
            if (cap < 9) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            rx[1] = 0x05;               // DAM slot version
            rx[2] = 0x10;               // quota limit
            rx[3] = 0x00;
            rx[4] = 0x20;               // free blocks
            rx[5] = 0x00;
            rx[6] = 0x11;               // AID
            rx[7] = 0x22;
            rx[8] = 0x33;
            *rx_len = 9;
            return NXPSC_OK;

        case 0xF0:                      // PreparePC
            if (cap < 5) {
                return NXPSC_E_LENGTH;
            }
            // what an EV3 answers: Option, a two byte published response time
            // and, because bit 0 of Option is set, a PPS1 byte
            rx[0] = 0x00;
            rx[1] = 0x01;               // Option
            rx[2] = 0x03;               // published response time, high
            rx[3] = 0x20;               // published response time, low
            rx[4] = 0x0A;               // PPS1
            *rx_len = 5;
            mock->pc_len = 0;
            return NXPSC_OK;

        case 0xF2: {                    // ProximityCheck, echo the challenge back
            size_t part = (tx_len >= 2) ? tx[1] : 0;
            if (part == 0 || part > tx_len - 2 || cap < part + 1) {
                return NXPSC_E_LENGTH;
            }

            rx[0] = 0x00;
            for (size_t i = 0; i < part; i++) {
                // the card answer, arbitrary but deterministic
                rx[1 + i] = (uint8_t)(tx[2 + i] ^ 0xFF);
                if (mock->pc_len + 2 <= sizeof(mock->pc_exchanged)) {
                    mock->pc_exchanged[mock->pc_len++] = rx[1 + i];
                }
            }
            for (size_t i = 0; i < part; i++) {
                if (mock->pc_len < sizeof(mock->pc_exchanged)) {
                    mock->pc_exchanged[mock->pc_len++] = tx[2 + i];
                }
            }
            *rx_len = part + 1;
            return NXPSC_OK;
        }

        case 0xFD: {                    // VerifyPC, answer with the response MAC
            uint8_t input[1 + 4 + 16] = {0x90, 0x01, 0x03, 0x20, 0x0A};
            size_t input_len = 5;

            memcpy(input + input_len, mock->pc_exchanged, mock->pc_len);
            input_len += mock->pc_len;

            uint8_t full[16] = {0};
            if (nxpsc_cmac(NXPSC_KEY_AES128, mock_pc_key, NULL, input, input_len, 0, full)
                    != NXPSC_OK) {
                return NXPSC_E_CRYPTO;
            }
            if (cap < 9) {
                return NXPSC_E_LENGTH;
            }

            rx[0] = mock->pc_bad_mac ? 0x00 : 0x00;
            for (int i = 0; i < 8; i++) {
                rx[1 + i] = full[i * 2 + 1];
            }
            if (mock->pc_bad_mac) {
                rx[1] ^= 0xFF;
            }
            *rx_len = 9;
            return NXPSC_OK;
        }

        case DF_CREATE_TRANS_MAC_FILE: {    // the key inside is enciphered, see mockcard.h
            mock->tm_file = true;
            mock->tmc = 0;
            mock->tmi_len = 0;
            {
                mock_file_t *file = mock_add_file(mock, (mock->tm_file_no == 0) ? 0x02 : mock->tm_file_no);
                if (file != NULL) {
                    file->type = 0x05;
                    file->comm = mock->tm_file_comm;
                    file->access = mock->tm_file_access;
                }
            }
            return mock_ack(mock, tx[0], rx, cap, rx_len);
        }

        case DF_WRITE_RECORD: {
            // FileNo || Offset (3) || Length (3) || Data, and the command MAC
            // after it in MAC mode
            size_t data_len = 0;
            bool plain = mock_write_payload(mock, tx, tx_len, 7, &data_len);

            if (mock->tm_file && plain && data_len > 0) {
                mock_tmi_write_record(mock, tx + 1, tx + 8, data_len);
            }

            // the record itself, pending until the transaction is committed
            mock_file_t *file = mock_find_file(mock, tx[1]);
            if (file != NULL && data_len > 0) {
                if (plain == false) {
                    file->contents_unknown = true;
                }
                else {
                    size_t stored = (data_len > MOCK_RECORD_SIZE) ? MOCK_RECORD_SIZE : data_len;
                    memset(file->pending_record, 0, MOCK_RECORD_SIZE);
                    memcpy(file->pending_record, tx + 8, stored);
                    file->pending_len = stored;
                    file->has_pending_record = true;
                }
            }
            return mock_ack(mock, tx[0], rx, cap, rx_len);
        }

        case 0x3D: {                    // WriteData
            // FileNo || Offset (3) || Length (3) || Data, and a command MAC
            // after it in MAC mode
            size_t data_len = 0;
            bool plain = mock_write_payload(mock, tx, tx_len, 7, &data_len);
            mock_file_t *file = (tx_len > 8) ? mock_find_file(mock, tx[1]) : NULL;
            if (file == NULL) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0xF0, false,
                                           rx, cap, rx_len);
                mock_secure_abort(mock);
                return rc;
            }

            uint32_t offset = mock_u24(tx + 2);
            if (plain == false) {
                // enciphered, so the mock cannot see what was written
                file->contents_unknown = true;
                if (mock->secure_active) {
                    int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_MAC, NULL, 0, 0x00, false,
                                               rx, cap, rx_len);
                    mock_secure_advance(mock);
                    return rc;
                }
                rx[0] = 0x00;
                *rx_len = 1;
                return NXPSC_OK;
            }
            if (offset + data_len > MOCK_FILE_DATA) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0xBE, false,
                                           rx, cap, rx_len);       // BOUNDARY_ERROR
                mock_secure_abort(mock);
                return rc;
            }
            memcpy(mock_write_target(file) + offset, tx + 8, data_len);

            return mock_ack(mock, tx[0], rx, cap, rx_len);
        }

        case 0xA7:                      // AbortTransaction
            mock_abort_files(mock);
            mock->tmi_len = 0;          // the transaction MAC calculation restarts
            break;                      // the acknowledgement follows below

        case DF_COMMIT_TRANSACTION: {
            // with option 0x01 the card answers TMC || TMV, and only an
            // application holding a transaction MAC file can
            size_t len = tx_len - 1;
            if (mock->secure_active && len >= 8) {
                len -= 8;
            }
            bool wants_tmac = (len >= 1) && (tx[1] == 0x01);
            if (wants_tmac == false) {
                mock_commit_files(mock);
                break;                  // plain CommitTransaction, bare ack below
            }
            if (mock->tm_file == false || mock->tmi_len == 0) {
                // the data sheet says only that the command is rejected; the
                // status here is the mock's choice, not a card observation
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, 0x9D, false,
                                           rx, cap, rx_len);
                mock_secure_abort(mock);
                return rc;
            }

            uint32_t tmc = mock->tmc + 1;   // the counter used for the session key
            uint8_t payload[12] = {0};
            payload[0] = (uint8_t)(tmc & 0xFF);
            payload[1] = (uint8_t)((tmc >> 8) & 0xFF);
            payload[2] = (uint8_t)((tmc >> 16) & 0xFF);
            payload[3] = (uint8_t)((tmc >> 24) & 0xFF);
            if (mock_tmac_value(mock, tmc, payload + 4) != NXPSC_OK) {
                return NXPSC_E_CRYPTO;
            }

            mock->tmc = tmc;
            mock->tmi_len = 0;          // a new transaction starts here
            mock_commit_files(mock);

            if (mock->secure_active) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_MAC, payload, sizeof(payload),
                                           0x00, false, rx, cap, rx_len);
                mock_secure_advance(mock);
                return rc;
            }
            if (cap < sizeof(payload) + 1) {
                return NXPSC_E_LENGTH;
            }
            rx[0] = 0x00;
            memcpy(rx + 1, payload, sizeof(payload));
            *rx_len = sizeof(payload) + 1;
            return NXPSC_OK;
        }

        case 0x51:                      // GetCardUID, only valid authenticated
            if (mock->secure_active) {
                int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_FULL, mock->uid,
                                           sizeof(mock->uid), 0x00, mock->d40_ev1_style_uid,
                                           rx, cap, rx_len);
                mock_secure_advance(mock);
                return rc;
            }
            rx[0] = 0xAE;
            *rx_len = 1;
            return NXPSC_OK;

        default:
            break;
    }

    // ChangeKey and RollKeySet take the key the running session was built on
    // out from under it, so the card answers those without a MAC and the
    // session is gone afterwards. a MACed answer here would let the library go
    // back to demanding one without any test noticing
    if (mock->secure_active && (tx[0] == DF_CHANGE_KEY || tx[0] == DF_CHANGE_KEY_EV2
                                || tx[0] == DF_ROLL_KEY_SETTINGS)) {
        bool ends_session = (tx[0] == DF_ROLL_KEY_SETTINGS);
        if (tx[0] == DF_CHANGE_KEY && tx_len >= 2) {
            ends_session = ((tx[1] & 0x3F) == mock->secure_key_no);
        }
        else if (tx[0] == DF_CHANGE_KEY_EV2 && tx_len >= 3) {
            // key set 0 is the active one, so changing the session key there
            // ends the session. any other set leaves it alone
            ends_session = (tx[1] == 0x00) && ((tx[2] & 0x3F) == mock->secure_key_no);
        }

        // the legacy channel only MACs the answers to ReadData, ReadRecords and
        // GetValue, so a ChangeKey there comes back as a bare status
        nxpsc_commmode_t comm = (ends_session || mock->secure_channel == NXPSC_CHAN_D40)
                                ? NXPSC_COMM_PLAIN : NXPSC_COMM_MAC;
        int rc = mock_secure_reply(mock, tx[0], comm, NULL, 0, 0x00, false,
                                   rx, cap, rx_len);
        if (ends_session) {
            mock_secure_abort(mock);
        }
        else {
            mock_secure_advance(mock);
        }
        return rc;
    }

    if (mock->secure_active && mock->reject_cmd == tx[0]) {
        int rc = mock_secure_reply(mock, tx[0], NXPSC_COMM_PLAIN, NULL, 0, mock->reject_status,
                                   false, rx, cap, rx_len);
        mock->reject_cmd = 0;
        mock_secure_abort(mock);
        return rc;
    }

    // everything else acknowledges without data
    rx[0] = 0x00;
    *rx_len = 1;
    return NXPSC_OK;
}

int mock_get_uid(void *ctx, uint8_t *uid, size_t cap, size_t *len) {
    mock_card_t *mock = (mock_card_t *)ctx;

    if (cap < sizeof(mock->uid)) {
        return NXPSC_E_LENGTH;
    }
    memcpy(uid, mock->uid, sizeof(mock->uid));
    *len = sizeof(mock->uid);
    return NXPSC_OK;
}

void mock_transport(mock_card_t *mock, nxpsc_transport_t *transport) {
    memset(transport, 0, sizeof(*transport));
    transport->ctx = mock;
    transport->transceive = mock_transceive;
    transport->get_uid = mock_get_uid;
}
