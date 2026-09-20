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
// libnxpsc - mock card transport for the protocol tests
//-----------------------------------------------------------------------------

#ifndef NXPSC_MOCKCARD_H__
#define NXPSC_MOCKCARD_H__

#include "nxpsc/nxpsc.h"
#include "nxpsc_crypto.h"

#define MOCK_MAX_FRAMES     32
#define MOCK_FRAME_SIZE     128
#define MOCK_TMI_SIZE       256
#define MOCK_MAX_FILES      8

// a file as the mock remembers it, enough to answer GetFileIDs and
// GetFileSettings with what was actually asked for
typedef struct {
    uint8_t file_no;
    uint8_t type;               // nxpsc_filetype_t
    uint8_t comm;               // nxpsc_commmode_t
    uint16_t access;            // packed access rights, as on the wire
    uint32_t size;              // data files
    uint32_t record_size;       // record files
    uint32_t max_records;
} mock_file_t;

typedef enum {
    MOCK_AUTH_NONE = 0,
    MOCK_AUTH_LEGACY,
    MOCK_AUTH_EV2,
    MOCK_AUTH_LRP,
} mock_auth_scheme_t;

typedef struct {
    nxpsc_cardtype_t type;
    uint8_t uid[7];
    bool secure_active;
    nxpsc_channel_t secure_channel;
    nxpsc_keytype_t secure_key_type;
    uint8_t secure_session_enc[NXPSC_MAX_KEY_SIZE];
    uint8_t secure_session_mac[NXPSC_MAX_KEY_SIZE];
    uint8_t secure_iv[NXPSC_MAX_BLOCK];
    uint8_t secure_ti[4];
    uint16_t secure_cmd_ctr;
    uint8_t secure_key_no;       // the key the session was built on
    bool validate_secure_requests;
    nxpsc_commmode_t read_comm;
    size_t read_len;
    uint32_t selected_aid;
    int version_step;
    int df_names_step;           // GetDFNames answers one entry per frame
    bool in_version;
    uint8_t plus_last_op;
    uint8_t reject_cmd;
    uint8_t reject_status;
    bool d40_ev1_style_uid;
    mock_auth_scheme_t auth_scheme;
    bool auth_pending;
    bool auth_first;
    uint8_t auth_cmd;
    uint8_t auth_key_no;        // key number the handshake in flight is for
    nxpsc_keytype_t auth_key_type;
    uint8_t auth_key[NXPSC_MAX_KEY_SIZE];
    uint8_t auth_rnd_b[NXPSC_AES_BLOCK];
    uint8_t auth_iv[NXPSC_MAX_BLOCK];   // carried across the ISO handshake frames
    uint8_t auth_ti[4];

    uint8_t pc_exchanged[32];   // interleaved proximity check challenge and answer
    size_t pc_len;
    bool pc_bad_mac;            // make the card answer with a wrong MAC

    // transaction MAC. the AppTransactionMACKey reaches a real card enciphered
    // inside CreateTransactionMACFile; the mock does not decipher command data,
    // so the test states the key here and the mock only notes that the file
    // exists. tmc counts committed transactions, tmi is what the card
    // accumulated during the ongoing one
    bool tm_file;
    uint8_t tm_key[16];
    uint32_t tmc;
    uint8_t tmi[MOCK_TMI_SIZE];
    size_t tmi_len;

    // CreateTransactionMACFile travels enciphered, so its file number and
    // settings are stated here too, the same way the key is. Everything else
    // the mock knows about a file it read off the wire
    uint8_t tm_file_no;             // 0 means 0x02
    uint8_t tm_file_comm;           // nxpsc_commmode_t
    uint16_t tm_file_access;        // packed, as on the wire

    // files the mock has seen created, in creation order. While none exist the
    // canned answers stay, so the tests that predate this keep their fixtures
    mock_file_t files[MOCK_MAX_FILES];
    size_t file_count;

    uint8_t tx[MOCK_MAX_FRAMES][MOCK_FRAME_SIZE];
    size_t tx_len[MOCK_MAX_FRAMES];
    size_t tx_count;
} mock_card_t;

extern const uint8_t mock_pc_key[16];

size_t mock_family_count(void);
nxpsc_cardtype_t mock_family_type(size_t index);

void mock_init(mock_card_t *mock, nxpsc_cardtype_t type);
void mock_transport(mock_card_t *mock, nxpsc_transport_t *transport);

int mock_transceive(void *ctx, const uint8_t *tx, size_t tx_len,
                    uint8_t *rx, size_t cap, size_t *rx_len);
int mock_get_uid(void *ctx, uint8_t *uid, size_t cap, size_t *len);

#endif // NXPSC_MOCKCARD_H__
