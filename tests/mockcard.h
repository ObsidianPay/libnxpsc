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
#define MOCK_MAX_APPS       8
#define MOCK_MAX_APP_KEYS   14
#define MOCK_MAX_RECORDS    8
#define MOCK_RECORD_SIZE    64
#define MOCK_FILE_DATA      256

// a file as the mock remembers it: its settings as they were created, and its
// contents as they were written. Everything the mock answers about a file comes
// from here, so a caller that reads back what it wrote gets what it wrote
typedef struct {
    uint8_t file_no;
    uint8_t type;               // nxpsc_filetype_t
    uint8_t comm;               // nxpsc_commmode_t
    uint16_t access;            // packed access rights, as on the wire
    uint32_t size;              // data files
    uint32_t record_size;       // record files
    uint32_t max_records;

    // data files: what was written, zero where nothing has been. A backup file
    // stages its writes until CommitTransaction, as on a real card
    uint8_t data[MOCK_FILE_DATA];
    uint8_t pending_data[MOCK_FILE_DATA];
    bool has_pending_data;

    // record files: oldest first, cyclic once full. A record written during a
    // transaction is pending until CommitTransaction, as on a real card
    uint8_t records[MOCK_MAX_RECORDS][MOCK_RECORD_SIZE];
    size_t record_count;
    uint8_t pending_record[MOCK_RECORD_SIZE];
    size_t pending_len;
    bool has_pending_record;

    // value files: the committed value, and the pending one during a transaction
    int32_t value;
    int32_t pending_value;
    bool has_pending_value;

    // set when a write arrived enciphered: the mock does not decipher command
    // data, so it no longer knows what the file holds. Reads then fail rather
    // than answer with something that looks like data
    bool contents_unknown;
} mock_file_t;

// an application as the mock remembers it, from CreateApplication
typedef struct {
    bool present;
    uint32_t aid;
    uint8_t key_settings;
    uint8_t num_keys;
    uint8_t key_type;           // nxpsc_keytype_t
    uint16_t iso_fid;
    uint8_t df_name[16];
    size_t df_name_len;
    // the version of each key. A changed key's version rides inside the
    // cryptogram, which the mock cannot read, so it takes the one the caller
    // stated through mock_card_t::change_key_version
    uint8_t key_version[MOCK_MAX_APP_KEYS];
} mock_app_t;

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

    // applications the mock has seen created, and the version a changed key
    // takes (ChangeKey carries it enciphered, so the caller states it)
    mock_app_t apps[MOCK_MAX_APPS];
    size_t app_count;
    uint8_t change_key_version;

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
