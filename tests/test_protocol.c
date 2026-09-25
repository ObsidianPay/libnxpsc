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
// libnxpsc - protocol level tests. every supported card family is exercised
// against the mock card so the CI can tell which family regressed
//-----------------------------------------------------------------------------

#include "mockcard.h"
#include "nxpsc_crypto.h"
#include "nxpsc_internal.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(const char *name, bool ok) {
    printf("%-44s %s\n", name, ok ? "ok" : "FAIL");
    if (ok == false) {
        failures++;
    }
}

typedef struct {
    uint8_t key[16];
    uint8_t rnd_b[16];
    uint8_t ti[4];
    bool corrupt_final;
} plus_auth_ctx_t;

static int fixed_rng(void *ctx, uint8_t *out, size_t len) {
    (void)ctx;
    for (size_t i = 0; i < len; i++) {
        out[i] = (uint8_t)(0x10 + i);
    }
    return NXPSC_OK;
}

static bool setup_secure_session(mock_card_t *mock, nxpsc_card_t **card_out, nxpsc_cardtype_t type,
                                 nxpsc_channel_t channel, nxpsc_keytype_t key_type,
                                 const uint8_t *session_enc, const uint8_t *session_mac,
                                 const uint8_t *iv, const uint8_t *ti, uint16_t cmd_ctr) {
    nxpsc_transport_t transport;
    size_t key_len = nxpsc_key_size(key_type);

    mock_init(mock, type);
    mock_transport(mock, &transport);

    if (nxpsc_open(&transport, card_out) != NXPSC_OK) {
        return false;
    }

    mock->secure_active = true;
    mock->secure_channel = channel;
    mock->secure_key_type = key_type;
    memcpy(mock->secure_session_enc, session_enc, key_len);
    memcpy(mock->secure_session_mac, session_mac, key_len);
    memcpy(mock->secure_iv, iv, sizeof(mock->secure_iv));
    memcpy(mock->secure_ti, ti, sizeof(mock->secure_ti));
    mock->secure_cmd_ctr = cmd_ctr;

    (*card_out)->authenticated = true;
    (*card_out)->channel = channel;
    (*card_out)->key_type = key_type;
    (*card_out)->type = type;
    memcpy((*card_out)->session_enc, session_enc, key_len);
    memcpy((*card_out)->session_mac, session_mac, key_len);
    memcpy((*card_out)->iv, iv, sizeof((*card_out)->iv));
    memcpy((*card_out)->ti, ti, sizeof((*card_out)->ti));
    (*card_out)->cmd_ctr = cmd_ctr;
    return true;
}

static bool run_exact_buffer_read_case(nxpsc_cardtype_t type, nxpsc_channel_t channel,
                                       nxpsc_keytype_t key_type, nxpsc_commmode_t comm) {
    static const uint8_t session_enc[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    static const uint8_t session_mac[16] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
    };
    static const uint8_t iv[16] = {0};
    static const uint8_t ti[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    mock_card_t mock;
    nxpsc_card_t *card = NULL;
    bool ok = setup_secure_session(&mock, &card, type, channel, key_type,
                                   session_enc, session_mac, iv, ti, 0);
    if (ok == false) {
        return false;
    }

    mock.read_comm = comm;
    mock.validate_secure_requests = (channel == NXPSC_CHAN_EV2);

    uint8_t buf[64] = {0};
    size_t len = 0;

    // the card answers with what is in the file, and this case is about the
    // size of that answer, so the file is given its contents directly rather
    // than through a write in the channel under test
    mock.files[0].file_no = 0x01;
    mock.files[0].type = 0x00;
    mock.files[0].comm = comm;
    mock.files[0].size = sizeof(buf);
    for (size_t i = 0; i < sizeof(buf); i++) {
        mock.files[0].data[i] = (uint8_t)i;
    }
    mock.file_count = 1;
    ok = ok && (nxpsc_read_data(card, 0x01, 0, 64, comm, buf, sizeof(buf), &len) == NXPSC_OK);
    ok = ok && (len == sizeof(buf));
    for (size_t i = 0; ok && i < sizeof(buf); i++) {
        ok = ok && (buf[i] == (uint8_t)i);
    }

    nxpsc_close(card);
    return ok;
}

static void setup_mock_auth(mock_card_t *mock, mock_auth_scheme_t scheme,
                            const nxpsc_key_t *key, const uint8_t *rnd_b) {
    size_t key_len = nxpsc_key_size(key->type);
    size_t rnd_len = nxpsc_block_size(key->type);

    mock->auth_scheme = scheme;
    mock->auth_key_type = key->type;
    memcpy(mock->auth_key, key->data, key_len);
    memset(mock->auth_rnd_b, 0, sizeof(mock->auth_rnd_b));
    memcpy(mock->auth_rnd_b, rnd_b, rnd_len);
}

static bool auth_frame_has_payload(const mock_card_t *mock, size_t index) {
    if (index >= mock->tx_count) {
        return false;
    }
    return mock->tx_len[index] > 5 &&
           mock->tx[index][0] == 0x90 &&
           mock->tx[index][1] == 0xAF &&
           mock->tx[index][4] > 0;
}

static bool run_desfire_auth_case(nxpsc_cardtype_t type, nxpsc_channel_t channel,
                                  mock_auth_scheme_t scheme, const nxpsc_key_t *key,
                                  const uint8_t *rnd_b, uint8_t first_cmd,
                                  bool include_nonfirst) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, type);
    setup_mock_auth(&mock, scheme, key, rnd_b);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok) {
        nxpsc_set_cmdset(card, NXPSC_CMDSET_NATIVE_ISO);
    }

    ok = ok && (nxpsc_authenticate(card, 0x00, key, channel) == NXPSC_OK);
    ok = ok && nxpsc_is_authenticated(card);
    ok = ok && (mock.tx_count == 2);
    ok = ok && (mock.tx[0][0] == 0x90) && (mock.tx[0][1] == first_cmd);
    ok = ok && auth_frame_has_payload(&mock, 1);

    if (ok && include_nonfirst) {
        mock.tx_count = 0;
        setup_mock_auth(&mock, scheme, key, rnd_b);
        ok = ok && (nxpsc_authenticate_nonfirst(card, 0x01, key) == NXPSC_OK);
        ok = ok && nxpsc_is_authenticated(card);
        ok = ok && (mock.tx_count == 2);
        ok = ok && (mock.tx[0][0] == 0x90) && (mock.tx[0][1] == 0x77);
        ok = ok && auth_frame_has_payload(&mock, 1);
    }

    nxpsc_close(card);
    return ok;
}

static int plus_auth_transceive(void *ctx, const uint8_t *tx, size_t tx_len,
                                uint8_t *rx, size_t cap, size_t *rx_len) {
    plus_auth_ctx_t *auth = (plus_auth_ctx_t *)ctx;

    if (tx_len == 0 || cap < 1) {
        return NXPSC_E_PARAM;
    }

    if (tx[0] == 0x70) {
        if (cap < 17) {
            return NXPSC_E_LENGTH;
        }

        uint8_t iv[16] = {0};
        rx[0] = 0x90;
        if (nxpsc_cbc_crypt(NXPSC_KEY_AES128, auth->key, iv, auth->rnd_b, 16, rx + 1, true) != NXPSC_OK) {
            return NXPSC_E_CRYPTO;
        }
        *rx_len = 17;
        return NXPSC_OK;
    }

    if (tx[0] == 0xAF) {
        if (tx_len != 33 || cap < 33) {
            return NXPSC_E_LENGTH;
        }

        uint8_t iv[16] = {0};
        uint8_t plain[32] = {0};
        if (nxpsc_cbc_crypt(NXPSC_KEY_AES128, auth->key, iv, tx + 1, 32, plain, false) != NXPSC_OK) {
            return NXPSC_E_CRYPTO;
        }

        uint8_t expect_rot_b[16] = {0};
        memcpy(expect_rot_b, auth->rnd_b + 1, 15);
        expect_rot_b[15] = auth->rnd_b[0];
        if (memcmp(plain + 16, expect_rot_b, 16) != 0) {
            return NXPSC_E_AUTH;
        }

        uint8_t reply[32] = {0};
        memcpy(reply, auth->ti, sizeof(auth->ti));
        memcpy(reply + 4, plain + 1, 15);
        reply[19] = plain[0];

        memset(iv, 0, sizeof(iv));
        rx[0] = 0x90;
        if (nxpsc_cbc_crypt(NXPSC_KEY_AES128, auth->key, iv, reply, 32, rx + 1, true) != NXPSC_OK) {
            return NXPSC_E_CRYPTO;
        }
        if (auth->corrupt_final) {
            rx[1] ^= 0x80;
        }
        *rx_len = 33;
        return NXPSC_OK;
    }

    return NXPSC_E_PARAM;
}

typedef struct {
    uint8_t payload[16];
    size_t payload_len;
} plus_read_ctx_t;

static int plus_read_transceive(void *ctx, const uint8_t *tx, size_t tx_len,
                                uint8_t *rx, size_t cap, size_t *rx_len) {
    plus_read_ctx_t *read = (plus_read_ctx_t *)ctx;
    (void)tx;
    (void)tx_len;

    if (cap < read->payload_len + 1) {
        return NXPSC_E_LENGTH;
    }

    rx[0] = 0x90;
    memcpy(rx + 1, read->payload, read->payload_len);
    *rx_len = read->payload_len + 1;
    return NXPSC_OK;
}

// identification must work for every card family the library claims to support
static void test_identify(void) {
    for (size_t i = 0; i < mock_family_count(); i++) {
        nxpsc_cardtype_t want = mock_family_type(i);

        mock_card_t mock;
        nxpsc_transport_t transport;
        nxpsc_card_t *card = NULL;

        mock_init(&mock, want);
        mock_transport(&mock, &transport);

        bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

        nxpsc_cardtype_t got = NXP_UNKNOWN;
        ok = ok && (nxpsc_identify(card, &got) == NXPSC_OK);
        ok = ok && (got == want);
        // GetVersion is three frames, 0x60 followed by two 0xAF
        ok = ok && (mock.tx_count == 3);
        ok = ok && (mock.tx[0][0] == 0x60);
        ok = ok && (mock.tx[1][0] == 0xAF);

        char name[64];
        snprintf(name, sizeof(name), "identify %s", nxpsc_cardtype_str(want));
        check(name, ok);

        nxpsc_close(card);
    }
}

static void test_version_fields(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;
    nxpsc_version_t version;

    mock_init(&mock, DESFIRE_EV3);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_get_version(card, &version) == NXPSC_OK);
    ok = ok && (version.hw_vendor == 0x04);
    ok = ok && (version.hw_type == 0x01);
    ok = ok && (version.hw_major == 0x33);
    ok = ok && (version.sw_type == 0x01);
    ok = ok && (version.sw_major == 0x03);
    ok = ok && (version.sw_minor == 0x00);
    ok = ok && (version.uid[0] == 0x04);
    ok = ok && (version.year == 0x18);

    check("GetVersion decoding", ok);
    nxpsc_close(card);
}

static void test_native_framing(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV1);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_select_application(card, 0x030201) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1);
    ok = ok && (mock.tx_len[0] == 4);
    ok = ok && (mock.tx[0][0] == 0x5A);
    // the AID travels little endian
    ok = ok && (mock.tx[0][1] == 0x01) && (mock.tx[0][2] == 0x02) && (mock.tx[0][3] == 0x03);
    ok = ok && (nxpsc_selected_aid(card) == 0x030201);

    check("native SelectApplication framing", ok);
    nxpsc_close(card);
}

static void test_iso_wrapping(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV1);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    nxpsc_set_cmdset(card, NXPSC_CMDSET_NATIVE_ISO);

    ok = ok && (nxpsc_select_application(card, 0x030201) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1);
    // CLA 0x90, INS is the native command, P1 P2 zero, Lc, data, Le
    ok = ok && (mock.tx[0][0] == 0x90);
    ok = ok && (mock.tx[0][1] == 0x5A);
    ok = ok && (mock.tx[0][2] == 0x00) && (mock.tx[0][3] == 0x00);
    ok = ok && (mock.tx[0][4] == 0x03);
    ok = ok && (mock.tx_len[0] == 9);
    ok = ok && (mock.tx[0][8] == 0x00);

    check("ISO wrapped native framing", ok);
    nxpsc_close(card);
}

static void test_iso_wrapping_zero_data(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;
    nxpsc_version_t version;

    mock_init(&mock, DESFIRE_EV1);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    nxpsc_set_cmdset(card, NXPSC_CMDSET_NATIVE_ISO);

    ok = ok && (nxpsc_get_version(card, &version) == NXPSC_OK);
    ok = ok && (mock.tx_count == 3);
    ok = ok && (mock.tx_len[0] == 5);
    ok = ok && (mock.tx[0][0] == 0x90) && (mock.tx[0][1] == 0x60);
    ok = ok && (mock.tx[0][2] == 0x00) && (mock.tx[0][3] == 0x00) && (mock.tx[0][4] == 0x00);
    ok = ok && (mock.tx_len[1] == 5) && (mock.tx_len[2] == 5);
    ok = ok && (mock.tx[1][0] == 0x90) && (mock.tx[1][1] == 0xAF);
    ok = ok && (mock.tx[2][0] == 0x90) && (mock.tx[2][1] == 0xAF);
    ok = ok && (mock.tx[1][2] == 0x00) && (mock.tx[1][3] == 0x00) && (mock.tx[1][4] == 0x00);
    ok = ok && (mock.tx[2][2] == 0x00) && (mock.tx[2][3] == 0x00) && (mock.tx[2][4] == 0x00);

    check("ISO wrapped zero-data framing", ok);
    nxpsc_close(card);
}

static void test_desfire_authentication(void) {
    const nxpsc_key_t key_d40 = {
        .type = NXPSC_KEY_2K3DES,
        .data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    };
    const nxpsc_key_t key_ev1 = {
        .type = NXPSC_KEY_2K3DES,
        .data = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
    };
    const nxpsc_key_t key_aes = {
        .type = NXPSC_KEY_AES128,
        .data = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F},
    };
    const uint8_t rnd_b8[8] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87};
    const uint8_t rnd_b16[16] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                                 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F};

    nxpsc_set_rng(fixed_rng, NULL);

    bool ok = run_desfire_auth_case(DESFIRE_MF3ICD40, NXPSC_CHAN_D40, MOCK_AUTH_LEGACY,
                                    &key_d40, rnd_b8, 0x0A, false);
    ok = ok && run_desfire_auth_case(DESFIRE_EV1, NXPSC_CHAN_EV1, MOCK_AUTH_LEGACY,
                                     &key_ev1, rnd_b8, 0x1A, false);
    ok = ok && run_desfire_auth_case(DESFIRE_EV2, NXPSC_CHAN_EV2, MOCK_AUTH_EV2,
                                     &key_aes, rnd_b16, 0x71, true);
    ok = ok && run_desfire_auth_case(DESFIRE_LIGHT, NXPSC_CHAN_LRP, MOCK_AUTH_LRP,
                                     &key_aes, rnd_b16, 0x71, true);

    nxpsc_set_rng(NULL, NULL);
    check("DESFire auth handshake AF handling", ok);
}

static void test_file_settings(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;
    nxpsc_file_settings_t settings;

    mock_init(&mock, DESFIRE_EV1);
    mock_transport(&mock, &transport);

    // access rights 0x00EE: read and write denied to keys 0 and 0, the rest free
    nxpsc_access_t access = {0x00, 0x00, 0x0E, 0x0E};

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_create_std_file(card, 0x01, 0, NXPSC_COMM_PLAIN, &access, 0x20) == NXPSC_OK);
    ok = ok && (nxpsc_get_file_settings(card, 0x01, &settings) == NXPSC_OK);
    ok = ok && (settings.type == NXPSC_FILE_STD);
    ok = ok && (settings.comm == NXPSC_COMM_PLAIN);
    ok = ok && (settings.size == 0x20);
    ok = ok && (settings.access.read == 0x00);
    ok = ok && (settings.access.change == 0x0E);

    // a file the card does not hold
    ok = ok && (nxpsc_get_file_settings(card, 0x09, &settings) != NXPSC_OK);

    check("GetFileSettings decoding", ok);
    nxpsc_close(card);
}

static void test_create_file_framing(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    nxpsc_access_t access = {.read = 0x00, .write = 0x01, .read_write = 0x02, .change = 0x03};

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_create_std_file(card, 0x02, 0, NXPSC_COMM_FULL, &access, 0x100)
                == NXPSC_OK);
    ok = ok && (mock.tx_count == 1);
    ok = ok && (mock.tx[0][0] == 0xCD);
    ok = ok && (mock.tx[0][1] == 0x02);
    ok = ok && (mock.tx[0][2] == 0x03);      // fully enciphered
    ok = ok && (mock.tx[0][3] == 0x23);      // access rights low byte
    ok = ok && (mock.tx[0][4] == 0x01);      // access rights high byte
    ok = ok && (mock.tx[0][5] == 0x00) && (mock.tx[0][6] == 0x01) && (mock.tx[0][7] == 0x00);
    ok = ok && (mock.tx_len[0] == 8);

    check("CreateStdDataFile framing", ok);
    nxpsc_close(card);
}

static void test_value_and_data(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV1);
    mock_transport(&mock, &transport);

    nxpsc_access_t access = {0x0E, 0x0E, 0x0E, 0x00};

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_create_value_file(card, 0x01, NXPSC_COMM_PLAIN, &access,
                                        0, 0x10000, 0x3039, false) == NXPSC_OK);
    ok = ok && (nxpsc_create_std_file(card, 0x02, 0, NXPSC_COMM_PLAIN, &access, 64) == NXPSC_OK);

    int32_t value = 0;
    ok = ok && (nxpsc_get_value(card, 0x01, NXPSC_COMM_PLAIN, &value) == NXPSC_OK);
    ok = ok && (value == 0x3039);

    // a credit only shows once the transaction is committed
    ok = ok && (nxpsc_credit(card, 0x01, 100, NXPSC_COMM_PLAIN) == NXPSC_OK);
    ok = ok && (nxpsc_get_value(card, 0x01, NXPSC_COMM_PLAIN, &value) == NXPSC_OK);
    ok = ok && (value == 0x3039);
    ok = ok && (nxpsc_commit_transaction(card) == NXPSC_OK);
    ok = ok && (nxpsc_get_value(card, 0x01, NXPSC_COMM_PLAIN, &value) == NXPSC_OK);
    ok = ok && (value == 0x3039 + 100);

    // and a debit that is aborted never happened
    ok = ok && (nxpsc_debit(card, 0x01, 50, NXPSC_COMM_PLAIN) == NXPSC_OK);
    ok = ok && (nxpsc_abort_transaction(card) == NXPSC_OK);
    ok = ok && (nxpsc_get_value(card, 0x01, NXPSC_COMM_PLAIN, &value) == NXPSC_OK);
    ok = ok && (value == 0x3039 + 100);

    static const uint8_t written[16] = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
    };
    uint8_t buf[64] = {0};
    size_t len = 0;
    ok = ok && (nxpsc_write_data(card, 0x02, 0, written, sizeof(written), NXPSC_COMM_PLAIN)
                == NXPSC_OK);
    ok = ok && (nxpsc_read_data(card, 0x02, 0, 16, NXPSC_COMM_PLAIN, buf, sizeof(buf), &len)
                == NXPSC_OK);
    ok = ok && (len == 16) && (memcmp(buf, written, sizeof(written)) == 0);

    // past the end of what was written, the file reads as zero
    memset(buf, 0xFF, sizeof(buf));
    ok = ok && (nxpsc_read_data(card, 0x02, 16, 8, NXPSC_COMM_PLAIN, buf, sizeof(buf), &len)
                == NXPSC_OK);
    ok = ok && (len == 8) && (buf[0] == 0x00) && (buf[7] == 0x00);

    // a file the card does not hold is an error, not an answer
    ok = ok && (nxpsc_get_value(card, 0x08, NXPSC_COMM_PLAIN, &value) != NXPSC_OK);
    ok = ok && (nxpsc_read_data(card, 0x08, 0, 8, NXPSC_COMM_PLAIN, buf, sizeof(buf), &len)
                != NXPSC_OK);

    check("value and data file access", ok);
    nxpsc_close(card);
}

static void test_access_roundtrip(void) {
    nxpsc_access_t in = {.read = 0x0A, .write = 0x0B, .read_write = 0x0C, .change = 0x0D};
    nxpsc_access_t out;

    uint16_t raw = nxpsc_pack_access(&in);
    nxpsc_unpack_access(raw, &out);

    bool ok = (raw == 0xABCD);
    ok = ok && (in.read == out.read) && (in.write == out.write);
    ok = ok && (in.read_write == out.read_write) && (in.change == out.change);

    check("access rights pack/unpack", ok);
}

// AN12196 conditional offsets, mirrors the NTAG 424 DNA example configuration
static void test_sdm_settings(void) {
    nxpsc_access_t access = {.read = 0x0E, .write = 0x00, .read_write = 0x00, .change = 0x00};
    nxpsc_sdm_settings_t sdm = {0};

    sdm.enabled = true;
    sdm.uid_mirror = true;
    sdm.counter_mirror = true;
    sdm.meta_read_key = 0x0E;
    sdm.file_read_key = 0x02;
    sdm.counter_ret_key = 0x0F;
    sdm.uid_offset = 0x000020;
    sdm.counter_offset = 0x000043;
    sdm.mac_input_offset = 0x000043;
    sdm.mac_offset = 0x00004F;

    uint8_t out[64] = {0};
    size_t len = 0;

    bool ok = (nxpsc_sdm_build_settings(NXPSC_COMM_PLAIN, &access, &sdm, out, sizeof(out), &len)
               == NXPSC_OK);
    // options, access(2), sdm options, sdm access(2), three offsets
    ok = ok && (len == 6 + (4 * 3));
    ok = ok && (out[0] == 0x40);                     // SDM and mirroring, plain
    ok = ok && (out[1] == 0x00) && (out[2] == 0xE0);
    ok = ok && (out[3] == 0xC1);                     // UID, counter, ASCII
    ok = ok && (out[4] == 0xFF) && (out[5] == 0xE2);
    ok = ok && (out[6] == 0x20) && (out[7] == 0x00) && (out[8] == 0x00);
    ok = ok && (out[9] == 0x43);
    ok = ok && (out[15] == 0x4F);

    check("NTAG 424 SDM settings layout", ok);

    // SDM disabled leaves only the file option and access rights
    memset(out, 0, sizeof(out));
    sdm.enabled = false;
    ok = (nxpsc_sdm_build_settings(NXPSC_COMM_FULL, &access, &sdm, out, sizeof(out), &len)
          == NXPSC_OK);
    ok = ok && (len == 3) && (out[0] == 0x03);

    check("NTAG 424 SDM disabled layout", ok);
}

static void test_plus_perso(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, PLUS_EV2);
    mock_transport(&mock, &transport);

    uint8_t block[16];
    memset(block, 0xA5, sizeof(block));

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_plus_write_perso(card, 0x4000, block, sizeof(block)) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1);
    ok = ok && (mock.tx[0][0] == 0xA8);
    // the key block address travels little endian
    ok = ok && (mock.tx[0][1] == 0x00) && (mock.tx[0][2] == 0x40);
    ok = ok && (mock.tx_len[0] == 19);

    ok = ok && (nxpsc_plus_commit_perso(card) == NXPSC_OK);
    ok = ok && (mock.tx[1][0] == 0xAA) && (mock.tx_len[1] == 1);

    // SL3 data commands need a session
    ok = ok && (nxpsc_plus_transfer(card, 0x0004) == NXPSC_E_AUTH);

    check("MIFARE Plus personalisation", ok);
    nxpsc_close(card);
}

static void test_guards(void) {
    bool ok = (nxpsc_open(NULL, NULL) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_select_application(NULL, 0) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_pack_access(&(nxpsc_access_t) {
        0x0F, 0x0F, 0x0F, 0x0F
    }) == 0xFFFF);

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;
    uint8_t uid[16] = {0};
    size_t uid_len = 0;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);
    ok = ok && (nxpsc_open(&transport, &card) == NXPSC_OK);

    // commands that require a session must refuse without one
    ok = ok && (nxpsc_change_key_settings(card, 0x0F) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_set_configuration(card, 0x00, NULL, 0) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_select_application(card, 0x01000000) == NXPSC_E_LENGTH);
    ok = ok && (nxpsc_read_data(card, 0x01, 0x01000000, 1, NXPSC_COMM_PLAIN,
                                uid, sizeof(uid), &uid_len) == NXPSC_E_LENGTH);
    ok = ok && (nxpsc_pack_access(NULL) == 0);
    nxpsc_unpack_access(0xFFFF, NULL);

    // without a session GetCardUID falls back to the UID the transport knows
    ok = ok && (nxpsc_get_card_uid(card, uid, sizeof(uid), &uid_len) == NXPSC_OK);
    ok = ok && (uid_len == 7) && (uid[0] == 0x04);

    // the mock rejects the native GetCardUID, that status must reach the caller
    uint8_t resp[32] = {0};
    size_t resp_len = 0;
    ok = ok && (nxpsc_command(card, 0x51, NULL, 0, NXPSC_COMM_PLAIN, NXPSC_COMM_PLAIN,
                              resp, sizeof(resp), &resp_len) == NXPSC_E_CARD);
    ok = ok && (nxpsc_last_status(card) == 0xAE);

    check("argument and session guards", ok);
    nxpsc_close(card);
}

// the EV2 and later extras must put the documented opcodes on the wire
static void test_advanced_commands(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV3);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    // ISO chaining swaps the file access opcodes but keeps the payload
    nxpsc_set_iso_chaining(card, true);
    ok = ok && (nxpsc_get_iso_chaining(card) == true);

    uint8_t buf[64] = {0};
    size_t len = 0;
    mock.tx_count = 0;
    nxpsc_read_data(card, 0x01, 0, 16, NXPSC_COMM_PLAIN, buf, sizeof(buf), &len);
    ok = ok && (mock.tx_count == 1) && (mock.tx[0][0] == 0xAD) && (mock.tx_len[0] == 8);

    nxpsc_set_iso_chaining(card, false);
    mock.tx_count = 0;
    nxpsc_read_data(card, 0x01, 0, 16, NXPSC_COMM_PLAIN, buf, sizeof(buf), &len);
    ok = ok && (mock.tx_count == 1) && (mock.tx[0][0] == 0xBD);

    // UpdateRecord carries file, record, offset and length before the data
    const uint8_t rec[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    mock.tx_count = 0;
    nxpsc_update_record(card, 0x02, 0, 4, rec, sizeof(rec), NXPSC_COMM_PLAIN);
    ok = ok && (mock.tx_count == 1) && (mock.tx[0][0] == 0xDB);
    ok = ok && (mock.tx_len[0] == 1 + 10 + sizeof(rec));
    ok = ok && (mock.tx[0][1] == 0x02) && (mock.tx[0][8] == 0x04) && (mock.tx[0][11] == 0xDE);

    // key set management
    mock.tx_count = 0;
    nxpsc_init_key_set(card, 0x01, NXPSC_KEY_AES128);
    // two bytes, key set then the new set's key type carried unshifted.
    // EV3 answers 0x7E to any other length
    ok = ok && (mock.tx_len[0] == 3);
    ok = ok && (mock.tx[0][0] == 0x56) && (mock.tx[0][1] == 0x01) && (mock.tx[0][2] == 0x02);
    mock.tx_count = 0;
    nxpsc_finalize_key_set(card, 0x01, 0x10);
    ok = ok && (mock.tx[0][0] == 0x57);
    mock.tx_count = 0;
    nxpsc_roll_key_set(card, 0x01);
    ok = ok && (mock.tx[0][0] == 0x55);

    // delegated application management
    mock.tx_count = 0;
    nxpsc_get_delegated_info(card, 0x0102, NULL);
    ok = ok && (mock.tx_count == 0);   // NULL out parameter must be rejected

    // MIFARE Classic mapping and the transaction notification
    const uint8_t mapping[8] = {0};
    mock.tx_count = 0;
    nxpsc_create_mfc_mapping(card, mapping, sizeof(mapping));
    ok = ok && (mock.tx[0][0] == 0xCF);
    mock.tx_count = 0;
    nxpsc_notify_transaction_success(card);
    ok = ok && (mock.tx[0][0] == 0xEE);

    // argument checks on the new calls
    ok = ok && (nxpsc_create_mfc_mapping(card, NULL, 4) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_proximity_check(card, NULL, 1, NULL) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_set_ats(card, mapping, 0) == NXPSC_E_PARAM);

    nxpsc_key_t des = {.type = NXPSC_KEY_DES};
    ok = ok && (nxpsc_proximity_check(card, &des, 1, NULL) == NXPSC_E_UNSUPPORTED);
    ok = ok && (nxpsc_init_key_set(NULL, 0, NXPSC_KEY_AES128) == NXPSC_E_PARAM);

    check("EV2 extras and ISO chaining", ok);
    nxpsc_close(card);
}

// proximity check, end to end against a mock that computes the same CMAC
static void test_proximity_check(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    nxpsc_key_t pc_key = {.type = NXPSC_KEY_AES128};
    memcpy(pc_key.data, mock_pc_key, sizeof(mock_pc_key));

    bool mac_ok = false;
    mock.tx_count = 0;
    ok = ok && (nxpsc_proximity_check(card, &pc_key, 4, &mac_ok) == NXPSC_OK);
    ok = ok && mac_ok;

    // PreparePC, four rounds, VerifyPC
    ok = ok && (mock.tx_count == 6);
    ok = ok && (mock.tx[0][0] == 0xF0);
    ok = ok && (mock.tx[1][0] == 0xF2) && (mock.tx[1][1] == 0x02);
    ok = ok && (mock.tx[5][0] == 0xFD) && (mock.tx_len[5] == 9);

    // a single round has to send the whole challenge at once
    mock.tx_count = 0;
    mac_ok = false;
    ok = ok && (nxpsc_proximity_check(card, &pc_key, 1, &mac_ok) == NXPSC_OK);
    ok = ok && mac_ok && (mock.tx_count == 3) && (mock.tx[1][1] == 0x08);

    // a wrong card MAC must be reported, not silently accepted
    mock.pc_bad_mac = true;
    mac_ok = true;
    ok = ok && (nxpsc_proximity_check(card, &pc_key, 2, &mac_ok) == NXPSC_E_AUTH);
    ok = ok && (mac_ok == false);
    mock.pc_bad_mac = false;

    ok = ok && (nxpsc_proximity_check(card, &pc_key, 0, NULL) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_proximity_check(card, &pc_key, 9, NULL) == NXPSC_E_PARAM);

    check("proximity check", ok);
    nxpsc_close(card);
}

static void test_secure_channel_guards(void) {
    nxpsc_card_t card;
    memset(&card, 0, sizeof(card));
    card.last_cmd = DF_READ_DATA;
    card.mode = MODE_MAC;

    uint8_t out[16] = {0};
    size_t out_len = 0;
    bool ok = true;

    card.channel = NXPSC_CHAN_D40;
    card.key_type = NXPSC_KEY_2K3DES;
    ok = ok && (nxpsc_channel_decode(&card, out, 4, 0x00, out, sizeof(out), &out_len) == NXPSC_E_LENGTH);

    card.channel = NXPSC_CHAN_EV1;
    card.key_type = NXPSC_KEY_AES128;
    ok = ok && (nxpsc_channel_decode(&card, out, 7, 0x00, out, sizeof(out), &out_len) == NXPSC_E_LENGTH);

    card.channel = NXPSC_CHAN_EV2;
    ok = ok && (nxpsc_channel_decode(&card, out, 7, 0x00, out, sizeof(out), &out_len) == NXPSC_E_LENGTH);

    check("secure channel short MAC rejection", ok);
}

static void test_secure_channel_exact_buffers(void) {
    check("D40 MAC exact-size buffer",
          run_exact_buffer_read_case(DESFIRE_MF3ICD40, NXPSC_CHAN_D40,
                                     NXPSC_KEY_2K3DES, NXPSC_COMM_MAC));
    check("D40 ENC exact-size buffer",
          run_exact_buffer_read_case(DESFIRE_MF3ICD40, NXPSC_CHAN_D40,
                                     NXPSC_KEY_2K3DES, NXPSC_COMM_FULL));
    check("EV1 MAC exact-size buffer",
          run_exact_buffer_read_case(DESFIRE_EV1, NXPSC_CHAN_EV1,
                                     NXPSC_KEY_AES128, NXPSC_COMM_MAC));
    check("EV1 ENC exact-size buffer",
          run_exact_buffer_read_case(DESFIRE_EV1, NXPSC_CHAN_EV1,
                                     NXPSC_KEY_AES128, NXPSC_COMM_FULL));
    check("EV2 MAC exact-size buffer",
          run_exact_buffer_read_case(DESFIRE_EV2, NXPSC_CHAN_EV2,
                                     NXPSC_KEY_AES128, NXPSC_COMM_MAC));
    check("EV2 ENC exact-size buffer",
          run_exact_buffer_read_case(DESFIRE_EV2, NXPSC_CHAN_EV2,
                                     NXPSC_KEY_AES128, NXPSC_COMM_FULL));
}

static bool run_legacy_get_card_uid_case(bool ev1_style_crc) {
    static const uint8_t session[16] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
    };
    static const uint8_t iv[16] = {0};
    static const uint8_t ti[4] = {0};

    mock_card_t mock;
    nxpsc_card_t *card = NULL;
    bool ok = setup_secure_session(&mock, &card, DESFIRE_EV3, NXPSC_CHAN_D40,
                                   NXPSC_KEY_2K3DES, session, session, iv, ti, 0);

    uint8_t uid[7] = {0};
    size_t uid_len = 0;

    if (ok) {
        mock.d40_ev1_style_uid = ev1_style_crc;
        ok = ok && (nxpsc_get_card_uid(card, uid, sizeof(uid), &uid_len) == NXPSC_OK);
        ok = ok && (uid_len == sizeof(uid));
        ok = ok && (memcmp(uid, mock.uid, sizeof(uid)) == 0);
    }

    nxpsc_close(card);
    return ok;
}

// a legacy session always enciphers the same way. EV3 answers GetCardUID with
// the legacy CRC16, confirmed against the card, but the decoder accepts the
// EV1 style CRC32 too because later silicon is not consistent about it
// CreateApplication has four optional blocks and the order matters. the key set
// block sits between KeySett2 and the ISO fields, not after them
static void test_create_application_layout(void) {
    static const uint8_t df_name[3] = {0xAA, 0xBB, 0xCC};

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV3);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok == false) {
        check("CreateApplication payload layout", false);
        return;
    }

    // plain application, no ISO fields and no key sets
    mock.tx_count = 0;
    ok = ok && (nxpsc_create_application(card, 0x010203, 0x0F, 3, NXPSC_KEY_AES128) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1) && (mock.tx_len[0] == 6);
    ok = ok && (mock.tx[0][0] == DF_CREATE_APPLICATION);
    ok = ok && (mock.tx[0][1] == 0x03) && (mock.tx[0][2] == 0x02) && (mock.tx[0][3] == 0x01);
    ok = ok && (mock.tx[0][4] == 0x0F);
    ok = ok && (mock.tx[0][5] == (0x03 | 0x80));

    // ISO fid and DF name, still no key sets
    mock.tx_count = 0;
    ok = ok && (nxpsc_create_application_iso(card, 0x010203, 0x0F, 3, NXPSC_KEY_AES128,
                                             0xE110, df_name, sizeof(df_name)) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1) && (mock.tx_len[0] == 11);
    ok = ok && (mock.tx[0][5] == (0x03 | 0x80 | 0x20));
    ok = ok && (mock.tx[0][6] == 0x10) && (mock.tx[0][7] == 0xE1);
    ok = ok && (memcmp(&mock.tx[0][8], df_name, sizeof(df_name)) == 0);

    // key sets, announced by bit 4 of KeySett2, block placed before the ISO fields
    nxpsc_app_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.key_settings = 0x0F;
    cfg.num_keys = 3;
    cfg.key_type = NXPSC_KEY_AES128;
    cfg.iso_fid_enabled = true;
    cfg.iso_fid = 0xE110;
    cfg.df_name = df_name;
    cfg.df_name_len = sizeof(df_name);
    cfg.num_key_sets = 2;
    cfg.key_set_version = 0x11;
    cfg.max_key_size = 16;
    cfg.key_set_settings = 0x02;    // three bits wide, the roll key

    mock.tx_count = 0;
    ok = ok && (nxpsc_create_application_ex(card, 0x010203, &cfg) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1) && (mock.tx_len[0] == 16);
    ok = ok && (mock.tx[0][5] == (0x03 | 0x80 | 0x20 | 0x10));
    ok = ok && (mock.tx[0][6] == 0x01);     // KeySett3, key sets enabled
    ok = ok && (mock.tx[0][7] == 0x11);     // AKSVersion
    ok = ok && (mock.tx[0][8] == 0x02);     // NoKeySets
    ok = ok && (mock.tx[0][9] == 16);       // MaxKeySize
    ok = ok && (mock.tx[0][10] == 0x02);    // AppKeySetSett
    ok = ok && (mock.tx[0][11] == 0x10) && (mock.tx[0][12] == 0xE1);
    ok = ok && (memcmp(&mock.tx[0][13], df_name, sizeof(df_name)) == 0);

    // specific VC keys ride in KeySett3 without bringing the key set block,
    // so the ISO fields follow it straight away
    memset(&cfg, 0, sizeof(cfg));
    cfg.key_settings = 0x0F;
    cfg.num_keys = 3;
    cfg.key_type = NXPSC_KEY_AES128;
    cfg.iso_fid_enabled = true;
    cfg.iso_fid = 0xE110;
    cfg.specific_vc_keys = true;

    mock.tx_count = 0;
    ok = ok && (nxpsc_create_application_ex(card, 0x010203, &cfg) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1) && (mock.tx_len[0] == 9);
    ok = ok && (mock.tx[0][5] == (0x03 | 0x80 | 0x20 | 0x10));
    ok = ok && (mock.tx[0][6] == 0x02);     // KeySett3, VC keys only
    ok = ok && (mock.tx[0][7] == 0x10) && (mock.tx[0][8] == 0xE1);

    // one key set is not a set, the caller meant either none or at least two
    memset(&cfg, 0, sizeof(cfg));
    cfg.key_settings = 0x0F;
    cfg.num_keys = 3;
    cfg.key_type = NXPSC_KEY_AES128;
    cfg.num_key_sets = 1;
    ok = ok && (nxpsc_create_application_ex(card, 0x010203, &cfg) == NXPSC_E_PARAM);

    // AppKeySetSett is three bits wide
    cfg.num_key_sets = 2;
    cfg.max_key_size = 16;
    cfg.key_set_settings = 0x0F;
    ok = ok && (nxpsc_create_application_ex(card, 0x010203, &cfg) == NXPSC_E_PARAM);

    check("CreateApplication payload layout", ok);
    nxpsc_close(card);
}

static void test_legacy_get_card_uid(void) {
    check("legacy GetCardUID, CRC16 payload", run_legacy_get_card_uid_case(false));
    check("legacy GetCardUID, CRC32 payload", run_legacy_get_card_uid_case(true));
}

// a 2TDEA key with two equal halves is a DES key. the PICC cannot tell the two
// apart from the key type alone and derives the shorter session key, which the
// handshake never exposes because 3DES with K1 == K2 is single DES
static void test_legacy_des_degraded_session_key(void) {
    // fixed_rng() and the mock both build RndA as 0x10 + index
    static const uint8_t rnd_a[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    static const uint8_t rnd_b[8] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7};

    nxpsc_key_t key;
    memset(&key, 0, sizeof(key));
    key.type = NXPSC_KEY_2K3DES;

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV3);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok) {
        card->type = DESFIRE_EV3;
        mock.auth_scheme = MOCK_AUTH_LEGACY;
        mock.auth_key_type = NXPSC_KEY_2K3DES;
        memset(mock.auth_key, 0, sizeof(mock.auth_key));
        memcpy(mock.auth_rnd_b, rnd_b, sizeof(rnd_b));
        nxpsc_set_rng(fixed_rng, NULL);

        ok = ok && (nxpsc_authenticate(card, 0, &key, NXPSC_CHAN_D40) == NXPSC_OK);
        nxpsc_set_rng(NULL, NULL);
    }

    if (ok) {
        // DES session key, RndA[0..3] || RndB[0..3], held duplicated
        uint8_t want[16] = {0};
        memcpy(want, rnd_a, 4);
        memcpy(want + 4, rnd_b, 4);
        memcpy(want + 8, want, 8);
        ok = ok && (memcmp(card->session_enc, want, sizeof(want)) == 0);
        ok = ok && (memcmp(mock.secure_session_enc, want, sizeof(want)) == 0);

        // and the first command on that session decodes, which is the only
        // place a wrong derivation would ever show up
        uint8_t uid[7] = {0};
        size_t uid_len = 0;
        ok = ok && (nxpsc_get_card_uid(card, uid, sizeof(uid), &uid_len) == NXPSC_OK);
        ok = ok && (uid_len == sizeof(uid));
        ok = ok && (memcmp(uid, mock.uid, sizeof(uid)) == 0);
    }

    check("legacy DES degraded session key", ok);
    nxpsc_close(card);
}

// Everything Tessera and Crucible drive on hardware should also be pinned off
// card, because a framing or parsing regression on a card surfaces as a status
// byte a long way from its cause. These cover the calls those two suites use
// that nothing here reached.
static void test_info_parsing(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    // the card answers about the application it holds, so create one first
    ok = ok && (nxpsc_create_application(card, 0x010203, 0x0F, 3, NXPSC_KEY_AES128) == NXPSC_OK);
    ok = ok && (nxpsc_select_application(card, 0x010203) == NXPSC_OK);

    uint8_t settings = 0;
    uint8_t num_keys = 0;
    nxpsc_keytype_t ktype = NXPSC_KEY_DES;
    ok = ok && (nxpsc_get_key_settings(card, &settings, &num_keys, &ktype) == NXPSC_OK);
    ok = ok && (settings == 0x0F) && (num_keys == 3) && (ktype == NXPSC_KEY_AES128);

    // every key starts at the factory version, and a key the application does
    // not have is an error rather than a number
    uint8_t version = 0xFF;
    ok = ok && (nxpsc_get_key_version(card, 1, &version) == NXPSC_OK);
    ok = ok && (version == 0x00);
    ok = ok && (nxpsc_get_key_version(card, 5, &version) != NXPSC_OK);

    uint32_t freemem = 0;
    ok = ok && (nxpsc_get_free_memory(card, &freemem) == NXPSC_OK);

    uint8_t sig[64] = {0};
    size_t siglen = 0;
    ok = ok && (nxpsc_get_signature(card, sig, sizeof(sig), &siglen) == NXPSC_OK);
    ok = ok && (siglen == 56) && (sig[0] == 0xA0) && (sig[55] == 0xD7);

    // and about the files it holds, so give it some of those too
    nxpsc_access_t any = {0, 0, 0, 0};
    ok = ok && (nxpsc_create_std_file(card, 0x00, 0, NXPSC_COMM_PLAIN, &any, 32) == NXPSC_OK);
    ok = ok && (nxpsc_create_std_file(card, 0x01, 0, NXPSC_COMM_PLAIN, &any, 32) == NXPSC_OK);
    ok = ok && (nxpsc_create_std_file(card, 0x02, 0, NXPSC_COMM_PLAIN, &any, 32) == NXPSC_OK);

    uint8_t ids[NXPSC_MAX_FILES] = {0};
    size_t count = 0;
    ok = ok && (nxpsc_get_file_ids(card, ids, NXPSC_MAX_FILES, &count) == NXPSC_OK);
    ok = ok && (count == 3);

    uint16_t iso_ids[NXPSC_MAX_FILES] = {0};
    count = 0;
    ok = ok && (nxpsc_get_iso_file_ids(card, iso_ids, NXPSC_MAX_FILES, &count) == NXPSC_OK);
    ok = ok && (count == 2) && (iso_ids[0] == 0xE110) && (iso_ids[1] == 0xE111);

    check("info commands parse what the card returns", ok);
    nxpsc_close(card);
}

// GetDFNames answers one application per frame, and the DF name length is only
// knowable from the frame length. Two applications is the case that tells a
// working parser from one that happens to survive a single entry.
static void test_get_df_names_two_apps(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    nxpsc_app_t apps[4];
    size_t count = 0;
    memset(apps, 0, sizeof(apps));
    ok = ok && (nxpsc_get_df_names(card, apps, 4, &count) == NXPSC_OK);

    ok = ok && (count == 2);
    if (count == 2) {
        ok = ok && (apps[0].aid == 0x030201) && (apps[0].iso_fid == 0xE110);
        ok = ok && (apps[0].df_name_len == 5);
        ok = ok && (memcmp(apps[0].df_name, "first", 5) == 0);

        ok = ok && (apps[1].aid == 0x332211) && (apps[1].iso_fid == 0xE120);
        ok = ok && (apps[1].df_name_len == 10);
        ok = ok && (memcmp(apps[1].df_name, "second.app", 10) == 0);
    }

    // and it refuses outright while a session is open, because sending it then
    // disables an EV1 permanently
    card->authenticated = true;
    ok = ok && (nxpsc_get_df_names(card, apps, 4, &count) == NXPSC_E_AUTH);

    check("GetDFNames keeps two applications apart", ok);
    nxpsc_close(card);
}

// the payloads the file management calls build, asserted byte for byte
static void test_file_management_framing(void) {
    nxpsc_access_t acc = {.read = 0x0E, .write = 0x00, .read_write = 0x01, .change = 0x02};

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    // ChangeFileSettings refuses to build a payload without a session, and the
    // channel stays AUTO so the bytes reach the mock unwrapped
    card->authenticated = true;

    // backup file: fileno, comm, access(2), size(3)
    mock.tx_count = 0;
    ok = ok && (nxpsc_create_backup_file(card, 4, 0x0000, NXPSC_COMM_MAC, &acc, 32) == NXPSC_OK);
    ok = ok && (mock.tx_len[0] == 8) && (mock.tx[0][0] == 0xCB);
    ok = ok && (mock.tx[0][1] == 0x04) && (mock.tx[0][2] == 0x01);
    ok = ok && (mock.tx[0][5] == 0x20) && (mock.tx[0][6] == 0x00) && (mock.tx[0][7] == 0x00);

    // value file: fileno, comm, access(2), lower(4), upper(4), value(4), limited(1)
    mock.tx_count = 0;
    ok = ok && (nxpsc_create_value_file(card, 5, NXPSC_COMM_MAC, &acc, 0, 1000, 500, true)
                == NXPSC_OK);
    ok = ok && (mock.tx_len[0] == 18) && (mock.tx[0][0] == 0xCC);
    ok = ok && (mock.tx[0][1] == 0x05);
    ok = ok && (mock.tx[0][9] == 0xE8) && (mock.tx[0][10] == 0x03);   // upper 1000
    ok = ok && (mock.tx[0][13] == 0xF4) && (mock.tx[0][14] == 0x01);  // value 500
    ok = ok && (mock.tx[0][17] == 0x01);                              // limited credit

    // cyclic and linear record files differ only in opcode
    mock.tx_count = 0;
    ok = ok && (nxpsc_create_record_file(card, true, 6, 0x0000, NXPSC_COMM_MAC, &acc, 8, 4)
                == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xC0) && (mock.tx_len[0] == 11);
    ok = ok && (mock.tx[0][5] == 0x08) && (mock.tx[0][8] == 0x04);

    mock.tx_count = 0;
    ok = ok && (nxpsc_create_record_file(card, false, 7, 0x0000, NXPSC_COMM_MAC, &acc, 8, 4)
                == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xC1);

    mock.tx_count = 0;
    ok = ok && (nxpsc_delete_file(card, 4) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xDF) && (mock.tx[0][1] == 0x04) && (mock.tx_len[0] == 2);

    mock.tx_count = 0;
    ok = ok && (nxpsc_change_file_settings(card, 3, NXPSC_COMM_FULL, &acc) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0x5F) && (mock.tx[0][1] == 0x03) && (mock.tx[0][2] == 0x03);

    mock.tx_count = 0;
    ok = ok && (nxpsc_delete_application(card, 0x010203) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xDA) && (mock.tx_len[0] == 4);
    ok = ok && (mock.tx[0][1] == 0x03) && (mock.tx[0][2] == 0x02) && (mock.tx[0][3] == 0x01);

    check("file management payload framing", ok);
    nxpsc_close(card);
}

// the data, record and value access calls, and the transaction pair
static void test_data_access_framing(void) {
    static const uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    // the files these commands work on: the mock answers from what they hold
    nxpsc_access_t access = {0x0E, 0x0E, 0x0E, 0x00};
    ok = ok && (nxpsc_create_std_file(card, 2, 0, NXPSC_COMM_PLAIN, &access, 64) == NXPSC_OK);
    ok = ok && (nxpsc_create_record_file(card, true, 6, 0, NXPSC_COMM_PLAIN, &access, 8, 4)
                == NXPSC_OK);
    ok = ok && (nxpsc_create_value_file(card, 5, NXPSC_COMM_PLAIN, &access, 0, 1000, 100, false)
                == NXPSC_OK);

    // WriteData: fileno, offset(3), length(3), data
    mock.tx_count = 0;
    ok = ok && (nxpsc_write_data(card, 2, 0x10, payload, sizeof(payload), NXPSC_COMM_PLAIN)
                == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0x3D) && (mock.tx_len[0] == 1 + 7 + sizeof(payload));
    ok = ok && (mock.tx[0][1] == 0x02);
    ok = ok && (mock.tx[0][2] == 0x10) && (mock.tx[0][3] == 0x00) && (mock.tx[0][4] == 0x00);
    ok = ok && (mock.tx[0][5] == 0x04) && (mock.tx[0][8] == 0xDE);

    // WriteRecord has the same shape under a different opcode
    mock.tx_count = 0;
    ok = ok && (nxpsc_write_record(card, 6, 0, payload, sizeof(payload), NXPSC_COMM_PLAIN)
                == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0x3B) && (mock.tx[0][1] == 0x06);

    // ReadRecords hands back the records that were committed, newest first
    static const uint8_t second[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t back[64] = {0};
    size_t back_len = 0;
    ok = ok && (nxpsc_commit_transaction(card) == NXPSC_OK);
    ok = ok && (nxpsc_write_record(card, 6, 0, second, sizeof(second), NXPSC_COMM_PLAIN)
                == NXPSC_OK);
    ok = ok && (nxpsc_commit_transaction(card) == NXPSC_OK);

    mock.tx_count = 0;
    ok = ok && (nxpsc_read_records(card, 6, 0, 2, NXPSC_COMM_PLAIN, back, sizeof(back), &back_len)
                == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xBB) && (back_len == 16);
    ok = ok && (back[0] == 0x11) && (back[8] == 0xDE);

    // a record that was written but not committed is not there yet
    ok = ok && (nxpsc_write_record(card, 6, 0, payload, sizeof(payload), NXPSC_COMM_PLAIN)
                == NXPSC_OK);
    ok = ok && (nxpsc_read_records(card, 6, 0, 3, NXPSC_COMM_PLAIN, back, sizeof(back), &back_len)
                != NXPSC_OK);
    ok = ok && (nxpsc_abort_transaction(card) == NXPSC_OK);

    mock.tx_count = 0;
    ok = ok && (nxpsc_clear_record_file(card, 6) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xEB) && (mock.tx[0][1] == 0x06);

    // credit, debit and limited credit differ only in opcode
    mock.tx_count = 0;
    ok = ok && (nxpsc_credit(card, 5, 50, NXPSC_COMM_PLAIN) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0x0C) && (mock.tx[0][1] == 0x05) && (mock.tx[0][2] == 0x32);

    mock.tx_count = 0;
    ok = ok && (nxpsc_debit(card, 5, 30, NXPSC_COMM_PLAIN) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xDC) && (mock.tx[0][2] == 0x1E);

    mock.tx_count = 0;
    ok = ok && (nxpsc_limited_credit(card, 5, 10, NXPSC_COMM_PLAIN) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0x1C) && (mock.tx[0][2] == 0x0A);

    mock.tx_count = 0;
    ok = ok && (nxpsc_commit_transaction(card) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xC7) && (mock.tx_len[0] == 1);

    mock.tx_count = 0;
    ok = ok && (nxpsc_abort_transaction(card) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xA7) && (mock.tx_len[0] == 1);

    check("data and record access framing", ok);
    nxpsc_close(card);
}

// The ISO 7816-4 wrappers build real APDUs rather than wrapped native frames,
// so the header bytes are the whole of what they do and nothing else checks
// them. Crucible drives all three against a card.
static void test_iso7816_wrappers(void) {
    static const uint8_t df_name[5] = {'n', 'x', 'p', 's', 'c'};

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    // SELECT by DF name: P1 0x04, P2 0x0C, no Le
    mock.tx_count = 0;
    ok = ok && (nxpsc_iso_select_df_name(card, df_name, sizeof(df_name)) == NXPSC_OK);
    ok = ok && (mock.tx_count == 1) && (mock.tx_len[0] == 5 + sizeof(df_name));
    ok = ok && (mock.tx[0][0] == 0x00) && (mock.tx[0][1] == 0xA4);
    ok = ok && (mock.tx[0][2] == 0x04) && (mock.tx[0][3] == 0x0C);
    ok = ok && (mock.tx[0][4] == sizeof(df_name));
    ok = ok && (memcmp(&mock.tx[0][5], df_name, sizeof(df_name)) == 0);

    // SELECT by file id: P1 0x02 for an EF, 0x01 for a DF, fid big endian
    mock.tx_count = 0;
    ok = ok && (nxpsc_iso_select_fid(card, 0xE110, true) == NXPSC_OK);
    ok = ok && (mock.tx_len[0] == 7) && (mock.tx[0][2] == 0x02) && (mock.tx[0][3] == 0x0C);
    ok = ok && (mock.tx[0][4] == 0x02);
    ok = ok && (mock.tx[0][5] == 0xE1) && (mock.tx[0][6] == 0x10);

    mock.tx_count = 0;
    ok = ok && (nxpsc_iso_select_fid(card, 0xE110, false) == NXPSC_OK);
    ok = ok && (mock.tx[0][2] == 0x01);

    // READ BINARY without a short file id: P1 carries the high offset bits
    uint8_t out[64] = {0};
    size_t out_len = 0;
    mock.tx_count = 0;
    ok = ok && (nxpsc_iso_read_binary(card, 0, 0x0102, 8, out, sizeof(out), &out_len)
                == NXPSC_OK);
    ok = ok && (mock.tx[0][1] == 0xB0) && (mock.tx[0][2] == 0x01) && (mock.tx[0][3] == 0x02);
    ok = ok && (mock.tx_len[0] == 5) && (mock.tx[0][4] == 0x08);
    ok = ok && (out_len == 8) && (out[0] == 0x50) && (out[7] == 0x57);

    // with one, P1 becomes 0x80 | sfi and the offset has to fit one byte
    mock.tx_count = 0;
    ok = ok && (nxpsc_iso_read_binary(card, 0x03, 0x10, 4, out, sizeof(out), &out_len)
                == NXPSC_OK);
    ok = ok && (mock.tx[0][2] == 0x83) && (mock.tx[0][3] == 0x10);
    ok = ok && (out_len == 4);

    ok = ok && (nxpsc_iso_read_binary(card, 0x03, 0x0100, 4, out, sizeof(out), &out_len)
                == NXPSC_E_PARAM);

    // UPDATE BINARY is the same addressing with data and no Le
    static const uint8_t payload[3] = {0xAA, 0xBB, 0xCC};
    mock.tx_count = 0;
    ok = ok && (nxpsc_iso_update_binary(card, 0x03, 0x10, payload, sizeof(payload))
                == NXPSC_OK);
    ok = ok && (mock.tx[0][1] == 0xD6) && (mock.tx[0][2] == 0x83) && (mock.tx[0][3] == 0x10);
    ok = ok && (mock.tx[0][4] == sizeof(payload)) && (mock.tx[0][5] == 0xAA);

    // argument checks
    ok = ok && (nxpsc_iso_select_df_name(card, df_name, 0) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_iso_select_df_name(card, df_name, 17) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_iso_read_binary(card, 0, 0, 8, NULL, 0, &out_len) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_iso_update_binary(card, 0, 0, payload, 0) == NXPSC_E_PARAM);

    check("ISO 7816-4 wrapper APDUs", ok);
    nxpsc_close(card);
}

// CommitReaderID needs a session and hands back the previous reader id through
// it. Crucible reaches this only on a card whose transaction MAC file allows it.
static void test_commit_reader_id(void) {
    static const uint8_t session_enc[16] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
    };
    static const uint8_t session_mac[16] = {
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F
    };
    static const uint8_t iv[16] = {0};
    static const uint8_t ti[4] = {0xCA, 0xFE, 0xBA, 0xBE};
    static const uint8_t reader_id[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    mock_card_t mock;
    nxpsc_card_t *card = NULL;
    bool ok = setup_secure_session(&mock, &card, DESFIRE_EV3, NXPSC_CHAN_EV2,
                                   NXPSC_KEY_AES128, session_enc, session_mac, iv, ti, 0);

    if (ok) {
        uint8_t prev[32] = {0};
        size_t prev_len = 0;

        mock.tx_count = 0;
        ok = ok && (nxpsc_commit_reader_id(card, reader_id, sizeof(reader_id),
                                           prev, sizeof(prev), &prev_len) == NXPSC_OK);
        ok = ok && (mock.tx[0][0] == 0xC8);
        // the reader id travels in the clear with the session MAC after it
        ok = ok && (memcmp(&mock.tx[0][1], reader_id, sizeof(reader_id)) == 0);
        ok = ok && (mock.tx_len[0] == 1 + 16 + 8);
        ok = ok && (prev_len == 16) && (prev[0] == 0xC0) && (prev[15] == 0xCF);

        // it is sixteen bytes or nothing, and it needs a session
        ok = ok && (nxpsc_commit_reader_id(card, reader_id, 8, prev, sizeof(prev), &prev_len)
                    == NXPSC_E_PARAM);
        nxpsc_reset_channel(card);
        ok = ok && (nxpsc_commit_reader_id(card, reader_id, sizeof(reader_id),
                                           prev, sizeof(prev), &prev_len) == NXPSC_E_AUTH);
    }

    check("CommitReaderID carries the reader id and returns the previous one", ok);
    nxpsc_close(card);
}

// The EV1 CMAC runs through the answers as well as the commands, so both sides
// have to keep the IV each MAC leaves behind. One command proves nothing: it is
// the second that fails when a side forgets. The mock used to compute its
// response MAC into a throwaway copy of the card context, and nothing caught it
// because no test had ever issued two MACed EV1 commands in a row.
static void test_ev1_chain_survives_several_commands(void) {
    static const uint8_t session_enc[16] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
    };
    static const uint8_t session_mac[16] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F
    };
    static const uint8_t iv[16] = {0};
    static const uint8_t ti[4] = {0x00, 0x00, 0x00, 0x00};

    mock_card_t mock;
    nxpsc_card_t *card = NULL;
    bool ok = setup_secure_session(&mock, &card, DESFIRE_EV1, NXPSC_CHAN_EV1,
                                   NXPSC_KEY_AES128, session_enc, session_mac, iv, ti, 0);

    if (ok) {
        // reads are what the EV1 channel MACs, so they are what exercises the
        // chain. The file holds a byte per position so a wrong answer shows
        mock.read_comm = NXPSC_COMM_MAC;
        mock.files[0].file_no = 0x01;
        mock.files[0].type = 0x00;
        mock.files[0].comm = NXPSC_COMM_MAC;
        mock.files[0].size = 16;
        for (size_t i = 0; i < 16; i++) {
            mock.files[0].data[i] = (uint8_t)(0xA0 + i);
        }
        mock.file_count = 1;

        uint8_t buf[32] = {0};
        size_t len = 0;
        for (int round = 0; round < 4 && ok; round++) {
            memset(buf, 0, sizeof(buf));
            ok = ok && (nxpsc_read_data(card, 0x01, 0, 16, NXPSC_COMM_MAC, buf, sizeof(buf), &len)
                        == NXPSC_OK);
            ok = ok && (len == 16) && (buf[0] == 0xA0) && (buf[15] == 0xAF);
        }
    }

    check("the EV1 chain survives several commands", ok);
    nxpsc_close(card);
}

// One round trip per command the mock answers from state: write something,
// read it back, and get what was written. A fixed table cannot creep back in
// without one of these failing.
static void test_mock_answers_what_was_written(void) {
    static const uint8_t record_a[8] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};
    static const uint8_t record_b[8] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7};
    static const uint8_t data[12] = {
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB
    };

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    nxpsc_access_t access = {0x0E, 0x0E, 0x0E, 0x00};
    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    // CreateApplication -> GetApplicationIDs, GetKeySettings, GetKeyVersion
    ok = ok && (nxpsc_create_application(card, 0xF0B501, 0x0B, 6, NXPSC_KEY_AES128) == NXPSC_OK);
    uint32_t aids[MOCK_MAX_APPS] = {0};
    size_t count = 0;
    ok = ok && (nxpsc_get_application_ids(card, aids, MOCK_MAX_APPS, &count) == NXPSC_OK);
    ok = ok && (count == 1) && (aids[0] == 0xF0B501);

    ok = ok && (nxpsc_select_application(card, 0xF0B501) == NXPSC_OK);
    uint8_t settings = 0;
    uint8_t num_keys = 0;
    nxpsc_keytype_t key_type = NXPSC_KEY_DES;
    ok = ok && (nxpsc_get_key_settings(card, &settings, &num_keys, &key_type) == NXPSC_OK);
    ok = ok && (settings == 0x0B) && (num_keys == 6) && (key_type == NXPSC_KEY_AES128);

    uint8_t version = 0xFF;
    ok = ok && (nxpsc_get_key_version(card, 0, &version) == NXPSC_OK);
    ok = ok && (version == 0x00);

    // CreateFile -> GetFileIDs, GetFileSettings
    ok = ok && (nxpsc_create_record_file(card, true, 0x01, 0, NXPSC_COMM_PLAIN, &access, 8, 3)
                == NXPSC_OK);
    ok = ok && (nxpsc_create_std_file(card, 0x02, 0, NXPSC_COMM_PLAIN, &access, 32) == NXPSC_OK);
    ok = ok && (nxpsc_create_value_file(card, 0x03, NXPSC_COMM_PLAIN, &access, 0, 500, 250, false)
                == NXPSC_OK);

    uint8_t ids[NXPSC_MAX_FILES] = {0};
    count = 0;
    ok = ok && (nxpsc_get_file_ids(card, ids, sizeof(ids), &count) == NXPSC_OK);
    ok = ok && (count == 3) && (ids[0] == 0x01) && (ids[2] == 0x03);

    nxpsc_file_settings_t file;
    memset(&file, 0, sizeof(file));
    ok = ok && (nxpsc_get_file_settings(card, 0x01, &file) == NXPSC_OK);
    ok = ok && (file.record_size == 8) && (file.max_records == 3);

    // WriteData -> ReadData
    uint8_t back[64] = {0};
    size_t back_len = 0;
    ok = ok && (nxpsc_write_data(card, 0x02, 4, data, sizeof(data), NXPSC_COMM_PLAIN) == NXPSC_OK);
    ok = ok && (nxpsc_read_data(card, 0x02, 4, sizeof(data), NXPSC_COMM_PLAIN, back, sizeof(back),
                                &back_len) == NXPSC_OK);
    ok = ok && (back_len == sizeof(data)) && (memcmp(back, data, sizeof(data)) == 0);

    // WriteRecord -> ReadRecords, newest first, and only once committed
    ok = ok && (nxpsc_write_record(card, 0x01, 0, record_a, sizeof(record_a), NXPSC_COMM_PLAIN)
                == NXPSC_OK);
    ok = ok && (nxpsc_commit_transaction(card) == NXPSC_OK);
    ok = ok && (nxpsc_write_record(card, 0x01, 0, record_b, sizeof(record_b), NXPSC_COMM_PLAIN)
                == NXPSC_OK);
    ok = ok && (nxpsc_commit_transaction(card) == NXPSC_OK);

    back_len = 0;
    ok = ok && (nxpsc_read_records(card, 0x01, 0, 2, NXPSC_COMM_PLAIN, back, sizeof(back), &back_len)
                == NXPSC_OK);
    ok = ok && (back_len == 16);
    ok = ok && (memcmp(back, record_b, sizeof(record_b)) == 0);
    ok = ok && (memcmp(back + 8, record_a, sizeof(record_a)) == 0);

    // Credit and Debit -> GetValue, again only once committed
    int32_t value = 0;
    ok = ok && (nxpsc_get_value(card, 0x03, NXPSC_COMM_PLAIN, &value) == NXPSC_OK);
    ok = ok && (value == 250);
    ok = ok && (nxpsc_debit(card, 0x03, 50, NXPSC_COMM_PLAIN) == NXPSC_OK);
    ok = ok && (nxpsc_commit_transaction(card) == NXPSC_OK);
    ok = ok && (nxpsc_get_value(card, 0x03, NXPSC_COMM_PLAIN, &value) == NXPSC_OK);
    ok = ok && (value == 200);

    // DeleteFile -> GetFileIDs, GetFileSettings
    ok = ok && (nxpsc_delete_file(card, 0x02) == NXPSC_OK);
    count = 0;
    ok = ok && (nxpsc_get_file_ids(card, ids, sizeof(ids), &count) == NXPSC_OK);
    ok = ok && (count == 2);
    ok = ok && (nxpsc_get_file_settings(card, 0x02, &file) != NXPSC_OK);
    ok = ok && (nxpsc_read_data(card, 0x02, 0, 4, NXPSC_COMM_PLAIN, back, sizeof(back), &back_len)
                != NXPSC_OK);

    // a record written to a file that is not there, or is not a record file,
    // is refused rather than acknowledged into nowhere
    ok = ok && (nxpsc_write_record(card, 0x07, 0, record_a, sizeof(record_a), NXPSC_COMM_PLAIN)
                != NXPSC_OK);
    ok = ok && (nxpsc_last_status(card) == 0xF0);
    ok = ok && (nxpsc_write_record(card, 0x03, 0, record_a, sizeof(record_a), NXPSC_COMM_PLAIN)
                != NXPSC_OK);

    check("the mock answers what was written to it", ok);
    nxpsc_close(card);
}

// The mock answers GetFileIDs and GetFileSettings from what it saw created, so
// a caller that reads its own file settings back gets what it asked for.
static void test_created_files_are_reported(void) {
    static const uint8_t session_enc[16] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
    };
    static const uint8_t session_mac[16] = {
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F
    };
    static const uint8_t iv[16] = {0};
    static const uint8_t ti[4] = {0xCA, 0xFE, 0xBA, 0xBE};

    mock_card_t mock;
    nxpsc_card_t *card = NULL;
    bool ok = setup_secure_session(&mock, &card, DESFIRE_EV3, NXPSC_CHAN_EV2,
                                  NXPSC_KEY_AES128, session_enc, session_mac, iv, ti, 0);

    if (ok) {
        nxpsc_access_t access = {2, 2, 2, 0};
        ok = ok && (nxpsc_create_record_file(card, true, 0x01, 0, NXPSC_COMM_MAC, &access, 32, 4)
                    == NXPSC_OK);

        uint8_t ids[NXPSC_MAX_FILES] = {0};
        size_t count = 0;
        ok = ok && (nxpsc_get_file_ids(card, ids, sizeof(ids), &count) == NXPSC_OK);
        ok = ok && (count == 1) && (ids[0] == 0x01);

        nxpsc_file_settings_t settings;
        memset(&settings, 0, sizeof(settings));
        ok = ok && (nxpsc_get_file_settings(card, 0x01, &settings) == NXPSC_OK);
        ok = ok && (settings.type == NXPSC_FILE_CYCLIC);
        ok = ok && (settings.comm == NXPSC_COMM_MAC);
        ok = ok && (settings.record_size == 32) && (settings.max_records == 4);
        ok = ok && (settings.access.read == 2) && (settings.access.write == 2);
        ok = ok && (settings.access.read_write == 2) && (settings.access.change == 0);

        // a file that was never created is not there
        ok = ok && (nxpsc_get_file_settings(card, 0x07, &settings) != NXPSC_OK);
    }

    check("the mock reports the files it was asked to create", ok);
    nxpsc_close(card);
}

// The transaction MAC: the card computes a TMV over what it saw, the back
// office recomputes it from what it expected. There are no published vectors
// for this, so what is checked here is that two independent readings of the
// data sheet agree: the mock builds the TMI and the TMV its own way (see
// mockcard.c) and nxpsc_tmac_compute builds them from the library's side.
// Only a real card settles it, which is why the personaliser proves it per card.
static void test_transaction_mac(void) {
    static const uint8_t session_enc[16] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
    };
    static const uint8_t session_mac[16] = {
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F
    };
    static const uint8_t iv[16] = {0};
    static const uint8_t ti[4] = {0xCA, 0xFE, 0xBA, 0xBE};
    static const uint8_t tm_key_data[16] = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
    };
    static const uint8_t record[32] = {
        0x01, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    mock_card_t mock;
    nxpsc_card_t *card = NULL;
    bool ok = setup_secure_session(&mock, &card, DESFIRE_EV3, NXPSC_CHAN_EV2,
                                   NXPSC_KEY_AES128, session_enc, session_mac, iv, ti, 0);

    nxpsc_key_t tm_key = {0};
    tm_key.type = NXPSC_KEY_AES128;
    memcpy(tm_key.data, tm_key_data, sizeof(tm_key_data));
    // a real card is told the key inside CreateTransactionMACFile, enciphered
    memcpy(mock.tm_key, tm_key_data, sizeof(tm_key_data));

    if (ok) {
        nxpsc_access_t access = {2, 0x0F, 2, 0x0F};
        ok = ok && (nxpsc_create_transaction_mac_file(card, 0x02, NXPSC_COMM_MAC, &access,
                                                      &tm_key, 1) == NXPSC_OK);
        ok = ok && mock.tm_file;

        // and the record file the payment is written to
        nxpsc_access_t record_access = {2, 2, 2, 0};
        ok = ok && (nxpsc_create_record_file(card, true, 0x01, 0, NXPSC_COMM_MAC, &record_access, 32, 4)
                    == NXPSC_OK);

        // one payment: a record written in MAC mode, then the commit
        ok = ok && (nxpsc_write_record(card, 0x01, 0, record, sizeof(record), NXPSC_COMM_MAC)
                    == NXPSC_OK);

        uint8_t tmc[4] = {0};
        uint8_t tmv[8] = {0};
        ok = ok && (nxpsc_commit_transaction_tmac(card, tmc, tmv) == NXPSC_OK);
        // the first transaction on a fresh file reports counter 1, LSB first
        ok = ok && (tmc[0] == 0x01) && (tmc[1] == 0x00) && (tmc[2] == 0x00) && (tmc[3] == 0x00);

        // rebuild the input from the record alone and recompute the value
        uint8_t tmi[64] = {0};
        size_t tmi_len = 0;
        ok = ok && (nxpsc_tmac_tmi_write_record(0x01, 0, record, sizeof(record),
                                                tmi, sizeof(tmi), &tmi_len) == NXPSC_OK);
        ok = ok && (tmi_len == 16 + 32);
        ok = ok && (tmi[0] == 0x3B) && (tmi[1] == 0x01);
        ok = ok && (tmi[5] == 0x20) && (tmi[6] == 0x00) && (tmi[7] == 0x00);   // length, LSB first
        ok = ok && (tmi[8] == 0x00) && (tmi[15] == 0x00);                      // the zero padding
        ok = ok && (memcmp(tmi + 16, record, sizeof(record)) == 0);

        uint8_t expected[8] = {0};
        ok = ok && (nxpsc_tmac_compute(&tm_key, mock.uid, sizeof(mock.uid), tmc,
                                       tmi, tmi_len, expected) == NXPSC_OK);
        ok = ok && (memcmp(expected, tmv, sizeof(expected)) == 0);

        // a second, identical transaction: the counter moves, so the value does
        uint8_t tmc2[4] = {0};
        uint8_t tmv2[8] = {0};
        ok = ok && (nxpsc_write_record(card, 0x01, 0, record, sizeof(record), NXPSC_COMM_MAC)
                    == NXPSC_OK);
        ok = ok && (nxpsc_commit_transaction_tmac(card, tmc2, tmv2) == NXPSC_OK);
        ok = ok && (tmc2[0] == 0x02);
        ok = ok && (memcmp(tmv2, tmv, sizeof(tmv)) != 0);

        uint8_t expected2[8] = {0};
        ok = ok && (nxpsc_tmac_compute(&tm_key, mock.uid, sizeof(mock.uid), tmc2,
                                       tmi, tmi_len, expected2) == NXPSC_OK);
        ok = ok && (memcmp(expected2, tmv2, sizeof(expected2)) == 0);

        // a wrong key, a wrong counter or a wrong record all miss
        uint8_t other[8] = {0};
        nxpsc_key_t wrong = tm_key;
        wrong.data[0] ^= 0xFF;
        ok = ok && (nxpsc_tmac_compute(&wrong, mock.uid, sizeof(mock.uid), tmc2,
                                       tmi, tmi_len, other) == NXPSC_OK);
        ok = ok && (memcmp(other, tmv2, sizeof(other)) != 0);
        ok = ok && (nxpsc_tmac_compute(&tm_key, mock.uid, sizeof(mock.uid), tmc,
                                       tmi, tmi_len, other) == NXPSC_OK);
        ok = ok && (memcmp(other, tmv2, sizeof(other)) != 0);

        uint8_t tampered[64] = {0};
        memcpy(tampered, tmi, tmi_len);
        tampered[20] ^= 0x01;
        ok = ok && (nxpsc_tmac_compute(&tm_key, mock.uid, sizeof(mock.uid), tmc2,
                                       tampered, tmi_len, other) == NXPSC_OK);
        ok = ok && (memcmp(other, tmv2, sizeof(other)) != 0);

        // arguments: 7 byte UID, whole blocks of input, AES-128 key, no nulls
        ok = ok && (nxpsc_tmac_compute(&tm_key, mock.uid, 4, tmc, tmi, tmi_len, other)
                    == NXPSC_E_LENGTH);
        ok = ok && (nxpsc_tmac_compute(&tm_key, mock.uid, sizeof(mock.uid), tmc, tmi, 8, other)
                    == NXPSC_E_LENGTH);
        ok = ok && (nxpsc_tmac_compute(NULL, mock.uid, sizeof(mock.uid), tmc, tmi, tmi_len, other)
                    == NXPSC_E_PARAM);
        ok = ok && (nxpsc_tmac_tmi_write_record(0x01, 0, record, sizeof(record),
                                                tmi, 16, &tmi_len) == NXPSC_E_LENGTH);
        ok = ok && (nxpsc_commit_transaction_tmac(card, NULL, tmv) == NXPSC_E_PARAM);
    }

    check("transaction MAC: card and host agree on TMC and TMV", ok);
    nxpsc_close(card);
}

// the derivation itself has known answer vectors in the self test. this is the
// public wrapper over it, which is what callers actually reach for
static void test_diversification_wrapper(void) {
    nxpsc_key_t master;
    memset(&master, 0, sizeof(master));
    master.type = NXPSC_KEY_AES128;
    for (int i = 0; i < 16; i++) {
        master.data[i] = (uint8_t)i;
    }

    static const uint8_t input[8] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    nxpsc_key_t a;
    nxpsc_key_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));

    bool ok = (nxpsc_diversify_an10922(&master, input, sizeof(input), &a) == NXPSC_OK);
    ok = ok && (memcmp(a.data, master.data, 16) != 0);
    ok = ok && (a.type == NXPSC_KEY_AES128);

    // deterministic, and a different input gives a different key
    ok = ok && (nxpsc_diversify_an10922(&master, input, sizeof(input), &b) == NXPSC_OK);
    ok = ok && (memcmp(a.data, b.data, 16) == 0);

    uint8_t other[8];
    memcpy(other, input, sizeof(other));
    other[0] ^= 0xFF;
    ok = ok && (nxpsc_diversify_an10922(&master, other, sizeof(other), &b) == NXPSC_OK);
    ok = ok && (memcmp(a.data, b.data, 16) != 0);

    ok = ok && (nxpsc_diversify_an10922(NULL, input, sizeof(input), &a) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_diversify_an10922(&master, input, sizeof(input), NULL) == NXPSC_E_PARAM);

    check("AN10922 diversification wrapper", ok);
}

// the small helpers both hardware suites lean on to report what happened
static void test_reporting_helpers(void) {
    bool ok = true;

    ok = ok && (strcmp(nxpsc_keytype_str(NXPSC_KEY_DES), "DES") == 0);
    ok = ok && (strcmp(nxpsc_keytype_str(NXPSC_KEY_2K3DES), "2TDEA") == 0);
    ok = ok && (strcmp(nxpsc_keytype_str(NXPSC_KEY_3K3DES), "3TDEA") == 0);
    ok = ok && (strcmp(nxpsc_keytype_str(NXPSC_KEY_AES128), "AES128") == 0);
    ok = ok && (strcmp(nxpsc_keytype_str((nxpsc_keytype_t)99), "unknown") == 0);

    // the statuses this work turned up, which is most of why the table matters
    ok = ok && (strcmp(nxpsc_status_str(0x00), "operation ok") == 0);
    ok = ok && (strstr(nxpsc_status_str(0x7E), "length") != NULL);
    ok = ok && (strstr(nxpsc_status_str(0x1E), "CRC or MAC") != NULL);
    ok = ok && (strstr(nxpsc_status_str(0x9D), "does not allow") != NULL);
    ok = ok && (strstr(nxpsc_status_str(0xAE), "authentication") != NULL);
    ok = ok && (strstr(nxpsc_status_str(0x0E), "eeprom") != NULL);
    ok = ok && (strcmp(nxpsc_status_str(0x0B), "unknown status") == 0);

    ok = ok && (strcmp(nxpsc_strerror(NXPSC_E_AUTH), "authentication error") == 0);
    ok = ok && (strcmp(nxpsc_cardtype_str(DESFIRE_EV3), "DESFire EV3") == 0);

    // and reset_channel puts the handle back where a fresh open leaves it
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);
    ok = ok && (nxpsc_open(&transport, &card) == NXPSC_OK);

    if (ok) {
        card->authenticated = true;
        card->session_lost = true;
        card->channel = NXPSC_CHAN_EV2;
        card->cmd_ctr = 7;

        ok = ok && (nxpsc_active_channel(card) == NXPSC_CHAN_EV2);

        nxpsc_reset_channel(card);
        ok = ok && (nxpsc_is_authenticated(card) == false);
        ok = ok && (nxpsc_active_channel(card) == NXPSC_CHAN_AUTO);
        ok = ok && (nxpsc_active_channel(NULL) == NXPSC_CHAN_AUTO);
        ok = ok && (nxpsc_session_lost(card) == false);
        ok = ok && (card->channel == NXPSC_CHAN_AUTO) && (card->cmd_ctr == 0);

        nxpsc_reset_channel(NULL);      // must not fall over
    }

    check("reporting helpers and channel reset", ok);
    nxpsc_close(card);
}

// The ISO handshake carries one CBC chain across both frames: the IV that
// encrypts RndA || RndB' is the one decrypting RndB left behind. Checking that
// the library and the mock agree proves nothing, because they agreed while both
// were wrong. This builds the expected frame from the primitives instead, and
// asserts the zero IV form is not what goes out.
static void test_ev1_handshake_chains_iv(void) {
    const nxpsc_key_t key = {
        .type = NXPSC_KEY_2K3DES,
        .data = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
    };
    static const uint8_t rnd_b[8] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87};
    uint8_t rnd_a[8];
    for (int i = 0; i < 8; i++) {
        rnd_a[i] = (uint8_t)(0x10 + i);     // what fixed_rng hands out
    }

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV1);
    mock_transport(&mock, &transport);
    mock.auth_scheme = MOCK_AUTH_LEGACY;
    mock.auth_key_type = NXPSC_KEY_2K3DES;
    memcpy(mock.auth_key, key.data, 16);
    memcpy(mock.auth_rnd_b, rnd_b, sizeof(rnd_b));

    nxpsc_set_rng(fixed_rng, NULL);
    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok) {
        mock.tx_count = 0;
        ok = (nxpsc_authenticate(card, 0, &key, NXPSC_CHAN_EV1) == NXPSC_OK);
    }
    nxpsc_set_rng(NULL, NULL);

    if (ok) {
        // AuthenticateISO, then the second frame carrying RndA || RndB'
        ok = ok && (mock.tx_count == 2);
        ok = ok && (mock.tx[0][0] == DF_AUTHENTICATE_ISO) && (mock.tx[0][1] == 0x00);
        ok = ok && (mock.tx[1][0] == DF_ADDITIONAL_FRAME) && (mock.tx_len[1] == 1 + 16);

        // the card enciphered RndB from a zero IV, which leaves the chain at
        // that ciphertext
        uint8_t iv[NXPSC_MAX_BLOCK] = {0};
        uint8_t enc_rnd_b[8] = {0};
        ok = ok && (nxpsc_cbc_crypt_ex(NXPSC_KEY_2K3DES, key.data, iv, rnd_b,
                                       sizeof(rnd_b), enc_rnd_b, true, true) == NXPSC_OK);

        uint8_t rot_b[8];
        memcpy(rot_b, rnd_b, sizeof(rot_b));
        uint8_t first = rot_b[0];
        memmove(rot_b, rot_b + 1, sizeof(rot_b) - 1);
        rot_b[sizeof(rot_b) - 1] = first;

        uint8_t plain[16];
        memcpy(plain, rnd_a, 8);
        memcpy(plain + 8, rot_b, 8);

        // iv now holds the chain, which is what the second frame must use
        uint8_t chained[16] = {0};
        uint8_t chain_iv[NXPSC_MAX_BLOCK];
        memcpy(chain_iv, iv, sizeof(chain_iv));
        ok = ok && (nxpsc_cbc_crypt_ex(NXPSC_KEY_2K3DES, key.data, chain_iv, plain,
                                       sizeof(plain), chained, true, true) == NXPSC_OK);
        ok = ok && (memcmp(&mock.tx[1][1], chained, sizeof(chained)) == 0);

        // and starting over from zero, which is what the bug did, must not be
        // what went out. without this the test passes on the broken behaviour
        uint8_t zero_iv[NXPSC_MAX_BLOCK] = {0};
        uint8_t restarted[16] = {0};
        ok = ok && (nxpsc_cbc_crypt_ex(NXPSC_KEY_2K3DES, key.data, zero_iv, plain,
                                       sizeof(plain), restarted, true, true) == NXPSC_OK);
        ok = ok && (memcmp(chained, restarted, sizeof(chained)) != 0);
        ok = ok && (memcmp(&mock.tx[1][1], restarted, sizeof(restarted)) != 0);
    }

    check("the EV1 handshake chains its IV across the frames", ok);
    nxpsc_close(card);
}

// A (2K3)DES key carries its version in the low bit of every key byte, so what
// the card stores is not what the caller passed. ChangeKey has to normalise
// both keys, because the card XORs the payload against what it stored. Missing
// it on the old key only shows up the second time a key is changed.
static void test_change_key_normalises_versions(void) {
    static const uint8_t session[16] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
    };
    static const uint8_t iv_zero[16] = {0};
    static const uint8_t ti[4] = {0};

    nxpsc_key_t old_key;
    nxpsc_key_t new_key;
    memset(&old_key, 0, sizeof(old_key));
    memset(&new_key, 0, sizeof(new_key));

    old_key.type = NXPSC_KEY_2K3DES;
    new_key.type = NXPSC_KEY_2K3DES;
    for (int i = 0; i < 16; i++) {
        old_key.data[i] = (uint8_t)(0xA0 + i);
        new_key.data[i] = (uint8_t)(0x50 + i);
    }
    // versions that actually disturb the low bits, so a missed normalisation
    // cannot pass by accident
    old_key.version = 0xAA;
    new_key.version = 0x0F;

    mock_card_t mock;
    nxpsc_card_t *card = NULL;
    bool ok = setup_secure_session(&mock, &card, DESFIRE_EV1, NXPSC_CHAN_D40,
                                   NXPSC_KEY_2K3DES, session, session, iv_zero, ti, 0);

    if (ok) {
        card->selected_aid = 0x010203;      // an application, so no key type bits
        card->key_no = 0;                   // authenticated as key 0, changing key 1

        mock.tx_count = 0;
        int ck = nxpsc_change_key(card, 1, &old_key, &new_key);
        ok = ok && (ck == NXPSC_OK);
        ok = ok && (mock.tx[0][0] == DF_CHANGE_KEY) && (mock.tx[0][1] == 0x01);

        // the payload is enciphered with the session key from a zero IV. D40
        // enciphers with the decrypt primitive, so recovering it runs the
        // encrypt one
        uint8_t plain[32] = {0};
        uint8_t iv[NXPSC_MAX_BLOCK] = {0};
        size_t enc_len = mock.tx_len[0] - 2;
        ok = ok && (enc_len == 24);
        if (ok) {
            ok = (nxpsc_cbc_crypt_ex(NXPSC_KEY_2K3DES, session, iv, &mock.tx[0][2],
                                     enc_len, plain, false, true) == NXPSC_OK);
        }

        // what the card will XOR against is both keys with their versions
        // written into the low bits
        uint8_t want_old[16];
        uint8_t want_new[16];
        memcpy(want_old, old_key.data, sizeof(want_old));
        memcpy(want_new, new_key.data, sizeof(want_new));
        nxpsc_des_key_set_version(want_old, NXPSC_KEY_2K3DES, old_key.version);
        nxpsc_des_key_set_version(want_new, NXPSC_KEY_2K3DES, new_key.version);

        uint8_t want_xor[16];
        for (int i = 0; i < 16; i++) {
            want_xor[i] = (uint8_t)(want_new[i] ^ want_old[i]);
        }
        ok = ok && (memcmp(plain, want_xor, sizeof(want_xor)) == 0);

        // leaving the old key as the caller passed it, which is what the bug
        // did, has to give something else
        uint8_t raw_xor[16];
        for (int i = 0; i < 16; i++) {
            raw_xor[i] = (uint8_t)(want_new[i] ^ old_key.data[i]);
        }
        ok = ok && (memcmp(want_xor, raw_xor, sizeof(want_xor)) != 0);
        ok = ok && (memcmp(plain, raw_xor, sizeof(raw_xor)) != 0);

        // the second checksum covers the normalised new key, not the raw one.
        // the legacy channel uses a CRC16 there
        uint8_t crc_new[2] = {0};
        uint8_t crc_raw[2] = {0};
        nxpsc_crc16(want_new, sizeof(want_new), crc_new);
        nxpsc_crc16(new_key.data, sizeof(want_new), crc_raw);
        ok = ok && (memcmp(plain + 16 + 2, crc_new, sizeof(crc_new)) == 0);
        ok = ok && (memcmp(crc_new, crc_raw, sizeof(crc_new)) != 0);
    }

    check("ChangeKey normalises both key versions", ok);
    nxpsc_close(card);
}

// Changing the key the running session was built on takes that key out from
// under it, so the card answers without a MAC. Demanding one turns a key change
// the card carried out into a local length error, which tells the caller the old
// key is still live when it is not. Against the PICC master key that loses the
// card, so it is worth a test that does not need one.
static void test_change_key_ends_session(void) {
    const nxpsc_key_t key = {
        .type = NXPSC_KEY_AES128,
        .data = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F},
    };
    const nxpsc_key_t fresh = {
        .type = NXPSC_KEY_AES128,
        .data = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
                 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF},
    };
    static const uint8_t rnd_b[16] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                                      0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F};

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);
    mock.auth_key_type = NXPSC_KEY_AES128;
    memcpy(mock.auth_key, key.data, sizeof(mock.auth_key));
    memcpy(mock.auth_rnd_b, rnd_b, sizeof(rnd_b));

    nxpsc_set_rng(fixed_rng, NULL);
    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok) {
        card->type = DESFIRE_EV2;
        card->selected_aid = 0x010203;
        ok = (nxpsc_authenticate(card, 0, &key, NXPSC_CHAN_EV2) == NXPSC_OK);
    }

    if (ok) {
        // a key that is not the session key leaves the session alone, and the
        // card MACs the answer as usual
        ok = ok && (nxpsc_change_key_ev2(card, 0, 2, &key, &fresh) == NXPSC_OK);
        ok = ok && nxpsc_is_authenticated(card);

        // the session key itself does not, and the answer carries no MAC
        ok = ok && (nxpsc_change_key(card, 0, &key, &fresh) == NXPSC_OK);
        ok = ok && (nxpsc_is_authenticated(card) == false);
        ok = ok && (mock.secure_active == false);
    }

    // RollKeySet is the same shape for the same reason
    if (ok) {
        ok = ok && (nxpsc_authenticate(card, 0, &key, NXPSC_CHAN_EV2) == NXPSC_OK);
        ok = ok && (nxpsc_roll_key_set(card, 1) == NXPSC_OK);
        ok = ok && (nxpsc_is_authenticated(card) == false);
    }

    nxpsc_set_rng(NULL, NULL);
    check("a key change that ends the session is not a length error", ok);
    nxpsc_close(card);
}

// GetCardUID on an EV2 session carries its MAC. Sent bare, an EV3 answered 0x7E
// and dropped the session, which is where Tessera's terminal first met it: the
// mock used to accept the bare command, so nothing here noticed
static void test_get_card_uid_ev2(void) {
    const nxpsc_key_t key = {
        .type = NXPSC_KEY_AES128,
        .data = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F},
    };
    static const uint8_t rnd_b[16] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                                      0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F};

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);
    mock.auth_key_type = NXPSC_KEY_AES128;
    memcpy(mock.auth_key, key.data, sizeof(mock.auth_key));
    memcpy(mock.auth_rnd_b, rnd_b, sizeof(rnd_b));
    mock.validate_secure_requests = true;

    nxpsc_set_rng(fixed_rng, NULL);
    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok) {
        card->type = DESFIRE_EV2;
        card->selected_aid = 0x010203;
        ok = (nxpsc_authenticate(card, 0, &key, NXPSC_CHAN_EV2) == NXPSC_OK);
    }

    // the library's GetCardUID: MACed, answered, decoded, and the session goes on
    uint8_t uid[16] = {0};
    size_t uid_len = 0;
    ok = ok && (nxpsc_get_card_uid(card, uid, sizeof(uid), &uid_len) == NXPSC_OK);
    ok = ok && (uid_len == 7) && (memcmp(uid, mock.uid, 7) == 0);
    ok = ok && nxpsc_is_authenticated(card);
    ok = ok && (nxpsc_get_card_uid(card, uid, sizeof(uid), &uid_len) == NXPSC_OK);

    // the bare command is the card's length error, and ends the session
    uint8_t resp[32] = {0};
    size_t resp_len = 0;
    ok = ok && (nxpsc_command(card, 0x51, NULL, 0, NXPSC_COMM_PLAIN, NXPSC_COMM_FULL,
                              resp, sizeof(resp), &resp_len) == NXPSC_E_CARD);
    ok = ok && (nxpsc_last_status(card) == 0x7E);
    ok = ok && (mock.secure_active == false);

    nxpsc_set_rng(NULL, NULL);
    check("GetCardUID on an EV2 session carries its MAC", ok);
    nxpsc_close(card);
}

// option 0x00 is one byte carrying four flags, and every call writes all of
// them. the two flag wrapper zeroes the other two, which is the whole reason
// the four flag form exists
static void test_picc_config_flags(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok == false) {
        check("SetConfiguration option 0x00 carries all four flags", false);
        return;
    }
    card->authenticated = true;
    card->channel = NXPSC_CHAN_AUTO;

    nxpsc_picc_config_t config;
    memset(&config, 0, sizeof(config));

    // bit 0 is inverted: set means format stays available
    mock.tx_count = 0;
    ok = ok && (nxpsc_set_picc_config_ex(card, &config) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0x5C) && (mock.tx[0][1] == 0x00) && (mock.tx[0][2] == 0x01);

    config.disable_format = true;
    mock.tx_count = 0;
    ok = ok && (nxpsc_set_picc_config_ex(card, &config) == NXPSC_OK);
    ok = ok && (mock.tx[0][2] == 0x00);

    config.disable_format = false;
    config.random_uid = true;
    config.pc_mandatory = true;
    config.auth_vc_mandatory = true;
    mock.tx_count = 0;
    ok = ok && (nxpsc_set_picc_config_ex(card, &config) == NXPSC_OK);
    ok = ok && (mock.tx[0][2] == (0x01 | 0x02 | 0x04 | 0x08));

    // and the old two flag call still writes zero into the other two
    mock.tx_count = 0;
    ok = ok && (nxpsc_set_picc_config(card, false, true) == NXPSC_OK);
    ok = ok && (mock.tx[0][2] == (0x01 | 0x02));

    ok = ok && (nxpsc_set_picc_config_ex(card, NULL) == NXPSC_E_PARAM);

    check("SetConfiguration option 0x00 carries all four flags", ok);
    nxpsc_close(card);
}

// an error answer inside a session is not a counter problem, the PICC has
// already thrown the session away by the time it sends one
static void test_session_abort_on_card_error(void) {
    const nxpsc_key_t key = {
        .type = NXPSC_KEY_AES128,
        .data = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F},
    };
    static const uint8_t rnd_b[16] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                                      0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F};

    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);
    mock.auth_key_type = NXPSC_KEY_AES128;
    memcpy(mock.auth_key, key.data, sizeof(mock.auth_key));
    memcpy(mock.auth_rnd_b, rnd_b, sizeof(rnd_b));

    nxpsc_set_rng(fixed_rng, NULL);
    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok) {
        card->type = DESFIRE_EV2;
        ok = (nxpsc_authenticate(card, 0, &key, NXPSC_CHAN_EV2) == NXPSC_OK);
    }

    if (ok) {
        mock.validate_secure_requests = true;
        mock.reject_cmd = DF_CHANGE_KEY_SETTINGS;
        mock.reject_status = 0x9D;

        uint8_t settings = 0x0F;
        uint8_t resp[8] = {0};
        size_t resp_len = 0;
        ok = ok && (nxpsc_command(card, DF_CHANGE_KEY_SETTINGS, &settings, 1,
                                  NXPSC_COMM_PLAIN, NXPSC_COMM_PLAIN,
                                  resp, sizeof(resp), &resp_len) == NXPSC_E_CARD);
        ok = ok && (nxpsc_last_status(card) == 0x9D);

        // both sides dropped the session, and ours says so
        ok = ok && (nxpsc_is_authenticated(card) == false);
        ok = ok && nxpsc_session_lost(card);
        ok = ok && (mock.secure_active == false);

        // the next command that needs the session fails locally, without
        // putting a MACed frame on the wire for the card to read as garbage
        size_t before = mock.tx_count;
        uint32_t aids[2] = {0};
        size_t count = 0;
        ok = ok && (nxpsc_get_application_ids(card, aids, 2, &count) == NXPSC_E_AUTH);
        ok = ok && (mock.tx_count == before);

        // authenticating again restores service
        ok = ok && (nxpsc_authenticate(card, 0, &key, NXPSC_CHAN_EV2) == NXPSC_OK);
        ok = ok && (nxpsc_session_lost(card) == false);
        ok = ok && (nxpsc_create_application(card, 0x030201, 0x0F, 1, NXPSC_KEY_AES128) == NXPSC_OK);
        ok = ok && (nxpsc_create_application(card, 0x332211, 0x0F, 1, NXPSC_KEY_AES128) == NXPSC_OK);
        ok = ok && (nxpsc_get_application_ids(card, aids, 2, &count) == NXPSC_OK);
        ok = ok && (count == 2);
        ok = ok && (aids[0] == 0x030201) && (aids[1] == 0x332211);
        ok = ok && (card->cmd_ctr == mock.secure_cmd_ctr);
    }

    nxpsc_set_rng(NULL, NULL);
    check("session dropped after card error", ok);
    nxpsc_close(card);
}



static void test_plus_authentication(void) {
    plus_auth_ctx_t ctx = {
        .key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
        .rnd_b = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                  0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F},
        .ti = {0xDE, 0xAD, 0xBE, 0xEF},
    };
    nxpsc_transport_t transport = {
        .ctx = &ctx,
        .transceive = plus_auth_transceive,
    };
    nxpsc_card_t *card = NULL;
    nxpsc_key_t key = {.type = NXPSC_KEY_AES128};
    memcpy(key.data, ctx.key, sizeof(ctx.key));

    nxpsc_set_rng(fixed_rng, NULL);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_plus_authenticate(card, 0x4000, &key, true) == NXPSC_OK);
    ok = ok && nxpsc_is_authenticated(card);
    nxpsc_close(card);

    ctx.corrupt_final = true;
    card = NULL;
    ok = ok && (nxpsc_open(&transport, &card) == NXPSC_OK);
    ok = ok && (nxpsc_plus_authenticate(card, 0x4000, &key, true) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_is_authenticated(card) == false);
    nxpsc_close(card);

    nxpsc_set_rng(NULL, NULL);
    check("MIFARE Plus auth cryptogram check", ok);
}

static void test_plus_missing_mac(void) {
    plus_read_ctx_t ctx = {
        .payload = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
        .payload_len = 16,
    };
    nxpsc_transport_t transport = {
        .ctx = &ctx,
        .transceive = plus_read_transceive,
    };
    nxpsc_card_t *card = NULL;

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);
    if (ok) {
        card->authenticated = true;
        card->key_type = NXPSC_KEY_AES128;
        card->channel = NXPSC_CHAN_EV2;
        memcpy(card->session_mac, ctx.payload, 16);
        memcpy(card->session_enc, ctx.payload, 16);
        memcpy(card->ti, "\x01\x02\x03\x04", 4);
    }

    uint8_t out[16] = {0};
    size_t out_len = 0;
    ok = ok && (nxpsc_plus_read(card, 0x0004, 1, false, true, out, sizeof(out), &out_len)
                == NXPSC_E_LENGTH);

    check("MIFARE Plus missing MAC rejection", ok);
    nxpsc_close(card);
}

// delegated application management and the configuration wrappers
static void test_delegation_and_config(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, DESFIRE_EV2);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    nxpsc_delegate_info_t info;
    mock.tx_count = 0;
    ok = ok && (nxpsc_get_delegated_info(card, 0x0102, &info) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0x69) && (mock.tx[0][1] == 0x02) && (mock.tx[0][2] == 0x01);
    ok = ok && (info.dam_slot_version == 0x05) && (info.quota_limit == 0x0010);
    ok = ok && (info.free_blocks == 0x0020) && (info.aid == 0x332211);

    const uint8_t enck[32] = {0};
    const uint8_t dam_mac[8] = {0};
    const uint8_t df_name[5] = {'D', 'E', 'M', 'O', '1'};

    mock.tx_count = 0;
    ok = ok && (nxpsc_create_delegated_application(card, 0xF51234, 0x0001, 0x00, 0x0010,
                                                   0x0F, 3, NXPSC_KEY_AES128,
                                                   0x1234, df_name, sizeof(df_name),
                                                   enck, sizeof(enck),
                                                   dam_mac, sizeof(dam_mac)) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xC9);
    ok = ok && (mock.tx[0][1] == 0x34) && (mock.tx[0][3] == 0xF5);   // AID, little endian
    ok = ok && (mock.tx[0][9] == 0x0F);                              // key settings
    ok = ok && (mock.tx[0][10] == 0xA3);                             // AES, ISO, 3 keys
    // 57 payload bytes do not fit one frame, the rest follows as 0xAF
    ok = ok && (mock.tx_count == 2);
    ok = ok && (mock.tx_len[0] == 55) && (mock.tx[1][0] == 0xAF) && (mock.tx_len[1] == 4);

    ok = ok && (nxpsc_create_delegated_application(card, 0, 0, 0, 0, 0, 0, NXPSC_KEY_AES128,
                                                   0, NULL, 0, NULL, 0, NULL, 0)
                == NXPSC_E_PARAM);

    // SetConfiguration wrappers all need a session
    const uint8_t ats[5] = {0x06, 0x75, 0x77, 0x81, 0x02};
    nxpsc_key_t key = {.type = NXPSC_KEY_AES128};
    ok = ok && (nxpsc_set_picc_config(card, true, false) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_set_default_key(card, &key) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_set_ats(card, ats, sizeof(ats)) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_set_ats(card, ats, 0) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_set_ats(NULL, ats, sizeof(ats)) == NXPSC_E_PARAM);

    // the transaction MAC file carries a key, so it needs a session and AES
    nxpsc_access_t access = {.read = 0x01, .write = 0x02, .read_write = 0x02, .change = 0x00};
    nxpsc_key_t des = {.type = NXPSC_KEY_DES};
    ok = ok && (nxpsc_create_transaction_mac_file(card, 0x0F, NXPSC_COMM_FULL, &access,
                                                  &des, 0x00) == NXPSC_E_UNSUPPORTED);
    ok = ok && (nxpsc_create_transaction_mac_file(card, 0x0F, NXPSC_COMM_FULL, &access,
                                                  NULL, 0x00) == NXPSC_E_PARAM);
    // without a session the command degrades to plain, the framing must still hold
    mock.tx_count = 0;
    ok = ok && (nxpsc_create_transaction_mac_file(card, 0x0F, NXPSC_COMM_FULL, &access,
                                                  &key, 0x10) == NXPSC_OK);
    ok = ok && (mock.tx[0][0] == 0xCE) && (mock.tx_len[0] == 23);
    ok = ok && (mock.tx[0][1] == 0x0F) && (mock.tx[0][2] == 0x03);   // file, full mode
    ok = ok && (mock.tx[0][5] == 0x02);                              // TMKeyOption AES
    ok = ok && (mock.tx[0][22] == 0x10);                             // key version

    check("delegated apps and configuration", ok);
    nxpsc_close(card);
}

// the MIFARE Plus commands added on top of the plain read/write set
static void test_plus_extras(void) {
    mock_card_t mock;
    nxpsc_transport_t transport;
    nxpsc_card_t *card = NULL;

    mock_init(&mock, PLUS_EV2);
    mock_transport(&mock, &transport);

    bool ok = (nxpsc_open(&transport, &card) == NXPSC_OK);

    // no session, so the block operations must refuse before touching the card
    ok = ok && (nxpsc_plus_value_transfer(card, 0x04, 10, true, true) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_plus_restore(card, 0x04) == NXPSC_E_AUTH);
    ok = ok && (nxpsc_plus_value_transfer(NULL, 0x04, 10, true, true) == NXPSC_E_PARAM);
    ok = ok && (nxpsc_plus_restore(NULL, 0x04) == NXPSC_E_PARAM);

    // the personalisation level commands work without a session
    mock.tx_count = 0;
    ok = ok && (nxpsc_plus_personalize_uid(card, 0x00) == NXPSC_OK);
    ok = ok && (mock.plus_last_op == 0x40) && (mock.tx_len[0] == 2);

    const uint8_t cfg[4] = {0x01, 0x02, 0x03, 0x04};
    mock.tx_count = 0;
    ok = ok && (nxpsc_plus_set_config_sl1(card, cfg, sizeof(cfg)) == NXPSC_OK);
    ok = ok && (mock.plus_last_op == 0x44) && (mock.tx_len[0] == 1 + sizeof(cfg));
    ok = ok && (nxpsc_plus_set_config_sl1(card, NULL, 4) == NXPSC_E_PARAM);

    uint8_t vc[16] = {0};
    size_t vc_len = 0;
    mock.tx_count = 0;
    ok = ok && (nxpsc_plus_vc_support_last_iso_l3(card, vc, sizeof(vc), &vc_len) == NXPSC_OK);
    ok = ok && (mock.plus_last_op == 0x4B);
    ok = ok && (nxpsc_plus_vc_support_last_iso_l3(card, NULL, 0, &vc_len) == NXPSC_E_PARAM);

    // ResetAuth ends the session on both sides
    mock.tx_count = 0;
    ok = ok && (nxpsc_plus_reset_auth(card) == NXPSC_OK);
    ok = ok && (mock.plus_last_op == 0x78);
    ok = ok && (nxpsc_is_authenticated(card) == false);

    check("MIFARE Plus extras", ok);
    nxpsc_close(card);
}

int main(void) {
    printf("libnxpsc protocol tests\n");

    test_identify();
    test_version_fields();
    test_native_framing();
    test_iso_wrapping();
    test_iso_wrapping_zero_data();
    test_desfire_authentication();
    test_file_settings();
    test_create_file_framing();
    test_value_and_data();
    test_access_roundtrip();
    test_sdm_settings();
    test_plus_perso();
    test_advanced_commands();
    test_proximity_check();
    test_secure_channel_guards();
    test_secure_channel_exact_buffers();
    test_create_application_layout();
    test_legacy_get_card_uid();
    test_get_card_uid_ev2();
    test_legacy_des_degraded_session_key();
    test_info_parsing();
    test_get_df_names_two_apps();
    test_file_management_framing();
    test_data_access_framing();
    test_iso7816_wrappers();
    test_commit_reader_id();
    test_created_files_are_reported();
    test_mock_answers_what_was_written();
    test_ev1_chain_survives_several_commands();
    test_transaction_mac();
    test_diversification_wrapper();
    test_reporting_helpers();
    test_ev1_handshake_chains_iv();
    test_change_key_normalises_versions();
    test_change_key_ends_session();
    test_picc_config_flags();
    test_session_abort_on_card_error();
    test_plus_authentication();
    test_plus_missing_mac();
    test_delegation_and_config();
    test_plus_extras();
    test_guards();

    if (failures > 0) {
        printf("%d test(s) failed\n", failures);
        return 1;
    }

    printf("all protocol tests passed\n");
    return 0;
}
