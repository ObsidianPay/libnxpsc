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
// libnxpsc - card handle, framing, chaining and identification
//-----------------------------------------------------------------------------

#include "nxpsc_internal.h"

#include <stdlib.h>
#include <string.h>

//-----------------------------------------------------------------------------
// strings
//-----------------------------------------------------------------------------
// baked in when the library is compiled, so a caller linked against a stale
// build sees that version and not the one its own headers declare
const char *nxpsc_version_string(void) {
    return NXPSC_VERSION_STRING;
}

const char *nxpsc_strerror(int rc) {
    switch (rc) {
        case NXPSC_OK:
            return "ok";
        case NXPSC_E_PARAM:
            return "invalid parameter";
        case NXPSC_E_TRANSPORT:
            return "transport error";
        case NXPSC_E_CARD:
            return "card returned an error status";
        case NXPSC_E_CRYPTO:
            return "crypto error";
        case NXPSC_E_AUTH:
            return "authentication error";
        case NXPSC_E_LENGTH:
            return "length error";
        case NXPSC_E_UNSUPPORTED:
            return "not supported";
        case NXPSC_E_MEMORY:
            return "out of memory";
        default:
            break;
    }
    return "unknown error";
}

// status text, merged from libfreefare freefare.h, python-desfire
// desfire_status.py and proxmark3 desfirecore.c
const char *nxpsc_status_str(uint8_t status) {
    switch (status) {
        case 0x00:
            return "operation ok";
        case 0x0C:
            return "no changes done to backup files";
        case 0x0E:
            return "out of eeprom, insufficient NV memory";
        case 0x1C:
            return "command code not supported";
        case 0x1E:
            return "CRC or MAC does not match data, padding bytes invalid";
        case 0x40:
            return "invalid key number specified";
        case 0x7E:
            return "length of command string invalid";
        case 0x9D:
            return "current configuration or status does not allow the command";
        case 0x9E:
            return "value of the parameter(s) invalid";
        case 0xA0:
            return "requested AID not present on PICC";
        case 0xA1:
            return "application integrity error, application will be disabled";
        case 0xAE:
            return "current authentication status does not allow the command";
        case 0xAF:
            return "additional data frame is expected";
        case 0xBE:
            return "attempt to read or write beyond the file or record limits";
        case 0xC1:
            return "PICC integrity error, PICC will be disabled";
        case 0xCA:
            return "previous command was not fully completed";
        case 0xCD:
            return "PICC was disabled by an unrecoverable error";
        case 0xCE:
            return "number of applications limited to 28, no additional applications possible";
        case 0xDE:
            return "file, application or ISO name already exists";
        case 0xEE:
            return "could not complete NV write operation due to loss of power";
        case 0xF0:
            return "specified file number does not exist";
        case 0xF1:
            return "file integrity error, file will be disabled";
        default:
            break;
    }
    return "unknown status";
}

const char *nxpsc_cardtype_str(nxpsc_cardtype_t type) {
    switch (type) {
        case DESFIRE_MF3ICD40:
            return "DESFire MF3ICD40";
        case DESFIRE_EV1:
            return "DESFire EV1";
        case DESFIRE_EV2:
            return "DESFire EV2";
        case DESFIRE_EV2_XL:
            return "DESFire EV2 XL";
        case DESFIRE_EV3:
            return "DESFire EV3";
        case DESFIRE_LIGHT:
            return "DESFire Light";
        case PLUS_EV1:
            return "MIFARE Plus EV1";
        case PLUS_EV2:
            return "MIFARE Plus EV2";
        case NTAG413DNA:
            return "NTAG 413 DNA";
        case NTAG424:
            return "NTAG 424 DNA";
        case DUOX:
            return "MIFARE DUOX";
        case NXP_UNKNOWN:
        default:
            break;
    }
    return "unknown";
}

const char *nxpsc_keytype_str(nxpsc_keytype_t type) {
    switch (type) {
        case NXPSC_KEY_DES:
            return "DES";
        case NXPSC_KEY_2K3DES:
            return "2TDEA";
        case NXPSC_KEY_3K3DES:
            return "3TDEA";
        case NXPSC_KEY_AES128:
            return "AES128";
        case NXPSC_KEY_AES256:
            return "AES256";
        default:
            break;
    }
    return "unknown";
}

//-----------------------------------------------------------------------------
// life cycle
//-----------------------------------------------------------------------------
int nxpsc_open(const nxpsc_transport_t *transport, nxpsc_card_t **out) {
    if (transport == NULL || transport->transceive == NULL || out == NULL) {
        return NXPSC_E_PARAM;
    }

    nxpsc_card_t *card = calloc(1, sizeof(nxpsc_card_t));
    if (card == NULL) {
        return NXPSC_E_MEMORY;
    }

    card->transport = *transport;
    card->cmdset = NXPSC_CMDSET_NATIVE;
    card->channel = NXPSC_CHAN_AUTO;
    card->default_comm = NXPSC_COMM_PLAIN;
    card->type = NXP_UNKNOWN;

    if (card->transport.get_uid != NULL) {
        size_t len = 0;
        if (card->transport.get_uid(card->transport.ctx, card->uid, sizeof(card->uid), &len) == NXPSC_OK) {
            card->uid_len = (len <= sizeof(card->uid)) ? len : sizeof(card->uid);
        }
    }

    *out = card;
    return NXPSC_OK;
}

void nxpsc_close(nxpsc_card_t *card) {
    if (card == NULL) {
        return;
    }
    // key material must not linger in the heap
    nxpsc_secure_zero(card, sizeof(*card));
    free(card);
}

void nxpsc_reset_channel(nxpsc_card_t *card) {
    if (card == NULL) {
        return;
    }

    card->channel = NXPSC_CHAN_AUTO;
    card->authenticated = false;
    card->session_lost = false;
    card->cmd_ctr = 0;
    memset(card->ti, 0, sizeof(card->ti));
    memset(card->iv, 0, sizeof(card->iv));
    memset(card->session_enc, 0, sizeof(card->session_enc));
    memset(card->session_mac, 0, sizeof(card->session_mac));
}

uint8_t nxpsc_last_status(const nxpsc_card_t *card) {
    return (card != NULL) ? card->last_status : 0xFF;
}

void nxpsc_set_cmdset(nxpsc_card_t *card, nxpsc_cmdset_t cmdset) {
    if (card != NULL) {
        card->cmdset = cmdset;
    }
}

nxpsc_cmdset_t nxpsc_get_cmdset(const nxpsc_card_t *card) {
    return (card != NULL) ? card->cmdset : NXPSC_CMDSET_NATIVE;
}

void nxpsc_set_commmode(nxpsc_card_t *card, nxpsc_commmode_t mode) {
    if (card != NULL) {
        card->default_comm = mode;
    }
}

bool nxpsc_is_authenticated(const nxpsc_card_t *card) {
    return (card != NULL && card->authenticated);
}

nxpsc_channel_t nxpsc_active_channel(const nxpsc_card_t *card) {
    return (card != NULL) ? card->channel : NXPSC_CHAN_AUTO;
}

bool nxpsc_session_lost(const nxpsc_card_t *card) {
    return (card != NULL && card->session_lost);
}

// the PICC aborts secure messaging whenever it answers a command inside a
// session with an error, so everything but a success or a continuation frame
// leaves the reader talking to a card that has already thrown the session away
bool nxpsc_status_ends_session(uint8_t status) {
    return (status != DF_S_OK && status != DF_S_SIGNATURE && status != DF_S_ADDITIONAL_FRAME);
}

uint32_t nxpsc_selected_aid(const nxpsc_card_t *card) {
    return (card != NULL) ? card->selected_aid : 0;
}

size_t nxpsc_mac_length(const nxpsc_card_t *card) {
    switch (card->channel) {
        case NXPSC_CHAN_D40:
            return 4;
        case NXPSC_CHAN_EV1:
            return 8;
        case NXPSC_CHAN_EV2:
        case NXPSC_CHAN_LRP:
            return 8;
        default:
            break;
    }
    return 0;
}

size_t nxpsc_padded_len(size_t len, size_t block) {
    if (block == 0) {
        return len;
    }
    return ((len / block) + ((len % block) ? 1 : 0)) * block;
}

nxpsc_mode_t nxpsc_mode_from_public(nxpsc_commmode_t comm) {
    switch (comm) {
        case NXPSC_COMM_MAC:
            return MODE_MAC;
        case NXPSC_COMM_FULL:
            return MODE_ENC;
        case NXPSC_COMM_PLAIN:
        default:
            break;
    }
    return MODE_PLAIN;
}

//-----------------------------------------------------------------------------
// framing
//-----------------------------------------------------------------------------
static int transceive(nxpsc_card_t *card, const uint8_t *tx, size_t tx_len,
                      uint8_t *rx, size_t rx_cap, size_t *rx_len) {
    int rc = card->transport.transceive(card->transport.ctx, tx, tx_len, rx, rx_cap, rx_len);
    if (rc != NXPSC_OK) {
        return rc;
    }
    if (*rx_len == 0) {
        return NXPSC_E_TRANSPORT;
    }
    return NXPSC_OK;
}

// one native frame, either raw or wrapped in an ISO 7816-4 APDU
static int frame_exchange(nxpsc_card_t *card, uint8_t cmd, const uint8_t *data, size_t len,
                          uint8_t *status, uint8_t *resp, size_t cap, size_t *resp_len) {
    uint8_t tx[NXPSC_MAX_APDU];
    uint8_t rx[NXPSC_MAX_APDU];
    size_t tx_len = 0;
    size_t rx_len = 0;

    if (len > NXPSC_MAX_APDU - 6) {
        return NXPSC_E_LENGTH;
    }

    if (card->cmdset == NXPSC_CMDSET_NATIVE_ISO || card->cmdset == NXPSC_CMDSET_ISO) {
        tx[tx_len++] = ISO_CLA_WRAP;
        tx[tx_len++] = cmd;
        tx[tx_len++] = 0x00;
        tx[tx_len++] = 0x00;
        if (len > 0) {
            tx[tx_len++] = (uint8_t)len;
            memcpy(tx + tx_len, data, len);
            tx_len += len;
        }
        tx[tx_len++] = 0x00;
    } else {
        tx[tx_len++] = cmd;
        if (len > 0) {
            memcpy(tx + tx_len, data, len);
            tx_len += len;
        }
    }

    int rc = transceive(card, tx, tx_len, rx, sizeof(rx), &rx_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    if (card->cmdset == NXPSC_CMDSET_NATIVE_ISO || card->cmdset == NXPSC_CMDSET_ISO) {
        if (rx_len < 2) {
            return NXPSC_E_LENGTH;
        }
        // 91 XX carries the native status in SW2
        if (rx[rx_len - 2] != 0x91) {
            return NXPSC_E_CARD;
        }
        *status = rx[rx_len - 1];
        rx_len -= 2;

        if (rx_len > cap) {
            return NXPSC_E_LENGTH;
        }
        if (rx_len > 0) {
            memcpy(resp, rx, rx_len);
        }
        *resp_len = rx_len;
        return NXPSC_OK;
    }

    *status = rx[0];
    if (rx_len - 1 > cap) {
        return NXPSC_E_LENGTH;
    }
    if (rx_len > 1) {
        memcpy(resp, rx + 1, rx_len - 1);
    }
    *resp_len = rx_len - 1;
    return NXPSC_OK;
}

int nxpsc_raw_exchange_ex(nxpsc_card_t *card, uint8_t cmd, const uint8_t *data, size_t len,
                          uint8_t *status, uint8_t *resp, size_t cap, size_t *resp_len,
                          bool follow_af) {
    if (card == NULL || status == NULL || resp == NULL || resp_len == NULL) {
        return NXPSC_E_PARAM;
    }

    *resp_len = 0;

    size_t sent = 0;
    size_t total = 0;
    uint8_t chunk[NXPSC_MAX_APDU];
    int rc;

    // command chaining out, every follow up frame is an AdditionalFrame
    do {
        size_t take = len - sent;
        uint8_t frame_cmd = (sent == 0) ? cmd : DF_ADDITIONAL_FRAME;
        if (take > NXPSC_TX_FRAME_MAX) {
            take = NXPSC_TX_FRAME_MAX;
        }

        size_t got = 0;
        rc = frame_exchange(card, frame_cmd, (take > 0) ? data + sent : NULL, take,
                            status, chunk, sizeof(chunk), &got);
        if (rc != NXPSC_OK) {
            return rc;
        }
        sent += take;

        if (sent < len) {
            // the card acknowledges every intermediate frame with 0xAF
            if (*status != DF_S_ADDITIONAL_FRAME) {
                card->last_status = *status;
                return NXPSC_E_CARD;
            }
            continue;
        }

        if (total + got > cap) {
            return NXPSC_E_LENGTH;
        }
        memcpy(resp + total, chunk, got);
        total += got;
    } while (sent < len);

    // response chaining in
    while (follow_af && *status == DF_S_ADDITIONAL_FRAME) {
        size_t got = 0;
        rc = frame_exchange(card, DF_ADDITIONAL_FRAME, NULL, 0, status, chunk, sizeof(chunk), &got);
        if (rc != NXPSC_OK) {
            return rc;
        }

        if (total + got > cap) {
            return NXPSC_E_LENGTH;
        }
        memcpy(resp + total, chunk, got);
        total += got;
    }

    *resp_len = total;
    card->last_status = *status;
    return NXPSC_OK;
}

int nxpsc_raw_exchange(nxpsc_card_t *card, uint8_t cmd, const uint8_t *data, size_t len,
                       uint8_t *status, uint8_t *resp, size_t cap, size_t *resp_len) {
    return nxpsc_raw_exchange_ex(card, cmd, data, len, status, resp, cap, resp_len, true);
}

int nxpsc_exchange(nxpsc_card_t *card, uint8_t cmd, const uint8_t *data, size_t len,
                   nxpsc_mode_t tx_mode, nxpsc_mode_t rx_mode,
                   uint8_t *resp, size_t cap, size_t *resp_len) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t *wrapped = calloc(NXPSC_MAX_RESPONSE, 1);
    uint8_t *raw = calloc(NXPSC_MAX_RESPONSE, 1);
    if (wrapped == NULL || raw == NULL) {
        free(wrapped);
        free(raw);
        return NXPSC_E_MEMORY;
    }

    size_t wrapped_len = 0;
    uint8_t status = 0;
    size_t raw_len = 0;

    card->mode = tx_mode;
    card->mac_mismatch = false;

    // the card dropped the session under us, a MACed or enciphered frame would
    // only be read as trailing garbage. say so here instead of on the wire
    if (card->session_lost && (tx_mode != MODE_PLAIN || rx_mode != MODE_PLAIN)) {
        free(wrapped);
        free(raw);
        if (resp_len != NULL) {
            *resp_len = 0;
        }
        return NXPSC_E_AUTH;
    }

    int rc = nxpsc_channel_encode(card, cmd, data, len, wrapped, NXPSC_MAX_RESPONSE, &wrapped_len);
    if (rc == NXPSC_OK) {
        rc = nxpsc_raw_exchange(card, cmd, wrapped, wrapped_len, &status, raw, NXPSC_MAX_RESPONSE, &raw_len);
    }

    if (rc == NXPSC_OK && nxpsc_status_ends_session(status)) {
        if (card->authenticated) {
            nxpsc_reset_channel(card);
            card->session_lost = true;
        }
        rc = NXPSC_E_CARD;
    } else if (rc == NXPSC_OK && status != DF_S_ADDITIONAL_FRAME && card->authenticated &&
               (card->channel == NXPSC_CHAN_EV2 || card->channel == NXPSC_CHAN_LRP)) {
        // only a command the PICC actually carried out advances the counter,
        // and the response MAC is computed over the advanced value
        card->cmd_ctr++;
    }

    if (rc == NXPSC_OK) {
        // the card may downgrade an encrypted request to a mac only answer
        card->mode = rx_mode;
        size_t out_len = 0;
        rc = nxpsc_channel_decode(card, raw, raw_len, status, resp, cap, &out_len);
        if (rc == NXPSC_OK && resp_len != NULL) {
            *resp_len = out_len;
        }
    } else if (resp_len != NULL) {
        *resp_len = 0;
    }

    free(wrapped);
    free(raw);
    return rc;
}

int nxpsc_iso_exchange(nxpsc_card_t *card, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                       const uint8_t *data, size_t len, bool le_present, size_t le,
                       uint8_t *resp, size_t cap, size_t *resp_len, uint16_t *sw) {
    if (card == NULL || (len > 0 && data == NULL)) {
        return NXPSC_E_PARAM;
    }

    if (len > 255 || le > 256) {
        return NXPSC_E_LENGTH;
    }

    uint8_t tx[NXPSC_MAX_APDU];
    uint8_t rx[NXPSC_MAX_APDU];
    size_t tx_len = 0;
    size_t rx_len = 0;

    tx[tx_len++] = cla;
    tx[tx_len++] = ins;
    tx[tx_len++] = p1;
    tx[tx_len++] = p2;

    if (len > 0) {
        tx[tx_len++] = (uint8_t)len;
        memcpy(tx + tx_len, data, len);
        tx_len += len;
    }

    if (le_present) {
        tx[tx_len++] = (le == 256) ? 0x00 : (uint8_t)le;
    }

    int rc = transceive(card, tx, tx_len, rx, sizeof(rx), &rx_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    if (rx_len < 2) {
        return NXPSC_E_LENGTH;
    }

    uint16_t status = (uint16_t)((rx[rx_len - 2] << 8) | rx[rx_len - 1]);
    if (sw != NULL) {
        *sw = status;
    }
    card->last_status = rx[rx_len - 1];
    rx_len -= 2;

    if (rx_len > cap) {
        return NXPSC_E_LENGTH;
    }
    if (rx_len > 0 && resp != NULL) {
        memcpy(resp, rx, rx_len);
    }
    if (resp_len != NULL) {
        *resp_len = rx_len;
    }

    if (status != 0x9000 && (status & 0xFF00) != 0x9100 && (status & 0xFF00) != 0x6100) {
        return NXPSC_E_CARD;
    }
    return NXPSC_OK;
}

int nxpsc_command(nxpsc_card_t *card, uint8_t cmd, const uint8_t *data, size_t len,
                  nxpsc_commmode_t tx_mode, nxpsc_commmode_t rx_mode,
                  uint8_t *resp, size_t cap, size_t *resp_len) {
    return nxpsc_exchange(card, cmd, data, len, nxpsc_mode_from_public(tx_mode),
                          nxpsc_mode_from_public(rx_mode), resp, cap, resp_len);
}

//-----------------------------------------------------------------------------
// identification
//-----------------------------------------------------------------------------
nxpsc_cardtype_t nxpsc_card_type_from_version(uint8_t type, uint8_t major, uint8_t minor) {
    if (type == 0x01 && major == 0x00 && minor == 0x02) {
        return DESFIRE_MF3ICD40;
    }
    if (type == 0x01 && major == 0x01 && minor == 0x00) {
        return DESFIRE_EV1;
    }
    if (type == 0x01 && major == 0x12 && minor == 0x00) {
        return DESFIRE_EV2;
    }
    if (type == 0x01 && major == 0x22 && minor == 0x00) {
        return DESFIRE_EV2_XL;
    }
    if (type == 0x01 && major == 0x33 && minor == 0x00) {
        return DESFIRE_EV3;
    }
    if (type == 0x81 && major == 0x43 && minor == 0x01) {
        return DESFIRE_EV3;
    }
    if (type == 0x01 && major == 0xA0 && minor == 0x00) {
        return DUOX;
    }
    if (type == 0x08 && major == 0x30 && minor == 0x00) {
        return DESFIRE_LIGHT;
    }
    // combo card DESFire / EMV
    if (type == 0x81 && major == 0x42 && minor == 0x00) {
        return DESFIRE_EV2;
    }
    // Apple wallet DESFire applet, v62.0 and v62.1 seen in the field
    if (type == 0x91 && major == 0x62 && (minor == 0x01 || minor == 0x00)) {
        return DESFIRE_EV2;
    }
    if (type == 0x02 && major == 0x11 && minor == 0x00) {
        return PLUS_EV1;
    }
    if (type == 0x02 && major == 0x22 && minor == 0x00) {
        return PLUS_EV2;
    }
    if (major == 0x10 && minor == 0x00) {
        return NTAG413DNA;
    }
    if (type == 0x04 && major == 0x30 && minor == 0x00) {
        return NTAG424;
    }
    return NXP_UNKNOWN;
}

int nxpsc_get_version(nxpsc_card_t *card, nxpsc_version_t *version) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[64] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_exchange(card, DF_GET_VERSION, NULL, 0, MODE_PLAIN,
                            card->authenticated ? MODE_MAC : MODE_PLAIN,
                            resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    // 7 bytes hw + 7 bytes sw + 14 (or 16) bytes production information
    if (resp_len < 28) {
        return NXPSC_E_LENGTH;
    }

    nxpsc_version_t v;
    memset(&v, 0, sizeof(v));

    v.hw_vendor = resp[0];
    v.hw_type = resp[1];
    v.hw_subtype = resp[2];
    v.hw_major = resp[3];
    v.hw_minor = resp[4];
    v.hw_storage = resp[5];
    v.hw_protocol = resp[6];

    v.sw_vendor = resp[7];
    v.sw_type = resp[8];
    v.sw_subtype = resp[9];
    v.sw_major = resp[10];
    v.sw_minor = resp[11];
    v.sw_storage = resp[12];
    v.sw_protocol = resp[13];

    memcpy(v.uid, resp + 14, 7);
    memcpy(v.batch, resp + 21, 5);
    v.week = resp[26];
    v.year = resp[27];
    v.has_batch_extra = (resp_len >= 30);

    card->version = v;
    card->version_read = true;
    card->type = nxpsc_card_type_from_version(v.hw_type, v.hw_major, v.hw_minor);

    if (card->uid_len == 0) {
        memcpy(card->uid, v.uid, 7);
        card->uid_len = 7;
    }

    if (version != NULL) {
        *version = v;
    }
    return NXPSC_OK;
}

int nxpsc_identify(nxpsc_card_t *card, nxpsc_cardtype_t *type) {
    if (card == NULL) {
        return NXPSC_E_PARAM;
    }

    if (card->version_read == false) {
        int rc = nxpsc_get_version(card, NULL);
        if (rc != NXPSC_OK) {
            return rc;
        }
    }

    if (type != NULL) {
        *type = card->type;
    }
    return NXPSC_OK;
}

nxpsc_cardtype_t nxpsc_card_type(const nxpsc_card_t *card) {
    return (card != NULL) ? card->type : NXP_UNKNOWN;
}

int nxpsc_get_card_uid(nxpsc_card_t *card, uint8_t *uid, size_t cap, size_t *len) {
    if (card == NULL || uid == NULL || len == NULL) {
        return NXPSC_E_PARAM;
    }

    if (card->authenticated == false) {
        // GetCardUID needs a secure channel, fall back to the transport UID
        if (card->uid_len == 0) {
            return NXPSC_E_AUTH;
        }
        if (card->uid_len > cap) {
            return NXPSC_E_LENGTH;
        }
        memcpy(uid, card->uid, card->uid_len);
        *len = card->uid_len;
        return NXPSC_OK;
    }

    uint8_t resp[32] = {0};
    size_t resp_len = 0;

    // on EV2 and LRP a command carries its MAC even with no data, and an EV3
    // answers a bare 51 with 0x7E, seen on a card. the earlier channels send it
    // bare, which is what the D40 path was verified with
    nxpsc_mode_t tx_mode = (card->channel == NXPSC_CHAN_EV2 || card->channel == NXPSC_CHAN_LRP)
                           ? MODE_MAC : MODE_PLAIN;
    int rc = nxpsc_exchange(card, DF_GET_CARD_UID, NULL, 0, tx_mode, MODE_ENC,
                            resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    if (resp_len < 7) {
        return NXPSC_E_LENGTH;
    }
    if (cap < 7) {
        return NXPSC_E_LENGTH;
    }

    memcpy(uid, resp, 7);
    *len = 7;

    memcpy(card->uid, resp, 7);
    card->uid_len = 7;
    return NXPSC_OK;
}

int nxpsc_get_free_memory(nxpsc_card_t *card, uint32_t *bytes) {
    if (card == NULL || bytes == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t resp[16] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_exchange(card, DF_GET_FREE_MEMORY, NULL, 0, MODE_PLAIN,
                            card->authenticated ? MODE_MAC : MODE_PLAIN,
                            resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    if (resp_len < 3) {
        return NXPSC_E_LENGTH;
    }

    *bytes = (uint32_t)resp[0] | ((uint32_t)resp[1] << 8) | ((uint32_t)resp[2] << 16);
    return NXPSC_OK;
}

int nxpsc_get_signature(nxpsc_card_t *card, uint8_t *sig, size_t cap, size_t *len) {
    if (card == NULL || sig == NULL || len == NULL) {
        return NXPSC_E_PARAM;
    }

    uint8_t param = 0x00;
    uint8_t resp[128] = {0};
    size_t resp_len = 0;

    int rc = nxpsc_exchange(card, DF_READ_SIG, &param, 1, MODE_PLAIN,
                            card->authenticated ? MODE_MAC : MODE_PLAIN,
                            resp, sizeof(resp), &resp_len);
    if (rc != NXPSC_OK) {
        return rc;
    }

    if (resp_len > cap) {
        return NXPSC_E_LENGTH;
    }

    memcpy(sig, resp, resp_len);
    *len = resp_len;
    return NXPSC_OK;
}
