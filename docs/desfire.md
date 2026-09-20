# Notes on MIFARE DESFire
<a id="top"></a>

How the DESFire family is driven through libnxpsc. The card side facts are in
[the Unofficial DESFire Bible](reference/unofficial_desfire_bible.md), this page
is about the API.

# Table of Contents

- [Documentation](#documentation)
- [Communication channel with a card](#communication-channel-with-a-card)
- [Card architecture](#card-architecture)
- [DESFire Light](#desfire-light)
- [How to](#how-to)
  - [Get the card UID](#get-the-card-uid)
  - [Pick the command set](#pick-the-command-set)
  - [Pick the communication mode](#pick-the-communication-mode)
  - [List applications](#list-applications)
  - [List and dump files](#list-and-dump-files)
  - [Change a key](#change-a-key)
  - [Create an application](#create-an-application)
  - [Create files](#create-files)
  - [Delete files](#delete-files)
  - [Read and write files](#read-and-write-files)
  - [Work with value files](#work-with-value-files)
  - [Work with the transaction MAC](#work-with-the-transaction-mac)
  - [Update a record in place](#update-a-record-in-place)
  - [Switch DESFire Light to LRP mode](#switch-desfire-light-to-lrp-mode)

## Documentation
^[Top](#top)

- ISO/IEC 7816-4 - APDU structure, used by the wrapped and ISO command sets
- ISO/IEC 14443-4 - the block transfer the transport backend must provide
- NXP AN10922 - key diversification
- NXP AN12343 / AN12752 - DESFire Light and LRP
- NXP AN12196 - NTAG 424 DNA, whose command set is DESFire EV2
- NIST SP 800-38B - CMAC

## Communication channel with a card
^[Top](#top)

Three things are chosen independently.

**Command set** - `nxpsc_set_cmdset()`

| Value | Wire format |
|---|---|
| `NXPSC_CMDSET_NATIVE` | raw native frames, `cmd \|\| data` |
| `NXPSC_CMDSET_NATIVE_ISO` | native command wrapped in an ISO 7816-4 APDU, `90 cmd 00 00 00` with no data or `90 cmd 00 00 Lc data 00` when data is present |
| `NXPSC_CMDSET_ISO` | real ISO 7816-4 commands, `SELECT`, `READ BINARY`, `UPDATE BINARY` |

Some backends, PC/SC in particular, cannot send raw native frames at all. Use
`NXPSC_CMDSET_NATIVE_ISO` there, it is understood by every DESFire from EV1 on.

**Secure channel** - the `channel` argument of `nxpsc_authenticate()`

| Value | Command | Applies to |
|---|---|---|
| `NXPSC_CHAN_D40` | `0x0A` | all cards, (2K3)DES keys |
| `NXPSC_CHAN_EV1` | `0x1A` ISO, `0xAA` AES | EV1 and later |
| `NXPSC_CHAN_EV2` | `0x71` first, `0x77` non first | EV2 and later, AES keys |
| `NXPSC_CHAN_LRP` | `0x71` with LRP indicator | DESFire Light, EV2 and later |
| `NXPSC_CHAN_AUTO` | picked from the card type and key type | default |

`NXPSC_CHAN_AUTO` is usually right. It falls back to the legacy channel when the
key is (2K3)DES, which is what the factory PICC master key of an EV2 or EV3 is.

**Communication mode** - per command, or `nxpsc_set_commmode()` for the default

| Value | Meaning |
|---|---|
| `NXPSC_COMM_PLAIN` | no protection |
| `NXPSC_COMM_MAC` | command and answer authenticated |
| `NXPSC_COMM_FULL` | enciphered and authenticated |

The mode a file needs is stored in the file itself, `nxpsc_get_file_settings()`
returns it in `settings.comm`. Reading it first and then using it saves guessing.

## Card architecture
^[Top](#top)

A card holds up to 28 applications, each identified by a 3 byte AID, plus the
PICC level application `0x000000`. Each application holds up to 32 files and up
to 14 keys. Key 0 of the selected application is its master key.

`key_settings` controls what may be changed later. The library passes the byte
through unchanged, so the card manual applies. `0x0F` is the usual permissive
value during personalisation.

Access rights are four 4 bit key numbers, `read`, `write`, `read_write` and
`change`, in `nxpsc_access_t`. `0x0E` means free access, `0x0F` means denied.
`nxpsc_pack_access()` and `nxpsc_unpack_access()` convert to and from the raw
16 bit form the card uses.

## DESFire Light
^[Top](#top)

DESFire Light has a single fixed application, no `CreateApplication`, and boots
in AES mode. It can be switched to LRP, the leakage resilient primitive of
AN12304, which the library implements in full including its own CMAC and
session key derivation. LRP is one way, switching back is not possible.

## How to
^[Top](#top)

All snippets assume `card` came from `nxpsc_open()` with a transport of your own.
Every call returns `NXPSC_OK` or a negative `nxpsc_error_t`; when the card itself
refused, `nxpsc_last_status()` holds its status byte and `nxpsc_status_str()`
names it.

### Get the card UID

`nxpsc_get_card_uid()` returns the UID from the secure `GetCardUID` command when
a session exists. Without a session it falls back to the UID the transport
reported, which is the random UID if the card has random ID enabled.

### Pick the command set

`nxpsc_set_cmdset()` before anything else. `nxpsc_get_cmdset()` reads it back.

### Pick the communication mode

`nxpsc_set_commmode()` sets the default for commands that do not derive one from
a file. File commands take an explicit mode argument.

### List applications

`nxpsc_get_application_ids()` fills an array of AIDs. `nxpsc_get_df_names()`
additionally returns the ISO file id and DF name of applications created with
`nxpsc_create_application_iso()`.

### List and dump files

`nxpsc_get_file_ids()`, then `nxpsc_get_file_settings()` per file, then the read
call that matches `settings.type`: `nxpsc_read_data()`, `nxpsc_get_value()` or
`nxpsc_read_records()`.

### Change a key

`nxpsc_change_key()` needs the old key as well as the new one, because the card
expects the new key XORed with the old whenever the key being changed is not the
one the session was opened with. The library handles the XOR, the per channel
checksum and the DES key version for you.

Changing the key the current session uses invalidates that session. Authenticate
again with the new key before continuing.

`nxpsc_change_key_ev2()` is the key set aware variant for EV2 and later.

### Create an application

`nxpsc_create_application()` for a plain AID, `nxpsc_create_application_iso()`
when the application also needs an ISO file id and DF name, which is what NDEF
and ISO 7816 aware readers look for. The key type given at creation time fixes
the key type of the whole application.

### Create files

- `nxpsc_create_std_file()` - plain data
- `nxpsc_create_backup_file()` - data with transaction support
- `nxpsc_create_value_file()` - a counter with limits, for purses
- `nxpsc_create_record_file()` - linear or cyclic records

### Delete files

`nxpsc_delete_file()`. Space is only reclaimed by `nxpsc_format_picc()`.

### Read and write files

`nxpsc_read_data()` and `nxpsc_write_data()` take an offset and a length and
handle the 0xAF chaining of long transfers internally.

### Work with value files

`nxpsc_get_value()`, `nxpsc_credit()`, `nxpsc_debit()` and
`nxpsc_limited_credit()`. Backup, value and record files only become permanent
after `nxpsc_commit_transaction()`; `nxpsc_abort_transaction()` discards.

### Update a record in place

`nxpsc_update_record()` rewrites part of an existing record, record 0 being the
most recent one, where `nxpsc_write_record()` appends a new one.

### Work with the transaction MAC

Transaction MAC files let a terminal prove a transaction happened. Create one
with `nxpsc_create_transaction_mac_file()`, then finish the transaction with
`nxpsc_commit_transaction_tmac()` to get back the counter and the MAC the card
computed. `nxpsc_commit_reader_id()` additionally binds a reader identity into
it. A back office checks the MAC with `nxpsc_tmac_compute()`, which needs no
card. The transaction MAC session keys are derived by the library. See
[EV2 and later extras](advanced.md#transaction-mac-files).

### Switch DESFire Light to LRP mode

`nxpsc_set_configuration()` with the option and payload from the card manual,
then authenticate with `NXPSC_CHAN_LRP`.

## Beyond the classic command set
^[Top](#top)

Delegated applications, MIFARE Classic mapping, key sets, the proximity check,
ISO chained file access and the `SetConfiguration` wrappers are documented
separately in [EV2 and later extras](advanced.md). Anything not wrapped at all is
still reachable with `nxpsc_command()`, which sends a raw native opcode through
the active secure channel.
