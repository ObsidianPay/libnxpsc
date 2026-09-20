# EV2 and later extras
<a id="top"></a>

Commands beyond the classic DESFire set: multi issuer card management, MIFARE
Classic mapping, key sets, the relay attack countermeasure, and the two
configuration wrappers. Most of these exist only on EV2 and later, DESFire Light
and DUOX support a subset.

# Table of Contents
- [ISO chaining](#iso-chaining)
- [Transaction MAC files](#transaction-mac-files)
- [Delegated applications](#delegated-applications)
- [MIFARE Classic mapping](#mifare-classic-mapping)
- [Key sets](#key-sets)
- [Proximity check](#proximity-check)
- [Transaction notification](#transaction-notification)
- [Configuration wrappers](#configuration-wrappers)
- [Updating a record in place](#updating-a-record-in-place)

## ISO chaining
^[Top](#top)

EV2 added a second opcode for each file access command, using ISO 7816-4
chaining instead of the native `0xAF` style. Same payload, different opcode:

| Native | ISO chained | Command |
|---|---|---|
| `0xBD` | `0xAD` | ReadData |
| `0x3D` | `0x8D` | WriteData |
| `0xBB` | `0xAB` | ReadRecords |
| `0x3B` | `0x8B` | WriteRecord |
| `0xDB` | `0xBA` | UpdateRecord |

```c
nxpsc_set_iso_chaining(card, true);
```

Turn it on when the reader or middleware cannot do native chaining, and for
files larger than the native length field can address. `nxpsc_ntag424_select()`
enables it automatically, because the DNA tags only expose the chained opcodes.
`nxpsc_get_iso_chaining()` reads the flag back.

## Transaction MAC files
^[Top](#top)

A transaction MAC file makes the card produce a MAC over every committed
transaction, which the back office can verify offline. That is what turns a
value file into an auditable purse.

```c
nxpsc_create_transaction_mac_file(card, file_no, comm, &access, &tm_key, version);
```

The TM key travels enciphered, so the command is always sent in full mode and
needs an open session. During the transaction, `nxpsc_commit_reader_id()` binds
the terminal identity into the MAC and returns the previous reader id,
enciphered.

Committing a transaction can hand back the MAC the card computed:

```c
uint8_t tmc[4], tmv[8];
nxpsc_commit_transaction_tmac(card, tmc, tmv);   // CommitTransaction, option 0x01
```

`tmc` is the transaction counter (4 bytes, LSB first) and `tmv` the 8 byte
transaction MAC value. Plain `nxpsc_commit_transaction()` commits without asking
for either. The card rejects the option if the application has no transaction
MAC file.

The back office verifies the MAC without a card. It rebuilds the transaction MAC
input from the data it expected the terminal to write, and recomputes the value
with the same key the file was created with:

```c
uint8_t tmi[64], expected[8];
size_t tmi_len = 0;
nxpsc_tmac_tmi_write_record(file_no, 0, record, record_len, tmi, sizeof(tmi), &tmi_len);
nxpsc_tmac_compute(&tm_key, uid, 7, tmc, tmi, tmi_len, expected);
// compare expected with the card's tmv in constant time
```

`nxpsc_tmac_compute()` derives the session key from the TM key, the UID and the
counter the card reported, then MACs the input; neither function touches a card.
The counter is passed through exactly as the card reported it. A terminal that
never holds the TM key cannot forge a value, and a value cannot be replayed
because the counter only moves forward.

There are **no published test vectors** for this construction, and no other
implementation computes it to compare against. What the tests prove is that two
independent readings of the data sheet agree, see
[Porting notes](md/Development/Porting_Notes.md). Prove it against a real card
before relying on it.

## Delegated applications
^[Top](#top)

Delegated application management lets a card owner hand a slot of the card to a
second issuer, who can create and manage their own application without the
owner's keys, within a memory quota.

```c
nxpsc_create_delegated_application(card, aid, dam_slot, dam_slot_version,
                                   quota_limit, key_settings, num_keys, key_type,
                                   iso_fid, df_name, df_name_len,
                                   enck, enck_len, dam_mac, dam_mac_len);
nxpsc_get_delegated_info(card, dam_slot, &info);
```

`enck` and `dam_mac` are produced by the DAM authority from its DAM keys, they
are not derived by the library; the card manual defines their construction. The
library sends the application data and the continuation data as one logical
command so the secure messaging state advances once.

`nxpsc_delegate_info_t` returns the slot version, the quota, the free blocks
left in the slot and the AID occupying it.

## MIFARE Classic mapping
^[Top](#top)

EV2 XL and EV3 can expose part of their memory as a MIFARE Classic sector, so
legacy infrastructure keeps working during a migration.

```c
nxpsc_create_mfc_mapping(card, data, len);      // sent enciphered, carries keys
nxpsc_restrict_mfc_update(card, data, len);     // narrows what the Classic side may change
```

Both take the raw payload from the card manual. The layout is card specific and
the library deliberately does not model it.

## Key sets
^[Top](#top)

An application can hold several complete sets of keys and switch between them
atomically, which is how a key rotation happens without a window where half the
estate is broken.

The application has to be built for them. A plain `nxpsc_create_application()`
cannot hold key sets and every command below will be refused on it, so reach for
`nxpsc_create_application_ex()` and give it `num_key_sets`:

```c
nxpsc_app_config_t cfg = {0};
cfg.key_settings = 0x0F;
cfg.num_keys = 3;
cfg.key_type = NXPSC_KEY_AES128;
cfg.num_key_sets = 4;        // sets 0..3, set 0 is the active one
cfg.max_key_size = 16;
nxpsc_create_application_ex(card, aid, &cfg);
```

```c
nxpsc_init_key_set(card, key_set, key_set_settings);     // create the set
nxpsc_change_key_ev2(card, key_set, key_no, old, new);   // fill it
nxpsc_finalize_key_set(card, key_set, key_set_version);  // freeze it
nxpsc_roll_key_set(card, key_set);                       // make it the active one
```

Roll is the switch. Until it is called the new set is inert, so a batch of cards
can be prepared over weeks and cut over in one pass.

The statuses each step answers, and what they mean, are in
[Hardware notes](hardware-notes.md#key-sets).

Three things are easy to get wrong here, all confirmed against EV3:

- the second argument to `nxpsc_init_key_set()` is the new set's **key type**,
  not a key count or a settings byte. It has to match the application. A set
  built as 2TDEA inside an AES application is accepted, then takes 2TDEA shaped
  `nxpsc_change_key_ev2()` payloads and can never be rolled, which is a
  confusing way to lose an afternoon
- `num_key_sets` must be 2 to 16 and `max_key_size` must be 16 or 24. Anything
  else is refused at `CreateApplication` time with `0x9E`
- `key_set_settings` is an access right naming the key allowed to roll:
  `0x00`..`0x0D` a key number, `0x0E` free. Issue `nxpsc_roll_key_set()` under
  any other key and the card answers `0xAE`

The roll swaps out the key the running session was built from, so the card
answers it without a MAC and the session is gone afterwards.
`nxpsc_roll_key_set()` accounts for both and leaves the channel reset, so
authenticate again before carrying on.

## Proximity check
^[Top](#top)

The proximity check measures the round trip time of a random challenge to detect
a relay. It is the reason an attacker cannot simply tunnel a card from another
country into your terminal.

```c
bool mac_ok = false;
nxpsc_proximity_check(card, &pc_key, rounds, &mac_ok);
```

`rounds` has to divide 8, so 1, 2, 4 or 8. `pc_key` is the application's VC
Proximity Key, key `0x21`, not an ordinary application key, and an application
only carries one when it was created with `specific_vc_keys`. Two things will
bite otherwise: the call returns `NXPSC_E_AUTH` with `mac_ok` false rather than
failing loudly, and `PreparePC` leaves the card in proximity check mode where
every other command answers `0x0B` until the field drops. See
[Hardware notes](hardware-notes.md#the-proximity-check).

The library generates the 8 byte challenge, splits it over `rounds` exchanges,
1 to 8, collects the card answers, and computes the AES CMAC, truncated to its
odd bytes, over the interleaved challenge and response. `mac_ok` reports whether
the card's own MAC over the same input matched; it may be NULL if you do not
care. `rounds` of 8 gives the tightest timing resolution.

`PreparePC` ends any open authentication on the card, so the library drops its
side of the session too. Authenticate again afterwards.

## Transaction notification
^[Top](#top)

`nxpsc_notify_transaction_success()` sends `0xEE`, which ECP capable readers use
to tell the card a transaction completed, letting the card update its own state
and a phone show the transaction as done.

## Configuration wrappers
^[Top](#top)

Thin wrappers over `SetConfiguration`, all of which need an authenticated session
with the PICC master key:

| Call | Option | Effect |
|---|---|---|
| `nxpsc_set_picc_config()` | `0x00` | disable `FormatPICC`, enable random UID |
| `nxpsc_set_default_key()` | `0x01` | default key used for keys of applications created later |
| `nxpsc_set_ats()` | `0x02` | replace the ATS the card answers with |

Disabling format and enabling random UID are one way on most cards. Read the
card manual before sending either to a production batch.

## Updating a record in place
^[Top](#top)

```c
nxpsc_update_record(card, file_no, record_no, offset, data, len, comm);
```

Rewrites part of an existing record rather than appending a new one. Record 0 is
the most recent record. As with every record operation, the change only becomes
durable at `nxpsc_commit_transaction()`.

^[Top](#top)
