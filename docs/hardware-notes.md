# Hardware notes
^[Top](#top)

Behaviour established against real silicon, not taken from a data sheet. Every
entry here was reached by sending the command to a card and reading what came
back, usually because a reference implementation disagreed with another one or
did not implement the command at all.

The card under test throughout is a DESFire EV3, `hw 33.00 sw 03.00`, production
week 08 of 2024, in factory state. Where a claim is specific to that silicon it
says so.

- [Why this file exists](#why-this-file-exists)
- [Statuses that are not errors](#statuses-that-are-not-errors)
- [A card error ends the session](#a-card-error-ends-the-session)
- [Legacy authentication and the DES degraded key](#legacy-authentication-and-the-des-degraded-key)
- [CreateApplication](#createapplication)
- [The EV1 channel chains its IV through the handshake](#the-ev1-channel-chains-its-iv-through-the-handshake)
- [(2K3)DES key versions live in the key bytes](#2k3des-key-versions-live-in-the-key-bytes)
- [Changing the key you are authenticated with](#changing-the-key-you-are-authenticated-with)
- [Key sets](#key-sets)
- [Key settings](#key-settings)
- [GetDFNames can disable a card](#getdfnames-can-disable-a-card)
- [Records](#records)
- [Files in an ISO application](#files-in-an-iso-application)
- [Transaction MAC files](#transaction-mac-files)
- [Statuses the mock card returns](#statuses-the-mock-card-returns)
- [The proximity check](#the-proximity-check)
- [SetConfiguration](#setconfiguration)
- [NV memory is not reclaimed](#nv-memory-is-not-reclaimed)
- [Reference implementations](#reference-implementations)

## Why this file exists
^[Top](#top)

Several of the behaviours below are not in any reference implementation we could
find, and two of them are places where a reference implementation is wrong. A
developer reading only the code would reasonably assume the opposite of what the
card does, so the reasoning is written down rather than left in commit messages.

## Statuses that are not errors
^[Top](#top)

`0x00` is not the only success. The library also treats `0x90` as one, and the
proximity check depends on it: `PreparePC` answers `0x90` rather than `0x00`, and
the MAC the card returns at the end is computed over that `0x90`. Treating it as
an error stops the exchange before the first round.

`0x0B` is not in the status table and is not a failure of the command that
received it. It means the card is in proximity check mode. See
[The proximity check](#the-proximity-check).

## A card error ends the session
^[Top](#top)

Whenever the PICC answers an in-session command with an error status, it throws
the secure messaging session away. The reader does not find out except by
noticing that everything afterwards fails, and the failures are misleading: the
library kept appending MACs the card then read as trailing garbage, so a command
that was perfectly well formed came back `0x7E`, a length error.

`0x7E` rather than `0x1E` is what identifies this. A stale command counter would
fail the MAC and draw an integrity error; a length error means the card parsed
the frame as a plain command and found extra bytes on the end.

`nxpsc_exchange()` now drops the session on any status that is not `0x00`, `0x90`
or `0xAF`, and any later command that needs the session fails with
`NXPSC_E_AUTH` before anything reaches the wire. `nxpsc_session_lost()` tells a
caller that this is what happened, rather than the card refusing the command.

The practical consequence for callers: a command that draws an expected error,
for example probing whether a file exists, costs the session. Authenticate again
before carrying on.

## Legacy authentication and the DES degraded key
^[Top](#top)

A 2TDEA key whose two halves are equal is a single DES key. DESFire stores both
under the same key type nibble and tells them apart by comparing the halves, so
for such a key it derives the 8 byte DES session key rather than the 16 byte
2TDEA one.

The factory PICC master key is all zero, so this is the common case, not a corner
one. The handshake cannot expose the difference, because 3DES with `K1 == K2` is
single DES and the final check runs against the master key rather than the
session key. The first command on the session is where it shows up, and it shows
up as a decode failure with no obvious cause.

`nxpsc_authenticate()` mirrors the rule. Proxmark3 leaves it to the user, which
is why its documented incantation for a factory card is `-t des` rather than
`-t 2tdea`.

## CreateApplication
^[Top](#top)

The payload, in the order the card wants it:

```
AID(3) KeySett1 KeySett2 [KeySett3] [AKSVersion NoKeySets MaxKeySize AppKeySetSett]
      [ISOFileID(2) ISODFName(1..16)]
```

`KeySett2` bit 4 announces `KeySett3`. `KeySett3` bit 0 announces the four key
set bytes, bit 1 asks for application specific virtual card keys, bit 2 for
specific capability data. The key set block sits **before** the ISO fields, not
after them.

Constraints the card enforces:

| Field | Accepted |
|---|---|
| `NoKeySets` | 2 to 16 |
| `MaxKeySize` | 16 or 24 |
| `AppKeySetSett` | 3 bits, so 0 to 7. `0x0F` is refused with `0x9E` |

`nxpsc_create_application_ex()` reaches all of it. The two older calls are thin
wrappers and frame exactly as they did before.

On the EV3 tested, asking for specific VC keys is refused with `0x9D`: the PICC
does not allow it in its factory configuration. Turning virtual card support on
is a `SetConfiguration` path.

## The EV1 channel chains its IV through the handshake
^[Top](#top)

`AuthenticateISO` and `AuthenticateAES` carry one CBC chain across the whole
handshake. The IV that encrypts `RndA || RndB'` is the one left behind by
decrypting `RndB`, not a fresh zero. The legacy `0x0A` handshake is the
exception: it starts every operation from zero.

Getting that wrong fails in a way that points at the wrong end of the exchange.
Only the first block depends on the IV, and the first block is `RndA`. `RndB'`
sits in the later blocks and arrives intact, so **the card accepts the
authentication and answers `0x00`**, then returns the rotation of an `RndA` it
never really received. The reader sees a good status followed by an `RndA'` it
cannot match and blames its own response handling.

The giveaway is that the second block of the answer decodes correctly while the
first does not, and that `RndA'` bytes 7 to 14 are exactly `RndA` bytes 8 to 15:
that is `rol()` applied to an `RndA` whose first block was corrupted in transit.

## (2K3)DES key versions live in the key bytes
^[Top](#top)

A DES, 2TDEA or 3TDEA key carries its version in the low bit of every key byte,
so the bytes the card stores are not the bytes the caller handed over. Both keys
in a `ChangeKey` have to be put through the same normalisation: the new one
because that is what gets written, and the old one because the card XORs the
payload against what it stored.

Missing it on the old key is invisible until the key is changed a **second**
time. DES treats those bits as parity and ignores them, so authentication with
either form succeeds, and only the next `ChangeKey` fails, with `0x1E`, pointing
at a CRC rather than at a key written three steps earlier.

A single DES key also has to be normalised **before** its two halves are
duplicated. Normalising afterwards leaves the halves differing in their low
bits, and the card then reads the key as 2TDEA rather than DES.

## Changing the key you are authenticated with
^[Top](#top)

Changing the key the running session was built on ends that session, so **the
card answers without a MAC**. Asking for a MACed answer turns a key change the
card carried out into a local `NXPSC_E_LENGTH`, and that is the worst way this
particular command can fail: the key really has changed and the caller has been
told it did not. Aimed at the PICC master key, that is how a card gets lost.

`nxpsc_change_key()` asks for a plain answer and resets the channel whenever the
target is the session's own key. A key in a key set other than the active one is
not the session key, so that case keeps its MAC.

`RollKeySet` fails the same way for the same reason, and is handled the same way.

## Key settings
^[Top](#top)

The bits, from proxmark3's decoder, confirmed on EV3:

| Bit | Set means |
|---|---|
| 0 | the master key can be changed |
| 1 | directory listing and `GetKeySettings` without the master key |
| 2 | create and delete without the master key |
| 3 | the settings themselves can be changed |
| 4-7 | which key may change keys |

Bits 0 and 3 are the ones that matter, because clearing either is irreversible.
Clearing bit 3 freezes the settings byte: every later `ChangeKeySettings` answers
`0x9D`, verified by doing it to a throwaway application. At PICC level that is
also how `FormatPICC` is lost for good, and with it the only way to reclaim
[NV memory](#nv-memory-is-not-reclaimed).

An application locked this way is recovered by deleting it. A PICC locked this
way is not recovered.

Both the PICC key settings and the PICC master key have since been round tripped
on hardware: settings `0x0F` to `0x0B` and back, and the master key from the
factory value to a different 2TDEA key and back, each step read off the card
rather than assumed. Nothing new broke, because the one bug in that path,
[changing the key you are authenticated with](#changing-the-key-you-are-authenticated-with),
had already been found by doing the same thing to an application first. That is
the argument for rehearsing it a level down: the bug it found reports a key
change as failed after the card has carried it out, which against the PICC master
key is how a card is lost.

## Key sets
^[Top](#top)

An application only accepts the key set commands when it was created with
`num_key_sets >= 2`. Before that was reachable the whole feature was dead code,
and the documentation described a workflow nobody could run.

**`InitializeKeySet`'s second byte is the new set's key type**, carried
unshifted, so `0x00` is 2TDEA, `0x01` is 3TDEA and `0x02` is AES. This is the
trap in the whole feature: `0x00` is accepted inside an AES application and
quietly builds a 2TDEA key set, which then takes 2TDEA shaped `ChangeKeyEV2`
payloads and can never be rolled. Everything downstream then looks subtly broken
for reasons that have nothing to do with the command you are debugging.

`ChangeKeyEV2` into a key set works exactly as it does for the active set. AES
keys carry a version byte wherever they are written.

`RollKeySet` takes one byte, the target set. Two bytes answer `0x7E`, and the
active set answers `0x9E` because it is already active. It has to be issued
under the key the `AppKeySetSett` low nibble names; any other key answers `0xAE`.

The roll swaps out the key the running session was built from, so **the card
answers it without a MAC** and the session is gone afterwards. Asking for a MACed
answer turns a command the card carried out into a local length error, which
looks like a refusal and is not one. `nxpsc_roll_key_set()` asks for a plain
answer and resets the channel.

## GetDFNames can disable a card
^[Top](#top)

**Never send GetDFNames while the PICC has a session open.** Measured by the
proxmark3 project on three DESFire EV1 8K cards: with one open, the card answers
the first `0xAF` continuation frame of the chained response with `0xC1`, "PICC
will be disabled", and is dead from then on. Unauthenticated, the identical
frames are answered normally.

EV2 and EV3 dropped the self disabling status codes, so the mistake survives
there. That is what makes it easy to ship: it works on the card in front of you
and destroys the older one in the field.

It is the card's session that matters, not whether the reader MACs the command,
so sending it plain while authenticated is no safer.
`nxpsc_get_df_names()` refuses outright with `NXPSC_E_AUTH` when a session is
open. `SelectApplication` ends the session on the card, so select and then call.

The entries also have to be read one frame at a time. Each frame is one
application, `AID(3) || ISO FID(2) || DF name`, and the name carries no length of
its own, so the frame boundary is the only thing that says where it ends.
Following the `0xAF` chain in one go concatenates them and the entries become
indistinguishable; this library used to do exactly that and reported two
applications as one with a 16 byte name. proxmark3 keeps each frame's length for
the same reason.

## Records
^[Top](#top)

Two things about record files that are easy to get backwards, and a test that
pins only one of them will pass on the wrong behaviour.

A record file holds **one pending record per transaction**. Writing twice before
a commit rewrites the same pending record rather than making two, so two records
means two commits.

Record numbers count back from the newest, so record 0 is the most recently
written. But a **multi record read returns the span oldest first**, so asking for
two records starting at 0 gives the older one first.

## Files in an ISO application
^[Top](#top)

An application created with an ISO file id makes one mandatory for every file
inside it. Asking for a file without one builds a frame two bytes shorter than
the card expects and it answers `0x7E`. The library frames the ISO field when
`iso_fid` is non zero, so it does what it is told; it has no way to know what the
application requires.

## Transaction MAC files
^[Top](#top)

`CommitReaderID` is switched on through the TMAC file's **ReadWrite access
right**, not through a separate option: `0x0F` disables it, `0x0E` is free
access, `0x00` to `0x04` names a key. A TMAC file created with ReadWrite `0x0F`
answers `0x9D` to `CommitReaderID`, which reads like a missing feature and is the
file's own settings refusing it.

`NotifyTransactionSuccess` answers `0x1C` on EV3. The command is not implemented
there.

A `ChangeKey` attempted from a session built on a different key, where the
application's key settings put key changes behind the master key, is refused
with `0xAE` (authentication error), not `0x9D` (permission denied). The status
names the session rather than the access right: the card is saying the key you
are authenticated with is not the one that may do this. `0x9D` is what a file
operation gets when the access rights refuse it.

## Statuses the mock card returns
^[Top](#top)

The mock card (`tests/mockcard.c`) answers some commands with an error status.
Each one below is either something a card has been seen to do, or a reading of
the data sheet that no card has confirmed yet. The second kind are the mock's
guesses, and a guess is a fixed table one level down: a test that passes against
it proves only that the library agrees with the guess. When a hardware run
passes through one of these paths, move the row up and say what was seen.

**Seen on a card**

| Status | When the mock returns it | Evidence |
|---|---|---|
| `0x7E` length error | an authentication frame of the wrong length | this page: a frame the card cannot parse answers `0x7E` |
| `0x1E` integrity error | a command whose MAC does not verify | this page: a stale command counter fails the MAC |
| `0xA0` application not found | SelectApplication of an AID the card does not hold | a personalisation run, 2026-09-21: the station read `0xA0` as "not present" |

**Not yet seen on a card**

| Status | When the mock returns it | Basis |
|---|---|---|
| `0xF0` file not found | ReadData, WriteData, ReadRecords, GetValue, Credit, Debit, LimitedCredit or GetFileSettings on a file the card does not hold | data sheet status table |
| `0xBE` boundary error | ReadData or WriteData past the end of the file; ReadRecords asking for more records than it holds | data sheet status table |
| `0x40` no such key | GetKeyVersion for a key the application does not have | data sheet; see the porting notes on `0x40` |
| `0xA0` application not found | GetKeySettings with no application selected | data sheet; only SelectApplication's `0xA0` has been seen |
| `0x9D` permission denied | CommitTransaction asking for the transaction MAC in an application with no transaction MAC file | the data sheet says only that the command is rejected |
| `0xAE` authentication error | GetCardUID without a session | data sheet; the card has been seen to answer `0xAE` elsewhere (RollKeySet above, ChangeKey below) |

**Not a card behaviour at all**

| Status | When the mock returns it | Why |
|---|---|---|
| `0x9D` permission denied | ReadData or ReadRecords on a file whose contents the mock does not know, because a write reached it enciphered or chained across frames | A card would return the data. This is the mock declining to invent it, so there is nothing for hardware to confirm; the status only has to be an error |

## The proximity check
^[Top](#top)

The exchange runs, the MAC does not verify, and the reason is the key rather than
the construction.

What the card does:

- `PreparePC` answers status `0x90` and four bytes: Option `0x01`, a two byte
  published response time `0x0320`, and PPS1 `0x0A`. **Bit 0 of Option** is what
  says the PPS1 byte is present, not the response length
- the challenge is split evenly across the rounds, so only round counts that
  divide 8 are meaningful
- it is application scoped. At PICC level `PreparePC` answers `0x0B`

The MAC input is `0xFD || Option || pubRespTime || PPS1` followed, per round, by
the card's answer and then ours, with the first byte replaced by `0x90` to check
the card's reply. This matches LogicalAccess byte for byte and is **not** what
needs changing. 456 combinations of truncation, interleaving and header layout
were tried against two captured exchanges without reproducing the card's MAC.

The card MACs with its **VC Proximity Key, key `0x21`** of the application, which
an application only owns when created with specific VC keys. That is refused on a
factory EV3, so the MAC cannot currently be verified on this hardware.
`nxpsc_proximity_check()` reports the mismatch through `mac_ok` rather than
claiming the check passed.

**`PreparePC` leaves the card in proximity check mode**, where every other command
answers `0x0B` until the sequence finishes or the field drops. PC/SC disconnects
leave the card powered, so this outlives the process and poisons the next run.
Reset the card after a proximity check, with `SCardReconnect` and
`SCARD_RESET_CARD` or the equivalent.

## SetConfiguration
^[Top](#top)

Untested against hardware, and deliberately so: disabling `FormatPICC` and
enabling random UID are one way, so a mistake costs the card rather than an
application. What is worth knowing before anyone reaches for it.

**Option `0x00` is a single byte carrying four flags**, not two: format enabled,
random UID, proximity check mandatory, and virtual card authentication
mandatory. Every call writes all four, so there is no way to change one and
leave the rest. Read the card first and pass back what it already had.

`nxpsc_set_picc_config()` only ever wrote two of them and left the other two
zero, which silently turned off the proximity check and virtual card
requirements as a side effect of setting anything else. Given the byte is one
way, that is a single wrong write with no second attempt.
`nxpsc_set_picc_config_ex()` takes all four.

The options. liblogicalaccess implements all seven, and the `ConfigurationOption`
enum in dumacp/smartcard numbers them identically, which is two independent
sources agreeing:

| Option | Carries |
|---|---|
| `0x00` | the four flags above |
| `0x01` | the default key for applications created later |
| `0x02` | the ATS the card answers with |
| `0x03` | SAK |
| `0x04` | D40 and EV1 secure messaging, EV2 chained writing |
| `0x05` | PD capabilities, which liblogicalaccess calls PDCap |
| `0x06` | ISO DF names and the virtual card IID |

Only option `0x00` is known to be one way. The rest look re-settable, but that
has not been confirmed on a card and should not be assumed.

One framing detail if option `0x02` is ever implemented properly: liblogicalaccess
appends a checksum to the ATS payload by hand, CRC16 on a legacy session and
CRC32 over `cmd || option || ats` otherwise, then an `0x80` pad. On the EV1
channel this library's `MODE_ENC` already computes CRC32 over `cmd || payload`,
which is the same bytes, but the EV2 path adds only the padding. Worth checking
against a card before trusting `nxpsc_set_ats()` on anything that matters.

Option `0x06` is the one to look at if the proximity check ever needs finishing,
since the PICC refuses an application with its own VC keys in factory
configuration, and `0x00` carries the two virtual card flags.

## NV memory is not reclaimed
^[Top](#top)

DESFire frees the AID when an application is deleted but not the non volatile
memory behind it. A card that is repeatedly provisioned and wiped keeps losing
free memory until `CreateApplication` starts answering `0x0E`. Measured on EV3, a
run creating one application with six files costs 544 bytes of 5120; partial runs
cost less. `FormatPICC` is the only command that gives it back, and the
`nxpsc_reclaim` example does exactly that.

## Reference implementations
^[Top](#top)

Where they disagree, the card decides. What each one is good for, and see
[Where the protocol knowledge came from](md/Development/Porting_Notes.md) for
licences and the full list:

| Implementation | Covers | Notes |
|---|---|---|
| proxmark3 | Most of the command set | No key set commands. Its file settings decoder is where the TMAC reader id rule came from |
| libfreefare | Legacy and EV1 | No key sets |
| RevK DESFireAES | AES basics | Basic `CreateApplication` only, no ISO fields, no key sets |
| [dumacp/smartcard](https://github.com/dumacp/smartcard) (Go) | EV2 including key sets | Confirms the `CreateApplication` key set block and the key type constants |
| [liblogicalaccess](https://github.com/liblogicalaccess/liblogicalaccess) | EV2 including key sets and the proximity check | The only one with a proximity check. Note `createDelegatedApplicationParam` swaps the meanings of `KeySett3` bits 1 and 2 relative to `createApplication` |
| [springcard-dotnet-libraries](https://github.com/springcard/springcard-dotnet-libraries) | Virtual card and proximity check | Reader manufacturer for this silicon. Its `VerifyPC` MAC input contradicts its own comment, omitting Option and using the measured rather than published response time. The card cannot know a reader's measured time, so the comment is right and the code is not. Licence permits redistribution only with SpringCard hardware, so it is read as a reference and nothing is taken from it |

^[Top](#top)
