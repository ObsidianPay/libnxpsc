# Where the protocol knowledge came from
<a id="top"></a>

libnxpsc was written by cross referencing independent implementations. This page
records what each contributed, where they disagree, and which side won.

The first four below carried the classic command set. The last three were added
later, when hardware testing reached commands none of the first four implement:
key sets and the proximity check. Where every reference is silent, the card
decides, and what it decided is in [Hardware notes](../../hardware-notes.md).

| Project | Language | Licence | Used for |
|---|---|---|---|
| [proxmark3](https://github.com/RfidResearchGroup/proxmark3) | C | GPLv3 | primary reference. EV2 and LRP secure messaging, ChangeKey rules, transaction MAC, SDM, MIFARE Plus SL3, and the known answer test vectors |
| [libfreefare](https://github.com/nfc-tools/libfreefare) | C | LGPLv3 with linking exception | legacy D40 and EV1 command formats, file and application semantics, the shape of a usable DESFire API |
| [python-desfire](https://github.com/waza-ari/python-desfire) | Python | MIT | independent check on command payloads and status handling |
| [DESFireAES](https://codeberg.org/RevK/DESFireAES) | C | GPLv3 | independent check on AES session key derivation and CMAC handling |
| [liblogicalaccess](https://github.com/liblogicalaccess/liblogicalaccess) | C++ | LGPLv3 | the only reference implementing the proximity check. Also the `CreateApplication` KeySett3 bits, the `InitializeKeySet` key type byte, and the three bit width of `AppKeySetSett` |
| [dumacp/smartcard](https://github.com/dumacp/smartcard) | Go | Apache 2.0 | independent confirmation of the `CreateApplication` key set block, field for field, and the key type constants 2TDEA 0, 3TDEA 1, AES 2 |
| [springcard-dotnet-libraries](https://github.com/springcard/springcard-dotnet-libraries) | C# | SpringCard proprietary, see below | virtual card selection and the proximity check. SpringCard build readers for this silicon, so their handling of `PreparePC` answering `0x90` carries weight |

The implementation in this repository is new code, written against these
references rather than copied from them; the parts closest in structure follow
the proxmark3 implementation, which is GPLv3, as is this library.

The SpringCard licence permits redistribution of their source only for use with
SpringCard hardware. Nothing from it is redistributed here. It was read to learn
what the card does, the same way a data sheet would be, and the behaviour it
described was then confirmed against a card before anything was written.

## Disagreements found while cross referencing

- **AuthenticateEV2NonFirst opcode.** python-desfire uses `0x72`. The correct
  value is `0x77`; `0x72` is the MIFARE Plus AuthenticateContinue. The other
  three implementations agree on `0x77`.
- **Status `0x40`.** DESFireAES labels it as a generic error. It is
  `NO_SUCH_KEY`.
- **AN10922 key version.** An early version of this library applied the DES key
  version to the *derived* key. It must not be: the version is a property of the
  key as loaded into the card, not part of the derivation. The known answer
  vectors caught it.
- **ChangeKey checksums.** The three legacy behaviours differ and all are real:
  D40 appends CRC16 over the payload, and a second CRC16 over the new key when
  the key being changed is not the session key; EV1 appends CRC32 over
  `cmd || keyno || payload` plus a CRC32 over the new key in the same case;
  EV2 and LRP append only the CRC32 over the new key.
- **Single DES on the wire.** A single DES key travels as a 2K3DES key with both
  halves equal. libfreefare makes this explicit, the others hide it.
- **PICC master key type.** Encoded in the top bits of the key number byte, not
  in a separate field.
- **`VerifyPC` MAC input.** SpringCard's comment quotes the spec as
  `VPC || Option || pubRespTime || PPS1 || pairs`, and the code below it omits
  Option and uses the *measured* response time instead of the published one. The
  card cannot know a reader's measured time, so the comment is right and the code
  is not. liblogicalaccess implements the comment, and this library follows it.
- **KeySett3 bit meanings.** liblogicalaccess assigns bit 1 to specific VC keys
  and bit 2 to specific capability data in `createApplication`, and swaps the two
  in `createDelegatedApplicationParam`. Only one can be right; this library
  follows `createApplication`, which is the path that was exercised on hardware.
- **Transaction MAC: nothing to cross reference against.** proxmark3 builds the
  same SV1 for the transaction MAC session key (`DesfireGenTransSessionKeyEV2`,
  citing MF2DLHX0 page 42), and this library agrees with it byte for byte. That
  is where the agreement ends: proxmark3 never accumulates a TMI and never
  computes a TMV, it only prints the TMC and TMV the card returned. libfreefare,
  python-desfire and DESFireAES predate the feature. So the TMI layouts in
  `nxpsc_tmac_tmi_write_record` come from the MF2DL(H)x0 data sheet rev 3.3
  section 10.3.4.2 alone, with no second implementation to check them against.
  The mock card's side (`tests/mockcard.c`) is written separately from the same
  section for exactly that reason: a test where both sides came from one
  function would only prove the function agrees with itself.
- **Where all four originals are silent.** None of proxmark3, libfreefare,
  python-desfire or DESFireAES implements the key set commands, and only
  SpringCard and liblogicalaccess implement the proximity check. Both areas were
  wrong in this library until they were tested against a card, because there was
  nothing to cross reference them against.

## Gap analysis against the references

Every DESFire opcode that proxmark3 defines is implemented or wrapped here,
including the ones proxmark3 itself only defines: delegated application
management, MIFARE Classic mapping, `RestrictMFCUpdate` and
`NotifyTransactionSuccess`. The MIFARE Plus command table is likewise complete
for security level 3 plus the SL0 and SL1 personalisation commands.

Where a command's payload is entirely card specific, the library takes a raw
buffer rather than pretending to understand it. Those are marked "payload per
card manual" in the header.

## Two lessons from the mock card

**A test that does not write what it reads proves nothing.** The mock card once
answered reads from fixed tables: a set list of file ids, a standard data file's
settings whatever the file was, synthetic records of a fixed size, a value of
12345. Six tests were written against those tables, and every one of them passed
by reading something it had never written. They would have gone on passing if
the mock had returned those answers for a card with no files at all, which is
exactly what a personalisation station checks for before it issues a card. When
a test reads, have it create and write first, and assert on what it wrote; where
the mock genuinely cannot know something — data that reached it enciphered, or a
write the library chained across frames — it answers with an error, and the test
should assert that error rather than a plausible value.

**Read the library's own encoder before teaching the mock a channel.** Which
commands carry a MAC, and which answers carry one, is per channel and per
command: EV1 computes a CMAC for every command but only transmits it for some
(`transmits_mac`), while expecting one on every answer; the legacy channel MACs
the answers to reads and nothing else; EV2 and LRP MAC both directions. Each
command names the modes it uses in its own `nxpsc_exchange` call, and
`encode_ev1` / `decode_ev1` say what happens to the chain. Patching the mock
channel by channel until the tests go green costs far more than reading those
three places once.

## Unverified areas

- The AES256 path of AN10922 has no published test vector. The construction
  follows the note, but is not covered by a known answer test.
- **The transaction MAC has no published test vectors at all.** NXP publishes
  the construction but no worked example, and none of the references carries
  one. `nxpsc_tmac_compute` is therefore checked only against the mock card's
  independent implementation, which shares its reading of the data sheet but not
  its code. A real card is the only witness that settles it, so any caller that
  depends on the TMV should prove it per card against the silicon rather than
  trusting these tests. `tmi` layouts for commands other than `WriteRecord` are
  not implemented; add them from section 10.3.4.2 as they are needed.
- `nxpsc_session_key_lrp()` ignores its encryption key argument, which matches
  the proxmark3 behaviour and the note, but is worth re-reading if LRP ever
  misbehaves on hardware.
- The EV1 CMAC chain runs through answers as well as commands, and the mock card
  used to advance its copy of it and throw the result away, so any two MACed EV1
  commands in a row disagreed. The library keeps the chain correctly in both
  directions (`encode_ev1` and `decode_ev1` both pass the card's own IV), and a
  test now issues several MACed EV1 reads in a row to keep it that way. No
  hardware here has an EV1 card, so that test is the only thing watching it.

^[Top](#top)
