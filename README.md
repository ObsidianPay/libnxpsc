# libnxpsc

[![libnxpsc](https://github.com/ObsidianPay/libnxpsc/actions/workflows/libnxpsc.yml/badge.svg)](https://github.com/ObsidianPay/libnxpsc/actions/workflows/libnxpsc.yml)

A portable, backend agnostic C library for low level programming of NXP
and MIFARE smartcards. 

[[card support]](#by-card-family)

| family | products |
| --- | --- |
| DESFire | MF3ICD40, EV1, EV2, EV2 XL, EV3, Light |
| MIFARE Plus | EV1, EV2 (SL1 and SL3) |
| NTAG | 413 DNA, 424 DNA (and TT) |
| DUOX | DUOX |

That table is what the code targets, not what has been proven against silicon.
Only DESFire EV3 has been run on a card. See
[Validation status](#validation-status) before relying on any of the others.

The library speaks the card protocols only. It never opens a reader itself, the
caller supplies a single transceive callback, so the same code runs on top of
libnfc, PC/SC, Android `IsoDep` through JNI, a Node N-API addon, or a bare metal
NFC frontend driver.

## What it does

- card identification from `GetVersion`, including the product table above
- every authentication flavour: legacy D40, ISO 3DES, AES EV1, EV2 first and
  non first, and LRP for EV2 XL / DESFire Light / NTAG 424
- application and file management, delegated applications, MIFARE Classic
  mapping, transaction MAC files, key sets, proximity check
- key change on any key including the PICC master key and factory key
  replacement, with AN10922 diversification
- NTAG 424 secure dynamic messaging, MIFARE Plus SL1 and SL3
- value files, records, backup files and the full transaction flow

## Validation status

Three different things get called "supported", and the difference matters more
here than usual, so they are kept apart.

- **written** - the code exists and follows the references in
  [docs/md/Development/Porting_Notes.md](docs/md/Development/Porting_Notes.md)
- **tested** - covered by the off-card suite, which drives the library against a
  mock card. 54 protocol assertions and 15 crypto known answer vectors, run on
  every build under both gcc and MSVC
- **proven** - run against a real card and seen to work

Everything in the product table is written. Most of it is tested. One product is
proven.

### By card family

| family | status |
| --- | --- |
| DESFire EV3 | **proven**, and the only one |
| DESFire EV1, EV2, EV2 XL, MF3ICD40 | written and tested, never on a card |
| DESFire Light | written and tested, never on a card. Also the only user of the LRP channel, which has never run |
| MIFARE Plus EV1 / EV2 | written and tested, never on a card. 13 public calls, the largest untried block in the library |
| NTAG 413 / 424 DNA | written and tested, never on a card |
| DUOX | written and tested, never on a card |

### By secure channel

The channels matter more than the family names, because they carry the crypto
and several families share one.

| channel | status |
| --- | --- |
| D40, the legacy handshake | proven, through the factory 2TDEA PICC key |
| EV1, `AuthenticateISO` | proven. An EV3 still answers `0x1A`, so the channel can be forced on the card in hand rather than waiting for an EV1. Doing that found it broken outright, twice over: see [hardware notes](docs/hardware-notes.md#the-ev1-channel-chains-its-iv-through-the-handshake) |
| EV2 | proven, through AES application keys |
| LRP | **never run.** Needs a DESFire Light, or LRP turned on elsewhere |

### By API surface

69 of the 99 public calls have run against a card. Of the rest: 13 are MIFARE
Plus, 3 are NTAG and SDM, 5 are `SetConfiguration` and deliberately untried
because its one way bits would cost the card, 4 are delegated applications and
MIFARE Classic mapping, and the remainder are pure helpers covered off card.

### Why proving a channel is not proving a family

A shared channel does not make a family safe, and there is a concrete example.
`GetDFNames` sent inside a session is harmless on EV3 and **permanently disables
an EV1**: the card answers the first continuation frame with `0xC1`, "PICC will
be disabled", and never works again. Same library code, same channel, opposite
outcome. That was found in a hardware note in another project, not by testing,
because the card that would have shown it was not on the desk.

So for EV1 and EV2 the honest position is that the crypto is proven and the card
behaviour is not.

### If another family is ever needed

Buy the card. An EV1 and an EV2 cost a few euros each and would confirm the
`GetDFNames` guard actually guards the card it was written for, which is the
single largest piece of untested risk. MIFARE Plus needs a Plus card and a
session's work, since none of SL3 has ever been exercised.

The hardware suites live alongside this repository: `Tessera` covers the paths a
normal application uses, `Crucible` the rest, in tiers by how recoverable a
mistake is. Together they are 156 assertions against a card. Everything they
established that is not in a data sheet is written down in
[docs/hardware-notes.md](docs/hardware-notes.md), including the several places a
reference implementation is wrong.

## Build

```
cmake -S . -B build
cmake --build build
(cd build && ctest --output-on-failure)
```

See [docs/README.md](docs/README.md) for the full documentation, the transport
backend guide and the personalisation workflows.

## Quick Example (on Windows)

This example connects to the card and displays some basic hardware information
about it.


```C++
#include <winscard.h>
#include <stdio.h>

extern "C" {
#include <nxpsc/nxpsc.h>
}

static int pcsc_transceive(void* vctx, const uint8_t* tx, size_t txlen,
    uint8_t* rx, size_t rxcap, size_t* rxlen);

struct PcscCtx {
    SCARDHANDLE hCard;
    DWORD proto;
};


int main()
{

    printf("libnxpsc version: %s\n", nxpsc_version_string());
    // Library selftest
    if (nxpsc_selftest(true) != NXPSC_OK) {
        printf("Library selftest failed\n");
        return 1;
    }
    PcscCtx ctx;
    SCARDCONTEXT hContext;
    LONG rv = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hContext);
    if (rv != SCARD_S_SUCCESS) {
        printf("Failed to establish context: %ld\n", rv);
        return 1;
    }

    // List available readers
    LPTSTR mszReaders = NULL;
    DWORD dwReaders = SCARD_AUTOALLOCATE;
    rv = SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders);
    if (rv != SCARD_S_SUCCESS) {
        printf("Failed to list readers: %ld\n", rv);
        SCardReleaseContext(hContext);
        return 1;
    }

    // Connect to the first reader
    rv = SCardConnect(hContext, mszReaders, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &ctx.hCard, &ctx.proto);
    if (rv != SCARD_S_SUCCESS) {
        printf("no card or bad reader\n");
        SCardFreeMemory(hContext, mszReaders);
        SCardReleaseContext(hContext);
        return 1;
    }

    nxpsc_transport_t transport = {};
    transport.ctx = &ctx;
    transport.transceive = pcsc_transceive;

    nxpsc_card_t* card;
    int rc = nxpsc_open(&transport, &card);
    if (rc != NXPSC_OK && nxpsc_selftest(true)) {
        printf("Failed to open card: %d\n", rc);
        SCardDisconnect(ctx.hCard, SCARD_LEAVE_CARD);
        SCardReleaseContext(hContext);
        return 1;
    }
    printf("\nthe card is connected\n\n");

    // Identify the card
    nxpsc_cardtype_t type = NXP_UNKNOWN;
    nxpsc_identify(card, &type);

    printf("Card type: %s\n", nxpsc_cardtype_str(type));

    nxpsc_version_t v{};
    rc = nxpsc_get_version(card, &v);
    if (rc == NXPSC_OK) {
        printf("sw version: %u.%u\n", v.sw_major, v.sw_minor);
        printf("hw type: %02X\n", v.hw_type);
        printf("hw storage size: %u bytes\n", v.hw_storage);
        printf("hw protocol: %02X\n", v.hw_protocol);
    }

    // Bytes free
    uint32_t bytes = 0;
    rc = nxpsc_get_free_memory(card, &bytes);
    if (rc == NXPSC_OK)
        printf("free: %u bytes\n", bytes);
    return 0;
}

static int pcsc_transceive(void* vctx, const uint8_t* tx, size_t txlen,
    uint8_t* rx, size_t rxcap, size_t* rxlen)
{
    PcscCtx* ctx = static_cast<PcscCtx*>(vctx);
    DWORD rlen = static_cast<DWORD>(rxcap);

    // Debug output of the sent data
    printf(">> ");
    for (size_t i = 0; i < txlen; i++) printf("%02X", tx[i]);
    printf("\n");

    // Transmit the APDU to the card
    LONG rc = SCardTransmit(ctx->hCard, SCARD_PCI_T1,
        tx, static_cast<DWORD>(txlen),
        nullptr, rx, &rlen);
    if (rc != SCARD_S_SUCCESS)
        return NXPSC_E_TRANSPORT;   // card removed / no answer

    // Debug output of the received data
    printf("<< ");
    for (DWORD i = 0; i < rlen; i++) printf("%02X", rx[i]);
    printf("\n\n");

    *rxlen = rlen;
    return NXPSC_OK;                // card errors are decoded by the library
}
```

## Licence

GPLv3, see [LICENSE.txt](LICENSE.txt).
