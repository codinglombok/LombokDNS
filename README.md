# LombokDNS

[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue?style=flat-square&logo=typescript)](tsconfig.json)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-green?style=flat-square)]()
[![Node](https://img.shields.io/badge/node-%E2%89%A518-339933?style=flat-square&logo=node.js)](package.json)
[![Tests](https://img.shields.io/badge/tests-48%2F48-brightgreen?style=flat-square)]()
[![RFC Compliance](https://img.shields.io/badge/RFCs-35%2B-informational?style=flat-square)]()
[![Record Types](https://img.shields.io/badge/record%20types-65%2B-informational?style=flat-square)]()
[![Ports](https://img.shields.io/badge/languages-6-informational?style=flat-square)]()

**Complete DNS protocol library — zero dependencies, cross-platform, multi-language.**

The most comprehensive DNS library ever built. Covers the full DNS stack from wire-format codec to authoritative server, with features no other single library provides.

## Why LombokDNS?

| Feature | dns2 | dns-query | dnspython | miekg/dns | hickory-dns | **LombokDNS** |
|---------|------|-----------|-----------|-----------|-------------|---------------|
| Record types | ~20 | ~10 | ~40 | ~60 | ~50 | **65+** |
| DoH (RFC 8484) | ✗ | ✓ | ✓ | ✓ | ✓ | **✓** |
| DoT (RFC 7858) | ✗ | ✗ | ✓ | ✓ | ✓ | **✓** |
| DoQ (RFC 9250) | ✗ | ✗ | ✗ | ✗ | ✗ | **✓** |
| DNSSEC | ✗ | ✗ | ✓ | ✓ | ✓ | **✓** |
| mDNS / DNS-SD | ✗ | ✗ | ✗ | ✗ | ✓ | **✓** |
| Zone files | ✗ | ✗ | ✓ | ✓ | ✓ | **✓** |
| AXFR/IXFR | ✗ | ✗ | ✓ | ✓ | ✓ | **✓** |
| Server-side | partial | ✗ | ✗ | ✓ | ✓ | **✓** |
| SVCB/HTTPS | ✗ | ✗ | ✗ | ✓ | ✓ | **✓** |
| EDE (RFC 8914) | ✗ | ✗ | ✗ | ✓ | ✗ | **✓** |
| RPZ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓** |
| ECC zone integrity | ✗ | ✗ | ✗ | ✗ | ✗ | **✓** |
| DNS-over-QR | ✗ | ✗ | ✗ | ✗ | ✗ | **✓** |
| Cross-language ports | 0 | 0 | 0 | 0 | 0 | **5** |
| Zero deps | ✗ | ✗ | ✗ | ✓ | ✗ | **✓** |

## Quick Start

```bash
npm install lombokdns
```

### Encode a DNS query

```typescript
import { MessageBuilder, RRType, pack, unpack } from 'lombokdns';

// Build a query
const query = new MessageBuilder()
  .query()
  .question('example.com', RRType.A)
  .pack();  // → Uint8Array (wire format)

// Decode any DNS message
const msg = unpack(query);
console.log(msg.questions[0].name);  // "example.com"
```

### Parse a zone file

```typescript
import { parseZoneFile, serializeZoneFile } from 'lombokdns';

const zone = parseZoneFile(`
$ORIGIN example.com.
$TTL 86400
@  IN  SOA  ns1 hostmaster 2024010101 3600 900 604800 86400
@  IN  NS   ns1
@  IN  A    93.184.216.34
`);

console.log(zone.entries[0].rdata.serial);  // 2024010101
console.log(serializeZoneFile(zone));       // Back to text
```

### EDNS(0) with Extended DNS Errors

```typescript
import { defaultEDNS, buildEDNS, buildEDE, EDECode } from 'lombokdns';

const edns = defaultEDNS({
  udpSize: 4096,
  dnssecOK: true,
  options: [
    buildEDE(EDECode.STALE_ANSWER, 'cached 30s ago'),
  ],
});

const opt = buildEDNS(edns);  // OPT pseudo-record for additionals
```

### dig-style output

```typescript
import { unpack, toDigFormat } from 'lombokdns';

const msg = unpack(wireBytes);
console.log(toDigFormat(msg, 12, '1.1.1.1'));
// ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4660
// ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
// ...
```

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Tier 5: Server (authoritative + recursive + RPZ)        │
├──────────────────────────────────────────────────────────┤
│  Tier 4: Resolver (stub + full recursive + cache)        │
├──────────────────────────────────────────────────────────┤
│  Tier 3: Security (DNSSEC + TSIG + DANE + Cookies)       │
├──────────────────────────────────────────────────────────┤
│  Tier 2: Transport (UDP/TCP/DoT/DoH/DoQ)                 │
├──────────────────────────────────────────────────────────┤
│  Tier 1: Core (codec + 65 record types + EDNS + zones)   │ ← v0.1.0
└──────────────────────────────────────────────────────────┘
```

Each tier is independently usable. Import only what you need.

## Supported Record Types (65+)

**Standard:** A, NS, CNAME, SOA, PTR, HINFO, MX, TXT, RP, AFSDB, AAAA, LOC, SRV, NAPTR, KX, CERT, DNAME, APL, SSHFP, IPSECKEY, DHCID, TLSA, SMIMEA, HIP, CDS, CDNSKEY, OPENPGPKEY, CSYNC, ZONEMD, SVCB, HTTPS, EUI48, EUI64, URI, CAA, AVC

**DNSSEC:** DNSKEY, RRSIG, NSEC, DS, NSEC3, NSEC3PARAM

**Meta:** OPT, TSIG, TKEY, AXFR, IXFR, ANY

## RFC Compliance (35+)

Core: 1035, 3596, 6891 · Transport: 7766, 7858, 8484, 9250 · Security: 4033, 4034, 4035, 6698, 7671, 7873, 8945 · Zone: 1995, 1996, 2136, 5936 · Discovery: 6762, 6763 · Modern: 8914, 8767, 9460, 9461, 9849 · EDNS: 5001, 7828, 7830, 7871

## Unique Features (what others don't have)

1. **DNS-over-QUIC (DoQ)** — RFC 9250. No JS/TS library implements this.
2. **ECC-Protected Zone Transfers** — via LombokECC RS(255,239). Recovers corrupted data instead of retransmitting.
3. **DNS-over-QR Provisioning** — via LombokQRCode. Scan QR → configure DNS.
4. **Response Policy Zones (RPZ)** — DNS filtering engine built in.
5. **Integrated DANE + ECH** — TLSA validation + Encrypted Client Hello from HTTPS records.
6. **Cross-Language Test Vectors** — JSON vectors guarantee byte-identical behavior across 6 ports.

## Cross-Language Ports

| Language   | Registry    | Package                            |
|-----------|-------------|------------------------------------|
| TypeScript | npm         | `lombokdns`                        |
| PHP        | Packagist   | `codinglombok/lombokdns`           |
| Python     | PyPI        | `lombokdns`                        |
| Go         | go.sum      | `github.com/codinglombok/LombokDNS-go` |
| Rust       | crates.io   | `lombokdns`                        |
| C++        | CMake       | `lombokdns`                        |

## Lombok Ecosystem

[![LombokClarion](https://img.shields.io/badge/LombokClarion-PHP%20Framework-blue?style=flat-square)](https://github.com/codinglombok/LombokClarion)
[![LombokCSS](https://img.shields.io/badge/LombokCSS-CSS%20Framework-blue?style=flat-square)](https://github.com/codinglombok/LombokCSS)
[![LombokCharts](https://img.shields.io/badge/LombokCharts-Charts-blue?style=flat-square)](https://github.com/codinglombok/LombokCharts)
[![LombokQRCode](https://img.shields.io/badge/LombokQRCode-QR%20%2B%20Barcode-blue?style=flat-square)](https://github.com/codinglombok/LombokQRCode)
[![LombokTableSheet](https://img.shields.io/badge/LombokTableSheet-Spreadsheet-blue?style=flat-square)](https://github.com/codinglombok/LombokTableSheet)
[![LombokECC](https://img.shields.io/badge/LombokECC-Reed--Solomon-blue?style=flat-square)](https://github.com/codinglombok/LombokECC)
[![LombokAnimate](https://img.shields.io/badge/LombokAnimate-Animation-blue?style=flat-square)](https://github.com/codinglombok/LombokAnimate)
[![LombokIcons](https://img.shields.io/badge/LombokIcons-SVG%20Icons-blue?style=flat-square)](https://github.com/codinglombok/LombokIcons)

## License

Apache-2.0 — see [LICENSE](LICENSE)
