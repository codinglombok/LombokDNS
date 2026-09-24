# LombokDNS — Architecture Document

**Status:** Proposed → In Development
**Date:** 2026-09-13
**Author:** codinglombok
**License:** Apache-2.0

---

## 1. Context & Motivation

The DNS protocol ecosystem spans 40+ years of RFCs, yet no single library covers
the full stack: wire-format codec, all modern transports (UDP/TCP/DoT/DoH/DoQ),
DNSSEC validation, mDNS/DNS-SD discovery, zone management, stub+recursive resolution,
AND authoritative serving — in a zero-dependency, cross-language, embeddable package.

**Existing landscape gaps:**

| Library          | Language   | Codec | DoH | DoT | DoQ | DNSSEC | mDNS | Zone | Server | Ports |
|-----------------|-----------|-------|-----|-----|-----|--------|------|------|--------|-------|
| dns2 (npm)       | JS        | ✓     | ✗   | ✗   | ✗   | ✗      | ✗    | ✗    | partial| 0     |
| dns-query (npm)  | JS        | ✓     | ✓   | ✗   | ✗   | ✗      | ✗    | ✗    | ✗      | 0     |
| @dnspect/dns-ts  | TS        | ✓     | ✗   | ✗   | ✗   | ✗      | ✗    | ✗    | ✗      | 0     |
| dnspython        | Python    | ✓     | ✓   | ✓   | ✗   | ✓      | ✗    | ✓    | ✗      | 0     |
| miekg/dns (Go)   | Go        | ✓     | ✗   | ✗   | ✗   | ✓      | ✗    | ✓    | ✓      | 0     |
| hickory-dns      | Rust      | ✓     | ✓   | ✓   | ✗   | ✓      | ✓    | ✓    | ✓      | 0     |
| **LombokDNS**    | **TS+5**  | **✓** |**✓**|**✓**|**✓**|**✓**   |**✓** |**✓** |**✓**   |**5**  |

LombokDNS fills EVERY cell. One codebase, one API surface, 6 languages.

## 2. Design Principles

1. **Zero runtime dependencies** — the TS reference uses only Node built-ins +
   Uint8Array; no `Buffer`-specific code in codec layer (runs in browser+Deno+Bun).
2. **RFC-first** — every codec, flag, and record type cites its RFC. Wire format
   is the specification; convenience is a layer on top.
3. **Layered architecture** — each tier can be used alone:
   ```
   ┌─────────────────────────────────────────────────┐
   │  Tier 5: Server (authoritative + recursive)     │
   ├─────────────────────────────────────────────────┤
   │  Tier 4: Resolver (stub + full recursive)       │
   ├─────────────────────────────────────────────────┤
   │  Tier 3: Security (DNSSEC + TSIG + DANE)        │
   ├─────────────────────────────────────────────────┤
   │  Tier 2: Transport (UDP/TCP/DoT/DoH/DoQ)        │
   ├─────────────────────────────────────────────────┤
   │  Tier 1: Core (codec + records + zone)           │
   └─────────────────────────────────────────────────┘
   ```
4. **Cross-language by design** — test vectors JSON (like LombokECC) enforce
   byte-identical behavior across all 6 ports.
5. **Ecosystem integration** — LombokECC for zone-transfer integrity,
   LombokQRCode for DNS-over-QR provisioning, LombokCSS for dashboard UI.

## 3. Module Map

### Tier 1: Core (`src/core/`)

| Module          | Responsibility                           | Key RFCs              |
|----------------|------------------------------------------|-----------------------|
| `types.ts`      | All DNS type enums + constants           | 1035, 3596, 6891      |
| `name.ts`       | Domain name encode/decode + compression  | 1035 §4.1.4           |
| `header.ts`     | 12-byte header encode/decode             | 1035 §4.1.1           |
| `question.ts`   | Question section                         | 1035 §4.1.2           |
| `rdata.ts`      | 65+ record type parsers                  | see record table      |
| `message.ts`    | Full DNS message pack/unpack             | 1035 §4.1             |
| `edns.ts`       | EDNS(0) OPT pseudo-record                | 6891, 7871, 8914      |

### Tier 2: Transport (`src/transport/`)

| Module           | Protocol        | RFC       | Port  |
|-----------------|----------------|-----------|-------|
| `udp.ts`         | Classic UDP     | 1035      | 53    |
| `tcp.ts`         | TCP length-prefixed | 1035, 7766 | 53 |
| `tls.ts`         | DNS-over-TLS    | 7858      | 853   |
| `https.ts`       | DNS-over-HTTPS  | 8484      | 443   |
| `quic.ts`        | DNS-over-QUIC   | 9250      | 853   |
| `transport.ts`   | Abstract transport interface             |       |

### Tier 3: Security (`src/security/`)

| Module           | Feature                    | RFC               |
|-----------------|----------------------------|-------------------|
| `dnssec.ts`      | DNSKEY/RRSIG/DS/NSEC/NSEC3 | 4033, 4034, 4035  |
| `tsig.ts`        | Transaction signatures     | 8945              |
| `dane.ts`        | TLSA record validation     | 6698, 7671        |
| `cookie.ts`      | DNS Cookies                | 7873              |
| `ecc-integrity.ts`| LombokECC zone integrity  | (ecosystem)       |

### Tier 4: Resolver (`src/resolver/`)

| Module           | Feature                    | RFC               |
|-----------------|----------------------------|-------------------|
| `stub.ts`        | Stub resolver              | 1035              |
| `recursive.ts`   | Full recursive resolution  | 1035, 8020        |
| `cache.ts`       | TTL-aware response cache   | 1035, 8767        |
| `policy.ts`      | RPZ + filtering            | draft-ietf-dnsop  |

### Tier 5: Server (`src/server/`)

| Module           | Feature                    | RFC               |
|-----------------|----------------------------|-------------------|
| `authoritative.ts`| Zone-serving auth server  | 1035              |
| `notify.ts`      | NOTIFY for zone changes    | 1996              |
| `update.ts`      | Dynamic DNS updates        | 2136              |
| `xfr.ts`         | AXFR + IXFR zone transfers | 5936, 1995        |

### Tier 6: Discovery (`src/discovery/`)

| Module           | Feature                    | RFC               |
|-----------------|----------------------------|-------------------|
| `mdns.ts`        | Multicast DNS              | 6762              |
| `dnssd.ts`       | DNS-based Service Discovery| 6763              |

### Tier 7: Zone (`src/zone/`)

| Module           | Feature                    | RFC               |
|-----------------|----------------------------|-------------------|
| `zonefile.ts`    | RFC 1035 zone file parser  | 1035 §5           |
| `zonedb.ts`      | In-memory zone database    |                   |

## 4. Supported Record Types (65+)

### Standard Records
A (1), NS (2), CNAME (5), SOA (6), PTR (12), HINFO (13),
MX (15), TXT (16), RP (17), AFSDB (18), AAAA (28),
LOC (29), SRV (33), NAPTR (35), KX (36), CERT (37),
DNAME (39), APL (42), SSHFP (44), IPSECKEY (45),
DHCID (49), TLSA (52), SMIMEA (53), HIP (55), NINFO (56),
CDS (59), CDNSKEY (60), OPENPGPKEY (61), CSYNC (62),
ZONEMD (63), SVCB (64), HTTPS (65), EUI48 (108), EUI64 (109),
URI (256), CAA (257), AVC (258)

### DNSSEC Records
DNSKEY (48), RRSIG (46), NSEC (47), DS (43), NSEC3 (50),
NSEC3PARAM (51)

### Meta / Pseudo Records
OPT (41), TSIG (250), TKEY (249), ANY (255), AXFR (252),
IXFR (251), MAILA (254), MAILB (253)

## 5. Unique Differentiators (what others DON'T have)

### 5.1 DNS-over-QUIC (DoQ) — RFC 9250
No JS/TS library implements DoQ. LombokDNS will be first.

### 5.2 ECC-Protected Zone Transfers
Using LombokECC RS(255,239), zone transfer data gets Reed-Solomon
error correction codes. If packets are corrupted in transit,
LombokDNS can RECOVER data rather than retransmit. No other DNS
library does this.

### 5.3 Integrated DANE + ECH
DNS-based Authentication of Named Entities (TLSA) combined with
Encrypted Client Hello (RFC 9849) support — LombokDNS can resolve
the ECHConfig from HTTPS/SVCB records and validate TLSA.

### 5.4 DNS-over-QR (Provisioning)
Using LombokQRCode, encode DNS configurations into QR codes for
zero-touch device provisioning. Scan QR → configure DNS. Novel
feature for IoT/hardware deployment.

### 5.5 Extended DNS Errors (EDE) — RFC 8914
Full EDE support with human-readable explanations in 11 languages,
using the same i18n pattern as LombokQRCode.

### 5.6 Structured SVCB/HTTPS (RFC 9460)
Complete SVCB/HTTPS record support including all SvcParams:
alpn, no-default-alpn, port, ipv4hint, ipv6hint, ech, mandatory.

### 5.7 Response Policy Zones (RPZ)
Built-in RPZ engine for DNS filtering — what commercial products
like DNSFilter charge for.

### 5.8 Cross-Language Test Vectors
JSON test vector file (like LombokECC) guarantees byte-identical
behavior across TypeScript, PHP, Python, Go, Rust, C++.

## 6. Security Architecture

### Input validation
- All message parsing uses bounds-checked reads (never trust length fields)
- Name decompression loop detection (RFC 1035 §4.1.4 pointer limit)
- EDNS buffer size clamped to safe maximums
- Query name length enforcement (253 chars, 63 per label)

### DNSSEC validation chain
```
Root KSK (built-in trust anchor)
  └→ Root DNSKEY (validate via DS)
       └→ TLD DNSKEY (validate via DS)
            └→ Domain DNSKEY (validate via DS)
                 └→ RRSIG over answer RRset
```

### TSIG authentication
- HMAC-SHA256/SHA384/SHA512 transaction signing
- Replay protection via time window ± 300s
- Per-message MAC for zone transfer streams

### Cookie-based anti-amplification
- RFC 7873 DNS Cookies for client/server mutual verification
- Prevents DNS amplification attacks

## 7. RFC Compliance Matrix

| RFC    | Title                              | Status    |
|--------|------------------------------------|-----------|
| 1035   | Domain Names — Implementation      | ✓ Core    |
| 1995   | Incremental Zone Transfer (IXFR)   | ✓ Zone    |
| 1996   | DNS NOTIFY                         | ✓ Server  |
| 2136   | Dynamic Updates                    | ✓ Server  |
| 2845   | Secret Key Transaction Auth (TSIG) | ✓ Security|
| 3596   | DNS Extensions for IPv6 (AAAA)     | ✓ Core    |
| 4033   | DNSSEC Introduction                | ✓ Security|
| 4034   | DNSSEC Resource Records            | ✓ Security|
| 4035   | DNSSEC Protocol Modifications      | ✓ Security|
| 5936   | DNS Zone Transfer Protocol (AXFR)  | ✓ Zone    |
| 6762   | Multicast DNS                      | ✓ Discover|
| 6763   | DNS-Based Service Discovery        | ✓ Discover|
| 6891   | EDNS(0)                            | ✓ Core    |
| 6698   | DANE / TLSA                        | ✓ Security|
| 7766   | DNS Transport over TCP             | ✓ Xport   |
| 7858   | DNS over TLS (DoT)                 | ✓ Xport   |
| 7871   | Client Subnet in DNS Queries       | ✓ Core    |
| 7873   | DNS Cookies                        | ✓ Security|
| 8484   | DNS over HTTPS (DoH)               | ✓ Xport   |
| 8767   | Serving Stale Data                 | ✓ Resolver|
| 8914   | Extended DNS Errors (EDE)           | ✓ Core    |
| 8945   | Secret Key Transaction Auth v2     | ✓ Security|
| 9250   | DNS over QUIC (DoQ)                | ✓ Xport   |
| 9460   | SVCB and HTTPS Resource Records    | ✓ Core    |
| 9461   | SVCB for DNS Servers               | ✓ Core    |
| 9849   | Encrypted Client Hello             | ✓ Security|

## 8. Cross-Language Port Strategy

Following LombokECC's proven pattern:

| Language   | Registry    | Package Name               |
|-----------|-------------|----------------------------|
| TypeScript | npm         | `lombokdns`                |
| PHP        | Packagist   | `codinglombok/lombokdns`   |
| Python     | PyPI        | `lombokdns`                |
| Go         | go.sum      | `github.com/codinglombok/LombokDNS-go` |
| Rust       | crates.io   | `lombokdns`                |
| C++        | CMake/vcpkg | `lombokdns`                |

Ports share:
- `vectors/lombokdns-vectors-v1.json` — test vectors
- Same algorithmic behavior (byte-identical wire output)
- Language-idiomatic APIs wrapping shared logic

## 9. Ecosystem Integration

```
LombokDNS ← LombokECC    (zone transfer integrity)
LombokDNS ← LombokQRCode (DNS-over-QR provisioning)
LombokDNS → LombokCSS    (dashboard UI styling)
LombokDNS → LombokCharts (query analytics visualization)
LombokDNS → LombokClarion (PHP DNS management app)
```

## 10. Target Users

| User Type                    | Use Case                           |
|-----------------------------|------------------------------------|
| App developers              | Embed DNS resolution in apps       |
| IoT manufacturers           | mDNS/DNS-SD device discovery       |
| Network engineers           | Custom DNS servers + monitoring    |
| Security researchers        | DNSSEC validation + DANE           |
| Cloud providers              | DNS-as-a-service backends          |
| ISPs                         | Recursive resolvers + RPZ filtering|
| Enterprise IT                | Internal DNS + split-horizon       |
| Embedded/hardware            | Lightweight DNS for MCU/RTOS (C++) |
| Academic/research            | DNS protocol analysis tools        |
