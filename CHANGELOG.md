# Changelog

All notable changes to LombokDNS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-09-13

### Added

- **Core wire codec** — full DNS message pack/unpack (RFC 1035 §4.1)
- **65+ record types** — A through HTTPS/SVCB, all DNSSEC types, meta/pseudo records
- **Domain name encoding** with compression pointer support (RFC 1035 §4.1.4)
- **EDNS(0)** — OPT pseudo-record build/parse (RFC 6891)
- **Extended DNS Errors (EDE)** — full RFC 8914 support with human-readable descriptions
- **EDNS options** — Client Subnet (RFC 7871), Cookies (RFC 7873), Padding (RFC 7830), NSID (RFC 5001), TCP Keepalive (RFC 7828)
- **SVCB/HTTPS records** — full RFC 9460 SvcParam decode including alpn, ech, ipv4hint/ipv6hint, dohpath
- **DNSSEC record parsers** — DNSKEY, RRSIG, DS, NSEC, NSEC3, NSEC3PARAM
- **DANE/TLSA record parser** — RFC 6698
- **Zone file parser + serializer** — RFC 1035 §5 with $ORIGIN, $TTL, multi-line parenthesized records
- **MessageBuilder** — fluent API for constructing DNS messages
- **dig-style output formatter** — `toDigFormat()` for human-readable message display
- **Encoding utilities** — hex, base64, base64url (DoH), IPv4/IPv6 encode/decode, all zero-dependency
- **48 tests** across 10 suites including 200-trial random fuzz round-trip
- **CI workflow** — GitHub Actions with Node 20 + 22
- **npm publish workflow** with quality gate (typecheck → build → test → publish)
- **5 GitHub Packages workflows** — npm GPR, Container, Maven, NuGet, RubyGems
- **Architecture document** — full 35+ RFC compliance matrix, 5-tier design, competitive analysis

### Notes

- This is the Tier 1 (Core) release — wire codec, records, EDNS, zone files
- Zero runtime dependencies; runs in Node, Bun, Deno, and browsers
- TypeScript strict mode with ES2022 target
- Tiers 2-5 (Transport, Security, Resolver, Server, Discovery) planned for subsequent releases
- Cross-language ports (PHP, Python, Go, Rust, C++) planned for v0.2.0

[0.1.0]: https://github.com/codinglombok/LombokDNS/releases/tag/v0.1.0
