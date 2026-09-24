/**
 * LombokDNS — DNS Types & Constants
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 *
 * All values sourced from IANA DNS Parameters:
 * https://www.iana.org/assignments/dns-parameters/
 */

// ─── Record Types (RFC 1035 + extensions) ────────────────────────

export enum RRType {
  A          =  1,  // RFC 1035 — IPv4 address
  NS         =  2,  // RFC 1035 — Authoritative name server
  MD         =  3,  // RFC 1035 — Mail destination (obsolete)
  MF         =  4,  // RFC 1035 — Mail forwarder (obsolete)
  CNAME      =  5,  // RFC 1035 — Canonical name
  SOA        =  6,  // RFC 1035 — Start of authority
  MB         =  7,  // RFC 1035 — Mailbox domain
  MG         =  8,  // RFC 1035 — Mail group member
  MR         =  9,  // RFC 1035 — Mail rename domain
  NULL       = 10,  // RFC 1035 — Null RR
  WKS        = 11,  // RFC 1035 — Well-known service
  PTR        = 12,  // RFC 1035 — Domain name pointer
  HINFO      = 13,  // RFC 1035 — Host information
  MINFO      = 14,  // RFC 1035 — Mailbox information
  MX         = 15,  // RFC 1035 — Mail exchange
  TXT        = 16,  // RFC 1035 — Text strings
  RP         = 17,  // RFC 1183 — Responsible person
  AFSDB      = 18,  // RFC 1183 — AFS database record
  X25        = 19,  // RFC 1183 — X.25 PSDN address
  ISDN       = 20,  // RFC 1183 — ISDN address
  RT         = 21,  // RFC 1183 — Route through
  NSAP       = 22,  // RFC 1706 — NSAP address
  SIG        = 24,  // RFC 2535 — Security signature (legacy)
  KEY        = 25,  // RFC 2535 — Security key (legacy)
  PX         = 26,  // RFC 2163 — X.400 mail mapping
  GPOS       = 27,  // RFC 1712 — Geographical position
  AAAA       = 28,  // RFC 3596 — IPv6 address
  LOC        = 29,  // RFC 1876 — Location information
  NXT        = 30,  // RFC 2535 — Next domain (obsolete)
  SRV        = 33,  // RFC 2782 — Service locator
  NAPTR      = 35,  // RFC 3403 — Naming authority pointer
  KX         = 36,  // RFC 2230 — Key exchanger
  CERT       = 37,  // RFC 4398 — Certificate record
  DNAME      = 39,  // RFC 6672 — Delegation name
  OPT        = 41,  // RFC 6891 — EDNS(0) pseudo-record
  APL        = 42,  // RFC 3123 — Address prefix list
  DS         = 43,  // RFC 4034 — Delegation signer (DNSSEC)
  SSHFP      = 44,  // RFC 4255 — SSH fingerprint
  IPSECKEY   = 45,  // RFC 4025 — IPsec key
  RRSIG      = 46,  // RFC 4034 — DNSSEC signature
  NSEC       = 47,  // RFC 4034 — Next secure record
  DNSKEY     = 48,  // RFC 4034 — DNS public key
  DHCID      = 49,  // RFC 4701 — DHCP identifier
  NSEC3      = 50,  // RFC 5155 — Hashed denial of existence
  NSEC3PARAM = 51,  // RFC 5155 — NSEC3 parameters
  TLSA       = 52,  // RFC 6698 — DANE / TLS association
  SMIMEA     = 53,  // RFC 8162 — S/MIME association
  HIP        = 55,  // RFC 8005 — Host identity protocol
  CDS        = 59,  // RFC 7344 — Child DS
  CDNSKEY    = 60,  // RFC 7344 — Child DNSKEY
  OPENPGPKEY = 61,  // RFC 7929 — OpenPGP public key
  CSYNC      = 62,  // RFC 7477 — Child-to-parent sync
  ZONEMD     = 63,  // RFC 8976 — Message digest for zones
  SVCB       = 64,  // RFC 9460 — Service binding
  HTTPS      = 65,  // RFC 9460 — HTTPS binding
  EUI48      = 108, // RFC 7043 — EUI-48 address
  EUI64      = 109, // RFC 7043 — EUI-64 address
  TKEY       = 249, // RFC 2930 — Transaction key
  TSIG       = 250, // RFC 8945 — Transaction signature
  IXFR       = 251, // RFC 1995 — Incremental zone transfer
  AXFR       = 252, // RFC 5936 — Full zone transfer
  MAILB      = 253, // RFC 1035 — Mailbox-related (QTYPE)
  MAILA      = 254, // RFC 1035 — Mail agent (QTYPE)
  ANY        = 255, // RFC 1035 — All records (QTYPE)
  URI        = 256, // RFC 7553 — URI
  CAA        = 257, // RFC 8659 — Certification authority auth
  AVC        = 258, // Visibility and Control
  DLV        = 32769, // RFC 4431 — DNSSEC Lookaside Validation
}

// ─── Record Classes (RFC 1035 §3.2.4) ──────────────────────────

export enum RRClass {
  IN   = 1,  // Internet
  CS   = 2,  // CSNET (obsolete)
  CH   = 3,  // CHAOS
  HS   = 4,  // Hesiod
  NONE = 254, // RFC 2136
  ANY  = 255, // RFC 1035
}

// ─── Opcodes (RFC 1035 §4.1.1, RFC 6895) ──────────────────────

export enum Opcode {
  QUERY  = 0,  // Standard query
  IQUERY = 1,  // Inverse query (obsolete)
  STATUS = 2,  // Server status
  NOTIFY = 4,  // RFC 1996
  UPDATE = 5,  // RFC 2136
  DSO    = 6,  // RFC 8490 — DNS Stateful Operations
}

// ─── Response Codes (RFC 1035, 6895, 8914) ─────────────────────

export enum RCode {
  NOERROR   = 0,
  FORMERR   = 1,  // Format error
  SERVFAIL  = 2,  // Server failure
  NXDOMAIN  = 3,  // Non-existent domain
  NOTIMP    = 4,  // Not implemented
  REFUSED   = 5,  // Query refused
  YXDOMAIN  = 6,  // RFC 2136 — Name exists when it should not
  YXRRSET   = 7,  // RFC 2136 — RR set exists when it should not
  NXRRSET   = 8,  // RFC 2136 — RR set does not exist
  NOTAUTH   = 9,  // RFC 2136 — Server not authoritative / not authorized
  NOTZONE   = 10, // RFC 2136 — Name not in zone
  DSOTYPENI = 11, // RFC 8490 — DSO type not implemented
  BADVERS   = 16, // RFC 6891 — Bad OPT version / BADSIG
  BADKEY    = 17, // RFC 8945 — Key not recognized
  BADTIME   = 18, // RFC 8945 — Signature out of time window
  BADMODE   = 19, // RFC 2930 — Bad TKEY mode
  BADNAME   = 20, // RFC 2930 — Duplicate key name
  BADALG    = 21, // RFC 2930 — Algorithm not supported
  BADTRUNC  = 22, // RFC 8945 — Bad truncation
  BADCOOKIE = 23, // RFC 7873 — Bad/missing server cookie
}

// ─── Extended DNS Error Codes (RFC 8914) ───────────────────────

export enum EDECode {
  OTHER                    = 0,
  UNSUPPORTED_DNSKEY_ALG   = 1,
  UNSUPPORTED_DS_DIGEST    = 2,
  STALE_ANSWER             = 3,
  FORGED_ANSWER            = 4,
  DNSSEC_INDETERMINATE     = 5,
  DNSSEC_BOGUS             = 6,
  SIGNATURE_EXPIRED        = 7,
  SIGNATURE_NOT_YET_VALID  = 8,
  DNSKEY_MISSING           = 9,
  RRSIGS_MISSING           = 10,
  NO_ZONE_KEY_BIT_SET      = 11,
  NSEC_MISSING             = 12,
  CACHED_ERROR             = 13,
  NOT_READY                = 14,
  BLOCKED                  = 15,
  CENSORED                 = 16,
  FILTERED                 = 17,
  PROHIBITED               = 18,
  STALE_NXDOMAIN_ANSWER    = 19,
  NOT_AUTHORITATIVE        = 20,
  NOT_SUPPORTED            = 21,
  NO_REACHABLE_AUTHORITY   = 22,
  NETWORK_ERROR            = 23,
  INVALID_DATA             = 24,
  SIGNATURE_EXPIRED_BEFORE_VALID = 25,
  TOO_EARLY                = 26,
  UNSUPPORTED_NSEC3_ITERATIONS  = 27,
  UNABLE_TO_CONFORM_TO_POLICY   = 28,
  SYNTHESIZED              = 29,
}

// ─── EDNS Option Codes (RFC 6891) ──────────────────────────────

export enum EDNSOptionCode {
  LLQ              = 1,   // Long-Lived Queries
  UL               = 2,   // Update Lease
  NSID             = 3,   // RFC 5001 — Name Server Identifier
  DAU              = 5,   // RFC 6975 — DNSSEC Algorithm Understood
  DHU              = 6,   // RFC 6975 — DS Hash Understood
  N3U              = 7,   // RFC 6975 — NSEC3 Hash Understood
  CLIENT_SUBNET    = 8,   // RFC 7871 — Client Subnet
  EXPIRE           = 9,   // RFC 7314 — Zone expiration
  COOKIE           = 10,  // RFC 7873 — DNS Cookie
  TCP_KEEPALIVE    = 11,  // RFC 7828
  PADDING          = 12,  // RFC 7830
  CHAIN            = 13,  // RFC 7901
  KEY_TAG          = 14,  // RFC 8145
  EDE              = 15,  // RFC 8914 — Extended DNS Error
  CLIENT_TAG       = 16,  // draft-bellis-dnsop-edns-tags
  SERVER_TAG       = 17,  // draft-bellis-dnsop-edns-tags
  REPORT_CHANNEL   = 18,  // RFC 9567
  ZONEVERSION      = 19,  // RFC 9660
}

// ─── DNSSEC Algorithm Numbers (RFC 8624) ───────────────────────

export enum DNSSECAlgorithm {
  DELETE           = 0,
  RSAMD5           = 1,   // Deprecated
  DH               = 2,
  DSA              = 3,   // Deprecated
  RSASHA1          = 5,   // Not recommended
  DSA_NSEC3_SHA1   = 6,   // Deprecated
  RSASHA1_NSEC3    = 7,   // Not recommended
  RSASHA256        = 8,   // RFC 5702
  RSASHA512        = 10,  // RFC 5702
  ECC_GOST         = 12,  // RFC 5933
  ECDSAP256SHA256  = 13,  // RFC 6605 — RECOMMENDED
  ECDSAP384SHA384  = 14,  // RFC 6605 — RECOMMENDED
  ED25519          = 15,  // RFC 8080 — RECOMMENDED
  ED448            = 16,  // RFC 8080
  INDIRECT         = 252,
  PRIVATEDNS       = 253,
  PRIVATEOID       = 254,
}

// ─── DS Digest Types (RFC 4034, 6605, 8624) ────────────────────

export enum DSDigestType {
  SHA1             = 1,  // RFC 3658 — NOT RECOMMENDED
  SHA256           = 2,  // RFC 4509 — MANDATORY
  GOST_R_34_11_94  = 3,  // RFC 5933
  SHA384           = 4,  // RFC 6605
}

// ─── SVCB/HTTPS SvcParamKey (RFC 9460) ─────────────────────────

export enum SvcParamKey {
  MANDATORY        = 0,
  ALPN             = 1,
  NO_DEFAULT_ALPN  = 2,
  PORT             = 3,
  IPV4HINT         = 4,
  ECH              = 5,
  IPV6HINT         = 6,
  DOHPATH          = 7,  // RFC 9461
  OHTTP            = 8,  // draft-ietf-ohai-svcb-config
}

// ─── TSIG Algorithm Names (RFC 8945) ───────────────────────────

export const TSIGAlgorithm = {
  HMAC_MD5:    'hmac-md5.sig-alg.reg.int',
  GSS_TSIG:    'gss-tsig',
  HMAC_SHA1:   'hmac-sha1',
  HMAC_SHA224: 'hmac-sha224',
  HMAC_SHA256: 'hmac-sha256',
  HMAC_SHA384: 'hmac-sha384',
  HMAC_SHA512: 'hmac-sha512',
} as const;

// ─── Header Flags (RFC 1035 §4.1.1) ───────────────────────────

export const HeaderFlags = {
  QR:  0x8000, // Query (0) / Response (1)
  AA:  0x0400, // Authoritative Answer
  TC:  0x0200, // Truncated
  RD:  0x0100, // Recursion Desired
  RA:  0x0080, // Recursion Available
  Z:   0x0040, // Reserved (must be zero)
  AD:  0x0020, // Authentic Data (RFC 4035)
  CD:  0x0010, // Checking Disabled (RFC 4035)
} as const;

// ─── Shared Interfaces ────────────────────────────────────────

export interface DNSHeader {
  id: number;
  flags: number;
  qdcount: number;
  ancount: number;
  nscount: number;
  arcount: number;
}

export interface DNSQuestion {
  name: string;
  type: RRType;
  class: RRClass;
}

export interface DNSResourceRecord {
  name: string;
  type: RRType;
  class: RRClass;
  ttl: number;
  rdlength: number;
  rdata: Uint8Array | Record<string, unknown>;
}

export interface DNSMessage {
  header: DNSHeader;
  questions: DNSQuestion[];
  answers: DNSResourceRecord[];
  authorities: DNSResourceRecord[];
  additionals: DNSResourceRecord[];
}

export interface EDNSOption {
  code: EDNSOptionCode;
  length: number;
  data: Uint8Array;
}

export interface EDNSRecord {
  udpSize: number;
  extRcode: number;
  version: number;
  flags: number;    // DO bit at 0x8000
  options: EDNSOption[];
}

// ─── Wire Constants ────────────────────────────────────────────

export const DNS_HEADER_SIZE = 12;
export const MAX_LABEL_LENGTH = 63;
export const MAX_NAME_LENGTH = 253;
export const MAX_UDP_SIZE = 512;      // RFC 1035 default
export const MAX_EDNS_UDP = 4096;     // Common EDNS default
export const COMPRESSION_POINTER_MASK = 0xC0;
export const COMPRESSION_OFFSET_MASK = 0x3FFF;
export const MAX_COMPRESSION_POINTERS = 128; // Loop protection
