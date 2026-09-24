/**
 * LombokDNS — Complete DNS Protocol Library
 * Zero-dependency, cross-platform, multi-language
 *
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 * Part of the Lombok Ecosystem (codinglombok)
 *
 * Features:
 *  - 65+ record types (A to HTTPS/SVCB)
 *  - All transports: UDP, TCP, DoT (RFC 7858), DoH (RFC 8484), DoQ (RFC 9250)
 *  - DNSSEC validation (RRSIG, DNSKEY, DS, NSEC/NSEC3)
 *  - EDNS(0) with EDE (RFC 8914), Client Subnet, Cookies, Padding
 *  - TSIG transaction authentication (RFC 8945)
 *  - DANE / TLSA validation (RFC 6698)
 *  - Zone file parsing + serialization (RFC 1035 §5, $GENERATE)
 *  - AXFR/IXFR zone transfers (RFC 5936, 1995)
 *  - mDNS (RFC 6762) + DNS-SD (RFC 6763) service discovery
 *  - Server-side + client-side programming (net/http pattern)
 *  - SVCB/HTTPS records (RFC 9460) with ECH support
 *  - Response Policy Zones (RPZ)
 *  - DNS-over-QR provisioning (via LombokQRCode)
 *  - ECC-protected zone transfers (via LombokECC)
 *  - Cross-language test vectors for 6 language ports
 */

// ─── Core: Wire format codec ───────────────────────────────────

export {
  // Enums & Constants
  RRType,
  RRClass,
  Opcode,
  RCode,
  EDECode,
  EDNSOptionCode,
  DNSSECAlgorithm,
  DSDigestType,
  SvcParamKey,
  TSIGAlgorithm,
  HeaderFlags,
  // Type interfaces
  type DNSHeader,
  type DNSQuestion,
  type DNSResourceRecord,
  type DNSMessage,
  type EDNSOption,
  type EDNSRecord,
  // Wire constants
  DNS_HEADER_SIZE,
  MAX_LABEL_LENGTH,
  MAX_NAME_LENGTH,
  MAX_UDP_SIZE,
  MAX_EDNS_UDP,
  COMPRESSION_POINTER_MASK,
  COMPRESSION_OFFSET_MASK,
  MAX_COMPRESSION_POINTERS,
} from './core/types.js';

// Domain name operations
export {
  encodeName,
  decodeName,
  NameCompressor,
  namesEqual,
  isSubdomain,
  parentDomain,
  labelCount,
  validateName,
  type DecodedName,
} from './core/name.js';

// Message pack/unpack
export {
  unpack,
  pack,
  MessageBuilder,
  createResponse,
  decodeHeader,
  encodeHeader,
  buildFlags,
  isResponse,
  isAuthoritative,
  isTruncated,
  isRecursionDesired,
  isRecursionAvailable,
  isAuthenticData,
  isCheckingDisabled,
  getOpcode,
  getRcode,
} from './core/message.js';

// RDATA encode/decode
export {
  decodeRData,
  encodeRData,
} from './core/rdata.js';

// EDNS(0) + EDE + options
export {
  parseEDNS,
  buildEDNS,
  findEDNS,
  defaultEDNS,
  buildEDE,
  parseEDE,
  describeEDE,
  buildClientSubnet,
  parseClientSubnet,
  buildCookie,
  parseCookie,
  buildPadding,
  buildNSID,
  buildTCPKeepalive,
} from './core/edns.js';

// ─── Zone: file parsing + serialization ────────────────────────

export {
  parseZoneFile,
  serializeZoneFile,
  typeNameToEnum,
  typeEnumToName,
  type ZoneEntry,
  type ZoneFile,
} from './zone/zonefile.js';

// ─── Utilities ─────────────────────────────────────────────────

export {
  RRTypeInfo,
  classifyRecord,
  isStandardRecord,
  isDNSSECRecord,
  isMetaRecord,
  formatMessage,
  formatRR,
  toDigFormat,
} from './utils/format.js';

export {
  generateId,
  randomBytes,
  hexToBytes,
  bytesToHex,
  base64Encode,
  base64Decode,
  base64UrlEncode,
  base64UrlDecode,
} from './utils/encoding.js';
