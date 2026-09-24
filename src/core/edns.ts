/**
 * LombokDNS — EDNS(0) Support
 * RFC 6891: Extension Mechanisms for DNS
 * RFC 8914: Extended DNS Errors (EDE)
 * RFC 7871: Client Subnet
 * RFC 7873: DNS Cookies
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 */

import {
  type DNSResourceRecord,
  type EDNSRecord,
  type EDNSOption,
  RRType,
  RRClass,
  EDNSOptionCode,
  EDECode,
  MAX_EDNS_UDP,
} from './types.js';

// ─── Helpers ───────────────────────────────────────────────────

function r16(b: Uint8Array, o: number): number { return (b[o] << 8) | b[o + 1]; }
function w16(b: Uint8Array, o: number, v: number): void { b[o] = (v >> 8) & 0xFF; b[o + 1] = v & 0xFF; }

// ─── Parse OPT pseudo-record ───────────────────────────────────

/**
 * Extract EDNS(0) information from the OPT pseudo-record in additionals.
 * RFC 6891 §6.1.2: The OPT record carries extended RCODE, version, flags,
 * and options in TTL+CLASS+RDATA.
 */
export function parseEDNS(rr: DNSResourceRecord): EDNSRecord {
  if (rr.type !== RRType.OPT) {
    throw new Error('Not an OPT record');
  }

  // CLASS = requestor's UDP payload size
  const udpSize = rr.class as number;

  // TTL encodes: extended RCODE (8), version (8), DO flag + reserved (16)
  const extRcode = (rr.ttl >>> 24) & 0xFF;
  const version  = (rr.ttl >>> 16) & 0xFF;
  const flags    = rr.ttl & 0xFFFF;

  // Parse EDNS options from RDATA
  const options: EDNSOption[] = [];
  if (rr.rdata instanceof Uint8Array) {
    let pos = 0;
    while (pos + 4 <= rr.rdata.length) {
      const code   = r16(rr.rdata, pos) as EDNSOptionCode;
      const length = r16(rr.rdata, pos + 2);
      pos += 4;

      if (pos + length > rr.rdata.length) break;

      options.push({
        code,
        length,
        data: rr.rdata.slice(pos, pos + length),
      });
      pos += length;
    }
  }

  return { udpSize, extRcode, version, flags, options };
}

/**
 * Build an OPT pseudo-record for inclusion in additionals.
 */
export function buildEDNS(edns: EDNSRecord): DNSResourceRecord {
  // Encode options to RDATA
  let rdataLen = 0;
  for (const opt of edns.options) {
    rdataLen += 4 + opt.data.length;
  }

  const rdata = new Uint8Array(rdataLen);
  let pos = 0;
  for (const opt of edns.options) {
    w16(rdata, pos, opt.code);
    w16(rdata, pos + 2, opt.data.length);
    rdata.set(opt.data, pos + 4);
    pos += 4 + opt.data.length;
  }

  // TTL encodes extended RCODE, version, flags
  const ttl = ((edns.extRcode & 0xFF) << 24) |
              ((edns.version & 0xFF) << 16) |
              (edns.flags & 0xFFFF);

  return {
    name: '',                    // root name (RFC 6891 §6.1.2)
    type: RRType.OPT,
    class: edns.udpSize as unknown as RRClass,
    ttl,
    rdlength: rdataLen,
    rdata,
  };
}

// ─── EDNS Option Builders ──────────────────────────────────────

/**
 * Build an Extended DNS Error option (RFC 8914).
 */
export function buildEDE(code: EDECode, extraText?: string): EDNSOption {
  const textBytes = extraText ? new TextEncoder().encode(extraText) : new Uint8Array(0);
  const data = new Uint8Array(2 + textBytes.length);
  w16(data, 0, code);
  data.set(textBytes, 2);

  return {
    code: EDNSOptionCode.EDE,
    length: data.length,
    data,
  };
}

/**
 * Parse an Extended DNS Error option.
 */
export function parseEDE(option: EDNSOption): { code: EDECode; text: string } {
  if (option.code !== EDNSOptionCode.EDE) {
    throw new Error('Not an EDE option');
  }
  const code = r16(option.data, 0) as EDECode;
  let text = '';
  for (let i = 2; i < option.data.length; i++) {
    text += String.fromCharCode(option.data[i]);
  }
  return { code, text };
}

/**
 * Build a Client Subnet option (RFC 7871).
 */
export function buildClientSubnet(
  family: 1 | 2,          // 1=IPv4, 2=IPv6
  sourcePrefixLen: number,
  scopePrefixLen: number,
  address: Uint8Array      // Truncated to sourcePrefixLen bits
): EDNSOption {
  const data = new Uint8Array(4 + address.length);
  w16(data, 0, family);
  data[2] = sourcePrefixLen;
  data[3] = scopePrefixLen;
  data.set(address, 4);

  return {
    code: EDNSOptionCode.CLIENT_SUBNET,
    length: data.length,
    data,
  };
}

/**
 * Parse a Client Subnet option.
 */
export function parseClientSubnet(option: EDNSOption): {
  family: number;
  sourcePrefixLen: number;
  scopePrefixLen: number;
  address: Uint8Array;
} {
  return {
    family: r16(option.data, 0),
    sourcePrefixLen: option.data[2],
    scopePrefixLen: option.data[3],
    address: option.data.slice(4),
  };
}

/**
 * Build a DNS Cookie option (RFC 7873).
 */
export function buildCookie(clientCookie: Uint8Array, serverCookie?: Uint8Array): EDNSOption {
  if (clientCookie.length !== 8) {
    throw new RangeError('Client cookie must be exactly 8 bytes');
  }
  if (serverCookie && (serverCookie.length < 8 || serverCookie.length > 32)) {
    throw new RangeError('Server cookie must be 8-32 bytes');
  }

  const len = 8 + (serverCookie ? serverCookie.length : 0);
  const data = new Uint8Array(len);
  data.set(clientCookie, 0);
  if (serverCookie) data.set(serverCookie, 8);

  return {
    code: EDNSOptionCode.COOKIE,
    length: len,
    data,
  };
}

/**
 * Parse a DNS Cookie option.
 */
export function parseCookie(option: EDNSOption): {
  clientCookie: Uint8Array;
  serverCookie: Uint8Array | null;
} {
  return {
    clientCookie: option.data.slice(0, 8),
    serverCookie: option.data.length > 8 ? option.data.slice(8) : null,
  };
}

/**
 * Build a Padding option (RFC 7830).
 */
export function buildPadding(paddingLength: number): EDNSOption {
  return {
    code: EDNSOptionCode.PADDING,
    length: paddingLength,
    data: new Uint8Array(paddingLength), // Zeros
  };
}

/**
 * Build an NSID option (RFC 5001).
 */
export function buildNSID(id?: Uint8Array): EDNSOption {
  return {
    code: EDNSOptionCode.NSID,
    length: id ? id.length : 0,
    data: id ?? new Uint8Array(0),
  };
}

/**
 * Build a TCP Keepalive option (RFC 7828).
 */
export function buildTCPKeepalive(timeout?: number): EDNSOption {
  const data = timeout !== undefined
    ? (() => { const d = new Uint8Array(2); w16(d, 0, timeout); return d; })()
    : new Uint8Array(0);

  return {
    code: EDNSOptionCode.TCP_KEEPALIVE,
    length: data.length,
    data,
  };
}

// ─── Convenience: find EDNS in additionals ─────────────────────

/**
 * Extract EDNS from a message's additional section.
 * Returns null if no OPT record is present.
 */
export function findEDNS(additionals: DNSResourceRecord[]): EDNSRecord | null {
  for (const rr of additionals) {
    if (rr.type === RRType.OPT) {
      return parseEDNS(rr);
    }
  }
  return null;
}

/**
 * Create default EDNS(0) settings for a query.
 */
export function defaultEDNS(opts?: {
  udpSize?: number;
  dnssecOK?: boolean;
  options?: EDNSOption[];
}): EDNSRecord {
  return {
    udpSize: opts?.udpSize ?? MAX_EDNS_UDP,
    extRcode: 0,
    version: 0,
    flags: (opts?.dnssecOK ? 0x8000 : 0), // DO bit
    options: opts?.options ?? [],
  };
}

// ─── EDE Code Descriptions (i18n-ready) ────────────────────────

const EDE_DESCRIPTIONS: Record<EDECode, string> = {
  [EDECode.OTHER]:                    'Other',
  [EDECode.UNSUPPORTED_DNSKEY_ALG]:   'Unsupported DNSKEY algorithm',
  [EDECode.UNSUPPORTED_DS_DIGEST]:    'Unsupported DS digest type',
  [EDECode.STALE_ANSWER]:             'Stale answer',
  [EDECode.FORGED_ANSWER]:            'Forged answer',
  [EDECode.DNSSEC_INDETERMINATE]:     'DNSSEC indeterminate',
  [EDECode.DNSSEC_BOGUS]:             'DNSSEC validation failure',
  [EDECode.SIGNATURE_EXPIRED]:        'Signature expired',
  [EDECode.SIGNATURE_NOT_YET_VALID]:  'Signature not yet valid',
  [EDECode.DNSKEY_MISSING]:           'DNSKEY missing',
  [EDECode.RRSIGS_MISSING]:           'RRSIGs missing',
  [EDECode.NO_ZONE_KEY_BIT_SET]:      'No zone key bit set',
  [EDECode.NSEC_MISSING]:             'NSEC missing',
  [EDECode.CACHED_ERROR]:             'Cached error',
  [EDECode.NOT_READY]:                'Not ready',
  [EDECode.BLOCKED]:                  'Blocked',
  [EDECode.CENSORED]:                 'Censored',
  [EDECode.FILTERED]:                 'Filtered',
  [EDECode.PROHIBITED]:               'Prohibited',
  [EDECode.STALE_NXDOMAIN_ANSWER]:    'Stale NXDOMAIN answer',
  [EDECode.NOT_AUTHORITATIVE]:        'Not authoritative',
  [EDECode.NOT_SUPPORTED]:            'Not supported',
  [EDECode.NO_REACHABLE_AUTHORITY]:    'No reachable authority',
  [EDECode.NETWORK_ERROR]:            'Network error',
  [EDECode.INVALID_DATA]:             'Invalid data',
  [EDECode.SIGNATURE_EXPIRED_BEFORE_VALID]: 'Signature expired before valid',
  [EDECode.TOO_EARLY]:                'Too early',
  [EDECode.UNSUPPORTED_NSEC3_ITERATIONS]: 'Unsupported NSEC3 iterations count',
  [EDECode.UNABLE_TO_CONFORM_TO_POLICY]:  'Unable to conform to policy',
  [EDECode.SYNTHESIZED]:              'Synthesized',
};

export function describeEDE(code: EDECode): string {
  return EDE_DESCRIPTIONS[code] ?? `Unknown EDE code ${code}`;
}
