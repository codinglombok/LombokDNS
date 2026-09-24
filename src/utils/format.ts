/**
 * LombokDNS — Formatting Utilities
 * Human-readable output (dig/drill style)
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 */

import {
  type DNSMessage,
  type DNSResourceRecord,
  RRType,
  RRClass,
  Opcode,
  RCode,
  HeaderFlags,
} from '../core/types.js';
import {
  isResponse, isAuthoritative, isTruncated,
  isRecursionDesired, isRecursionAvailable,
  isAuthenticData, isCheckingDisabled,
  getOpcode, getRcode,
} from '../core/message.js';
import { typeEnumToName } from '../zone/zonefile.js';

// ─── Record Type Info ──────────────────────────────────────────

export interface RRTypeDesc {
  name: string;
  value: number;
  category: 'standard' | 'dnssec' | 'meta' | 'experimental' | 'obsolete';
  rfc: string;
  description: string;
}

export const RRTypeInfo: Record<number, RRTypeDesc> = {
  [RRType.A]:          { name: 'A',          value:  1,  category: 'standard', rfc: '1035', description: 'IPv4 address' },
  [RRType.NS]:         { name: 'NS',         value:  2,  category: 'standard', rfc: '1035', description: 'Authoritative name server' },
  [RRType.CNAME]:      { name: 'CNAME',      value:  5,  category: 'standard', rfc: '1035', description: 'Canonical name (alias)' },
  [RRType.SOA]:        { name: 'SOA',        value:  6,  category: 'standard', rfc: '1035', description: 'Start of authority' },
  [RRType.PTR]:        { name: 'PTR',        value: 12,  category: 'standard', rfc: '1035', description: 'Domain name pointer' },
  [RRType.HINFO]:      { name: 'HINFO',      value: 13,  category: 'standard', rfc: '1035', description: 'Host information' },
  [RRType.MX]:         { name: 'MX',         value: 15,  category: 'standard', rfc: '1035', description: 'Mail exchange' },
  [RRType.TXT]:        { name: 'TXT',        value: 16,  category: 'standard', rfc: '1035', description: 'Text strings' },
  [RRType.RP]:         { name: 'RP',         value: 17,  category: 'standard', rfc: '1183', description: 'Responsible person' },
  [RRType.AAAA]:       { name: 'AAAA',       value: 28,  category: 'standard', rfc: '3596', description: 'IPv6 address' },
  [RRType.LOC]:        { name: 'LOC',        value: 29,  category: 'standard', rfc: '1876', description: 'Location information' },
  [RRType.SRV]:        { name: 'SRV',        value: 33,  category: 'standard', rfc: '2782', description: 'Service locator' },
  [RRType.NAPTR]:      { name: 'NAPTR',      value: 35,  category: 'standard', rfc: '3403', description: 'Naming authority pointer' },
  [RRType.CERT]:       { name: 'CERT',       value: 37,  category: 'standard', rfc: '4398', description: 'Certificate record' },
  [RRType.DNAME]:      { name: 'DNAME',      value: 39,  category: 'standard', rfc: '6672', description: 'Delegation name' },
  [RRType.DS]:         { name: 'DS',         value: 43,  category: 'dnssec',   rfc: '4034', description: 'Delegation signer' },
  [RRType.SSHFP]:      { name: 'SSHFP',      value: 44,  category: 'standard', rfc: '4255', description: 'SSH fingerprint' },
  [RRType.RRSIG]:      { name: 'RRSIG',      value: 46,  category: 'dnssec',   rfc: '4034', description: 'DNSSEC signature' },
  [RRType.NSEC]:       { name: 'NSEC',       value: 47,  category: 'dnssec',   rfc: '4034', description: 'Next secure record' },
  [RRType.DNSKEY]:     { name: 'DNSKEY',     value: 48,  category: 'dnssec',   rfc: '4034', description: 'DNS public key' },
  [RRType.NSEC3]:      { name: 'NSEC3',      value: 50,  category: 'dnssec',   rfc: '5155', description: 'Hashed denial of existence' },
  [RRType.NSEC3PARAM]: { name: 'NSEC3PARAM', value: 51,  category: 'dnssec',   rfc: '5155', description: 'NSEC3 parameters' },
  [RRType.TLSA]:       { name: 'TLSA',       value: 52,  category: 'standard', rfc: '6698', description: 'TLS certificate association (DANE)' },
  [RRType.CDS]:        { name: 'CDS',        value: 59,  category: 'dnssec',   rfc: '7344', description: 'Child DS' },
  [RRType.CDNSKEY]:    { name: 'CDNSKEY',    value: 60,  category: 'dnssec',   rfc: '7344', description: 'Child DNSKEY' },
  [RRType.ZONEMD]:     { name: 'ZONEMD',     value: 63,  category: 'standard', rfc: '8976', description: 'Zone message digest' },
  [RRType.SVCB]:       { name: 'SVCB',       value: 64,  category: 'standard', rfc: '9460', description: 'Service binding' },
  [RRType.HTTPS]:      { name: 'HTTPS',      value: 65,  category: 'standard', rfc: '9460', description: 'HTTPS binding' },
  [RRType.URI]:        { name: 'URI',        value: 256, category: 'standard', rfc: '7553', description: 'URI' },
  [RRType.CAA]:        { name: 'CAA',        value: 257, category: 'standard', rfc: '8659', description: 'Certification authority authorization' },
  [RRType.OPT]:        { name: 'OPT',        value: 41,  category: 'meta',     rfc: '6891', description: 'EDNS(0) pseudo-record' },
  [RRType.TSIG]:       { name: 'TSIG',       value: 250, category: 'meta',     rfc: '8945', description: 'Transaction signature' },
  [RRType.AXFR]:       { name: 'AXFR',       value: 252, category: 'meta',     rfc: '5936', description: 'Full zone transfer' },
  [RRType.IXFR]:       { name: 'IXFR',       value: 251, category: 'meta',     rfc: '1995', description: 'Incremental zone transfer' },
  [RRType.ANY]:        { name: 'ANY',        value: 255, category: 'meta',     rfc: '1035', description: 'All records (QTYPE only)' },
};

export function classifyRecord(type: RRType): 'standard' | 'dnssec' | 'meta' | 'unknown' {
  const cat = RRTypeInfo[type]?.category;
  if (cat === 'standard' || cat === 'dnssec' || cat === 'meta') return cat;
  return 'unknown';
}

export function isStandardRecord(type: RRType): boolean {
  return classifyRecord(type) === 'standard';
}

export function isDNSSECRecord(type: RRType): boolean {
  return classifyRecord(type) === 'dnssec';
}

export function isMetaRecord(type: RRType): boolean {
  return classifyRecord(type) === 'meta';
}

// ─── Opcode & RCode names ──────────────────────────────────────

const OPCODE_NAMES: Record<number, string> = {
  [Opcode.QUERY]:  'QUERY',
  [Opcode.IQUERY]: 'IQUERY',
  [Opcode.STATUS]: 'STATUS',
  [Opcode.NOTIFY]: 'NOTIFY',
  [Opcode.UPDATE]: 'UPDATE',
  [Opcode.DSO]:    'DSO',
};

const RCODE_NAMES: Record<number, string> = {
  [RCode.NOERROR]:   'NOERROR',
  [RCode.FORMERR]:   'FORMERR',
  [RCode.SERVFAIL]:  'SERVFAIL',
  [RCode.NXDOMAIN]:  'NXDOMAIN',
  [RCode.NOTIMP]:    'NOTIMP',
  [RCode.REFUSED]:   'REFUSED',
  [RCode.YXDOMAIN]:  'YXDOMAIN',
  [RCode.YXRRSET]:   'YXRRSET',
  [RCode.NXRRSET]:   'NXRRSET',
  [RCode.NOTAUTH]:   'NOTAUTH',
  [RCode.NOTZONE]:   'NOTZONE',
  [RCode.BADVERS]:   'BADVERS',
  [RCode.BADKEY]:    'BADKEY',
  [RCode.BADTIME]:   'BADTIME',
  [RCode.BADCOOKIE]: 'BADCOOKIE',
};

const CLASS_NAMES: Record<number, string> = {
  [RRClass.IN]:   'IN',
  [RRClass.CS]:   'CS',
  [RRClass.CH]:   'CH',
  [RRClass.HS]:   'HS',
  [RRClass.NONE]: 'NONE',
  [RRClass.ANY]:  'ANY',
};

// ─── dig-style Output Formatting ───────────────────────────────

/**
 * Format a DNS message in dig/drill output style.
 */
export function toDigFormat(msg: DNSMessage, queryTime?: number, server?: string): string {
  const lines: string[] = [];
  const flags = msg.header.flags;

  // Header
  lines.push(`;; ->>HEADER<<- opcode: ${OPCODE_NAMES[getOpcode(flags)] ?? 'UNKNOWN'}, status: ${RCODE_NAMES[getRcode(flags)] ?? 'UNKNOWN'}, id: ${msg.header.id}`);

  const flagList: string[] = [];
  if (isResponse(flags))            flagList.push('qr');
  if (isAuthoritative(flags))       flagList.push('aa');
  if (isTruncated(flags))           flagList.push('tc');
  if (isRecursionDesired(flags))    flagList.push('rd');
  if (isRecursionAvailable(flags))  flagList.push('ra');
  if (isAuthenticData(flags))       flagList.push('ad');
  if (isCheckingDisabled(flags))    flagList.push('cd');

  lines.push(`;; flags: ${flagList.join(' ')}; QUERY: ${msg.questions.length}, ANSWER: ${msg.answers.length}, AUTHORITY: ${msg.authorities.length}, ADDITIONAL: ${msg.additionals.length}`);
  lines.push('');

  // Question section
  if (msg.questions.length > 0) {
    lines.push(';; QUESTION SECTION:');
    for (const q of msg.questions) {
      const typeName = typeEnumToName(q.type);
      const className = CLASS_NAMES[q.class] ?? `CLASS${q.class}`;
      lines.push(`;${q.name}.\t\t\t${className}\t${typeName}`);
    }
    lines.push('');
  }

  // Answer section
  if (msg.answers.length > 0) {
    lines.push(';; ANSWER SECTION:');
    for (const rr of msg.answers) lines.push(formatRR(rr));
    lines.push('');
  }

  // Authority section
  if (msg.authorities.length > 0) {
    lines.push(';; AUTHORITY SECTION:');
    for (const rr of msg.authorities) lines.push(formatRR(rr));
    lines.push('');
  }

  // Additional section
  if (msg.additionals.length > 0) {
    lines.push(';; ADDITIONAL SECTION:');
    for (const rr of msg.additionals) {
      if (rr.type === RRType.OPT) {
        lines.push(`;; OPT PSEUDOSECTION:`);
        lines.push(`; EDNS: version: ${(rr.ttl >>> 16) & 0xFF}, flags:${(rr.ttl & 0x8000) ? ' do' : ''}; udp: ${rr.class}`);
      } else {
        lines.push(formatRR(rr));
      }
    }
    lines.push('');
  }

  // Footer
  if (queryTime !== undefined) {
    lines.push(`;; Query time: ${queryTime} msec`);
  }
  if (server) {
    lines.push(`;; SERVER: ${server}`);
  }
  lines.push(`;; WHEN: ${new Date().toUTCString()}`);

  return lines.join('\n');
}

/**
 * Format a single resource record.
 */
export function formatRR(rr: DNSResourceRecord): string {
  const name = rr.name.endsWith('.') ? rr.name : rr.name + '.';
  const typeName = typeEnumToName(rr.type);
  const className = CLASS_NAMES[rr.class] ?? `CLASS${rr.class}`;
  const rdataStr = formatRData(rr.type, rr.rdata);

  return `${name}\t${rr.ttl}\t${className}\t${typeName}\t${rdataStr}`;
}

function formatRData(type: RRType, rdata: Uint8Array | Record<string, unknown>): string {
  if (rdata instanceof Uint8Array) {
    return `\\# ${rdata.length} ${Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('')}`;
  }

  switch (type) {
    case RRType.A:
    case RRType.AAAA:
      return rdata.address as string;

    case RRType.NS:
    case RRType.CNAME:
    case RRType.PTR:
    case RRType.DNAME:
      return (rdata.target as string) + '.';

    case RRType.MX:
      return `${rdata.preference} ${rdata.exchange}.`;

    case RRType.SOA:
      return `${rdata.mname}. ${rdata.rname}. ${rdata.serial} ${rdata.refresh} ${rdata.retry} ${rdata.expire} ${rdata.minimum}`;

    case RRType.TXT:
      return (rdata.texts as string[]).map(t => `"${t}"`).join(' ');

    case RRType.SRV:
      return `${rdata.priority} ${rdata.weight} ${rdata.port} ${rdata.target}.`;

    case RRType.CAA:
      return `${(rdata.critical as boolean) ? 128 : 0} ${rdata.tag} "${rdata.value}"`;

    case RRType.DS:
      return `${rdata.keyTag} ${rdata.algorithm} ${rdata.digestType} ${rdata.digest}`;

    case RRType.DNSKEY:
      return `${rdata.flags} ${rdata.protocol} ${rdata.algorithm} ${rdata.publicKey}`;

    case RRType.TLSA:
      return `${rdata.usage} ${rdata.selector} ${rdata.matchingType} ${rdata.certificate}`;

    case RRType.SSHFP:
      return `${rdata.algorithm} ${rdata.fpType} ${rdata.fingerprint}`;

    case RRType.SVCB:
    case RRType.HTTPS: {
      let s = `${rdata.priority} ${rdata.target}`;
      if (rdata.params && typeof rdata.params === 'object') {
        const p = rdata.params as Record<string, unknown>;
        for (const [k, v] of Object.entries(p)) {
          if (Array.isArray(v)) {
            s += ` ${k}="${v.join(',')}"`;
          } else if (v === true) {
            s += ` ${k}`;
          } else {
            s += ` ${k}="${v}"`;
          }
        }
      }
      return s;
    }

    default:
      return JSON.stringify(rdata);
  }
}

/**
 * Format a complete DNS message in a compact human-readable form.
 */
export function formatMessage(msg: DNSMessage): string {
  const parts: string[] = [];
  parts.push(`ID:${msg.header.id} ${RCODE_NAMES[getRcode(msg.header.flags)] ?? '?'}`);

  if (msg.questions.length > 0) {
    parts.push(`Q:[${msg.questions.map(q => `${q.name} ${typeEnumToName(q.type)}`).join(', ')}]`);
  }

  if (msg.answers.length > 0) {
    parts.push(`A:[${msg.answers.map(a => `${a.name} ${typeEnumToName(a.type)}`).join(', ')}]`);
  }

  return parts.join(' ');
}
