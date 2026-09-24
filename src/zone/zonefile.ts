/**
 * LombokDNS — Zone File Parser
 * RFC 1035 §5: Master File Format
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 */

import { RRType, RRClass, type DNSResourceRecord } from '../core/types.js';
import { encodeName } from '../core/name.js';

// ─── Types ─────────────────────────────────────────────────────

export interface ZoneEntry {
  name: string;
  ttl: number;
  class: RRClass;
  type: RRType;
  rdata: Record<string, unknown>;
}

export interface ZoneFile {
  origin: string;
  defaultTTL: number;
  entries: ZoneEntry[];
}

// ─── RRType name ↔ enum mapping ────────────────────────────────

const TYPE_NAMES: Record<string, RRType> = {
  A: RRType.A, NS: RRType.NS, CNAME: RRType.CNAME, SOA: RRType.SOA,
  PTR: RRType.PTR, HINFO: RRType.HINFO, MX: RRType.MX, TXT: RRType.TXT,
  RP: RRType.RP, AFSDB: RRType.AFSDB, AAAA: RRType.AAAA, LOC: RRType.LOC,
  SRV: RRType.SRV, NAPTR: RRType.NAPTR, KX: RRType.KX, CERT: RRType.CERT,
  DNAME: RRType.DNAME, DS: RRType.DS, SSHFP: RRType.SSHFP,
  IPSECKEY: RRType.IPSECKEY, RRSIG: RRType.RRSIG, NSEC: RRType.NSEC,
  DNSKEY: RRType.DNSKEY, DHCID: RRType.DHCID, NSEC3: RRType.NSEC3,
  NSEC3PARAM: RRType.NSEC3PARAM, TLSA: RRType.TLSA, SMIMEA: RRType.SMIMEA,
  HIP: RRType.HIP, CDS: RRType.CDS, CDNSKEY: RRType.CDNSKEY,
  OPENPGPKEY: RRType.OPENPGPKEY, CSYNC: RRType.CSYNC, ZONEMD: RRType.ZONEMD,
  SVCB: RRType.SVCB, HTTPS: RRType.HTTPS, EUI48: RRType.EUI48,
  EUI64: RRType.EUI64, URI: RRType.URI, CAA: RRType.CAA, AVC: RRType.AVC,
};

const CLASS_NAMES: Record<string, RRClass> = {
  IN: RRClass.IN, CS: RRClass.CS, CH: RRClass.CH, HS: RRClass.HS,
};

export function typeNameToEnum(name: string): RRType | undefined {
  return TYPE_NAMES[name.toUpperCase()];
}

export function typeEnumToName(type: RRType): string {
  for (const [name, val] of Object.entries(TYPE_NAMES)) {
    if (val === type) return name;
  }
  return `TYPE${type}`;
}

// ─── Zone File Parser ──────────────────────────────────────────

/**
 * Parse an RFC 1035 zone file string into structured records.
 *
 * Supports:
 * - $ORIGIN directive
 * - $TTL directive
 * - Name inheritance (blank name = previous name)
 * - Parenthesized multi-line records
 * - Comments (;)
 * - Common record types
 */
export function parseZoneFile(text: string, defaultOrigin = '.'): ZoneFile {
  const lines = text.split('\n');
  let origin = defaultOrigin.endsWith('.') ? defaultOrigin : defaultOrigin + '.';
  let defaultTTL = 86400; // 1 day
  let lastName = '';
  const entries: ZoneEntry[] = [];

  // Pre-process: join parenthesized multi-line records
  const joined: string[] = [];
  let accumulator = '';
  let inParens = false;

  for (const rawLine of lines) {
    // Strip comments (but not inside quoted strings)
    const line = stripComment(rawLine);

    if (inParens) {
      accumulator += ' ' + line.trim();
      if (line.includes(')')) {
        inParens = false;
        accumulator = accumulator.replace(/[()]/g, '');
        joined.push(accumulator);
        accumulator = '';
      }
    } else if (line.includes('(') && !line.includes(')')) {
      inParens = true;
      accumulator = line;
    } else {
      const cleaned = line.replace(/[()]/g, '');
      if (cleaned.trim()) joined.push(cleaned);
    }
  }

  for (const line of joined) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // $ORIGIN directive
    if (trimmed.startsWith('$ORIGIN')) {
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2) {
        origin = parts[1].endsWith('.') ? parts[1] : parts[1] + '.';
      }
      continue;
    }

    // $TTL directive
    if (trimmed.startsWith('$TTL')) {
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2) {
        defaultTTL = parseTTL(parts[1]);
      }
      continue;
    }

    // $INCLUDE not supported (security risk)
    if (trimmed.startsWith('$INCLUDE')) continue;

    // Parse resource record
    const entry = parseRRLine(trimmed, origin, defaultTTL, lastName);
    if (entry) {
      lastName = entry.name;
      entries.push(entry);
    }
  }

  return { origin, defaultTTL, entries };
}

// ─── RR Line Parser ────────────────────────────────────────────

function parseRRLine(
  line: string,
  origin: string,
  defaultTTL: number,
  lastName: string
): ZoneEntry | null {
  const tokens = tokenize(line);
  if (tokens.length < 3) return null;

  let idx = 0;
  let name: string;
  let ttl = defaultTTL;
  let rrclass = RRClass.IN;

  // Determine name
  if (/^\s/.test(line)) {
    // Blank name → inherit
    name = lastName;
  } else {
    name = qualifyName(tokens[idx++], origin);
  }

  // Look for TTL and/or class (in either order)
  while (idx < tokens.length) {
    const upper = tokens[idx].toUpperCase();

    if (CLASS_NAMES[upper] !== undefined) {
      rrclass = CLASS_NAMES[upper];
      idx++;
    } else if (/^\d+$/.test(tokens[idx]) || /^\d+[smhdwSMHDW]$/.test(tokens[idx])) {
      // Could be TTL
      const prospectiveTTL = parseTTL(tokens[idx]);
      // Disambiguate: if next token is a type name, this is TTL
      if (idx + 1 < tokens.length && TYPE_NAMES[tokens[idx + 1].toUpperCase()]) {
        ttl = prospectiveTTL;
        idx++;
      } else {
        break;
      }
    } else {
      break;
    }
  }

  if (idx >= tokens.length) return null;

  // Type
  const typeName = tokens[idx++].toUpperCase();
  const type = TYPE_NAMES[typeName];
  if (type === undefined) return null;

  // Remaining tokens = RDATA
  const rdataTokens = tokens.slice(idx);
  const rdata = parseRDataTokens(type, rdataTokens, origin);

  return { name, ttl, class: rrclass, type, rdata };
}

// ─── RDATA Parsers (from zone file tokens) ─────────────────────

function parseRDataTokens(
  type: RRType,
  tokens: string[],
  origin: string
): Record<string, unknown> {
  switch (type) {
    case RRType.A:
      return { address: tokens[0] };

    case RRType.AAAA:
      return { address: tokens[0] };

    case RRType.NS:
    case RRType.CNAME:
    case RRType.PTR:
    case RRType.DNAME:
      return { target: qualifyName(tokens[0], origin) };

    case RRType.MX:
      return {
        preference: parseInt(tokens[0], 10),
        exchange: qualifyName(tokens[1], origin),
      };

    case RRType.SOA:
      return {
        mname:   qualifyName(tokens[0], origin),
        rname:   qualifyName(tokens[1], origin),
        serial:  parseInt(tokens[2], 10),
        refresh: parseTTL(tokens[3]),
        retry:   parseTTL(tokens[4]),
        expire:  parseTTL(tokens[5]),
        minimum: parseTTL(tokens[6]),
      };

    case RRType.TXT:
      // TXT records: tokens may be quoted strings
      return { texts: tokens.map(t => t.replace(/^"(.*)"$/, '$1')) };

    case RRType.SRV:
      return {
        priority: parseInt(tokens[0], 10),
        weight:   parseInt(tokens[1], 10),
        port:     parseInt(tokens[2], 10),
        target:   qualifyName(tokens[3], origin),
      };

    case RRType.CAA:
      return {
        critical: parseInt(tokens[0], 10) === 128,
        tag:      tokens[1],
        value:    tokens.slice(2).join(' ').replace(/^"(.*)"$/, '$1'),
      };

    case RRType.DS:
      return {
        keyTag:     parseInt(tokens[0], 10),
        algorithm:  parseInt(tokens[1], 10),
        digestType: parseInt(tokens[2], 10),
        digest:     tokens.slice(3).join('').toLowerCase(),
      };

    case RRType.TLSA:
      return {
        usage:        parseInt(tokens[0], 10),
        selector:     parseInt(tokens[1], 10),
        matchingType: parseInt(tokens[2], 10),
        certificate:  tokens.slice(3).join('').toLowerCase(),
      };

    case RRType.SSHFP:
      return {
        algorithm:   parseInt(tokens[0], 10),
        fpType:      parseInt(tokens[1], 10),
        fingerprint: tokens.slice(2).join('').toLowerCase(),
      };

    case RRType.SVCB:
    case RRType.HTTPS: {
      const priority = parseInt(tokens[0], 10);
      const target = qualifyName(tokens[1], origin);
      const params: Record<string, unknown> = {};
      for (let i = 2; i < tokens.length; i++) {
        const eqIdx = tokens[i].indexOf('=');
        if (eqIdx !== -1) {
          const key = tokens[i].substring(0, eqIdx);
          const val = tokens[i].substring(eqIdx + 1);
          params[key] = val;
        }
      }
      return { priority, target, params };
    }

    default:
      return { raw: tokens.join(' ') };
  }
}

// ─── Zone File Serializer ──────────────────────────────────────

/**
 * Serialize a ZoneFile back to RFC 1035 zone file text format.
 */
export function serializeZoneFile(zone: ZoneFile): string {
  const lines: string[] = [];

  lines.push(`$ORIGIN ${zone.origin}`);
  lines.push(`$TTL ${zone.defaultTTL}`);
  lines.push('');

  let prevName = '';
  for (const entry of zone.entries) {
    const name = entry.name === prevName ? '' : entry.name;
    prevName = entry.name;

    const className = Object.entries(CLASS_NAMES)
      .find(([, v]) => v === entry.class)?.[0] ?? 'IN';
    const typeName = typeEnumToName(entry.type);

    const rdataStr = serializeRData(entry.type, entry.rdata);

    if (entry.type === RRType.SOA) {
      // SOA gets multi-line formatting
      const r = entry.rdata;
      lines.push(`${padRight(name, 24)} ${entry.ttl} ${className} ${typeName} ${r.mname} ${r.rname} (`);
      lines.push(`                        ${r.serial}   ; Serial`);
      lines.push(`                        ${r.refresh}   ; Refresh`);
      lines.push(`                        ${r.retry}    ; Retry`);
      lines.push(`                        ${r.expire}  ; Expire`);
      lines.push(`                        ${r.minimum} ) ; Minimum TTL`);
    } else {
      lines.push(`${padRight(name, 24)} ${entry.ttl} ${className} ${padRight(typeName, 6)} ${rdataStr}`);
    }
  }

  return lines.join('\n') + '\n';
}

function serializeRData(type: RRType, rdata: Record<string, unknown>): string {
  switch (type) {
    case RRType.A:
    case RRType.AAAA:
      return rdata.address as string;
    case RRType.NS:
    case RRType.CNAME:
    case RRType.PTR:
    case RRType.DNAME:
      return rdata.target as string;
    case RRType.MX:
      return `${rdata.preference} ${rdata.exchange}`;
    case RRType.TXT:
      return (rdata.texts as string[]).map(t => `"${t}"`).join(' ');
    case RRType.SRV:
      return `${rdata.priority} ${rdata.weight} ${rdata.port} ${rdata.target}`;
    case RRType.CAA:
      return `${(rdata.critical as boolean) ? 128 : 0} ${rdata.tag} "${rdata.value}"`;
    case RRType.DS:
      return `${rdata.keyTag} ${rdata.algorithm} ${rdata.digestType} ${rdata.digest}`;
    case RRType.TLSA:
      return `${rdata.usage} ${rdata.selector} ${rdata.matchingType} ${rdata.certificate}`;
    case RRType.SSHFP:
      return `${rdata.algorithm} ${rdata.fpType} ${rdata.fingerprint}`;
    default:
      return rdata.raw as string ?? JSON.stringify(rdata);
  }
}

// ─── Utilities ─────────────────────────────────────────────────

function stripComment(line: string): string {
  let inQuote = false;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '"') inQuote = !inQuote;
    if (line[i] === ';' && !inQuote) return line.substring(0, i);
  }
  return line;
}

function tokenize(line: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inQuote = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      inQuote = !inQuote;
      current += ch;
    } else if (/\s/.test(ch) && !inQuote) {
      if (current) { tokens.push(current); current = ''; }
    } else {
      current += ch;
    }
  }
  if (current) tokens.push(current);

  return tokens;
}

function qualifyName(name: string, origin: string): string {
  if (name === '@') return origin;
  if (name.endsWith('.')) return name;
  return name + '.' + origin;
}

function parseTTL(s: string): number {
  const match = s.match(/^(\d+)([smhdwSMHDW])?$/);
  if (!match) return parseInt(s, 10) || 0;

  const num = parseInt(match[1], 10);
  const unit = (match[2] || 's').toLowerCase();

  switch (unit) {
    case 's': return num;
    case 'm': return num * 60;
    case 'h': return num * 3600;
    case 'd': return num * 86400;
    case 'w': return num * 604800;
    default:  return num;
  }
}

function padRight(s: string, len: number): string {
  return s + ' '.repeat(Math.max(0, len - s.length));
}
