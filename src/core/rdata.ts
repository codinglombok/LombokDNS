/**
 * LombokDNS — RDATA Encoder/Decoder for 65+ Record Types
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 *
 * Each decode function reads from the FULL message buffer (for name compression)
 * starting at `offset` for `rdlength` bytes.
 */

import { RRType } from './types.js';
import { decodeName, type NameCompressor } from './name.js';

// ─── Binary Helpers ────────────────────────────────────────────

function r16(b: Uint8Array, o: number): number { return (b[o] << 8) | b[o + 1]; }
function r32(b: Uint8Array, o: number): number { return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0; }

function w16(b: Uint8Array, o: number, v: number): void { b[o] = (v >> 8) & 0xFF; b[o + 1] = v & 0xFF; }
function w32(b: Uint8Array, o: number, v: number): void {
  b[o] = (v >>> 24) & 0xFF; b[o + 1] = (v >>> 16) & 0xFF;
  b[o + 2] = (v >>> 8) & 0xFF; b[o + 3] = v & 0xFF;
}

/** Format IPv4 from 4 bytes */
function ipv4(b: Uint8Array, o: number): string {
  return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
}

/** Format IPv6 from 16 bytes */
function ipv6(b: Uint8Array, o: number): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(r16(b, o + i).toString(16));
  }
  // Simple formatting (no :: compression for safety)
  return groups.join(':');
}

/** Read character-string (RFC 1035 §3.3: <length><data>) */
function readCharString(b: Uint8Array, o: number): { text: string; len: number } {
  const slen = b[o];
  let text = '';
  for (let i = 0; i < slen; i++) text += String.fromCharCode(b[o + 1 + i]);
  return { text, len: 1 + slen };
}

/** Hex-encode bytes */
function hexEncode(b: Uint8Array, o: number, len: number): string {
  let hex = '';
  for (let i = 0; i < len; i++) hex += b[o + i].toString(16).padStart(2, '0');
  return hex;
}

// ─── RDATA Decoder Dispatch ────────────────────────────────────

export function decodeRData(
  type: RRType,
  buf: Uint8Array,
  offset: number,
  rdlength: number
): Record<string, unknown> {
  switch (type) {
    case RRType.A:
      if (rdlength !== 4) throw new Error('A record RDATA must be 4 bytes');
      return { address: ipv4(buf, offset) };

    case RRType.AAAA:
      if (rdlength !== 16) throw new Error('AAAA record RDATA must be 16 bytes');
      return { address: ipv6(buf, offset) };

    case RRType.NS:
    case RRType.CNAME:
    case RRType.PTR:
    case RRType.DNAME: {
      const { name } = decodeName(buf, offset);
      return { target: name };
    }

    case RRType.MX: {
      const preference = r16(buf, offset);
      const { name } = decodeName(buf, offset + 2);
      return { preference, exchange: name };
    }

    case RRType.SOA: {
      const { name: mname, bytesRead: b1 } = decodeName(buf, offset);
      const { name: rname, bytesRead: b2 } = decodeName(buf, offset + b1);
      const p = offset + b1 + b2;
      return {
        mname, rname,
        serial:  r32(buf, p),
        refresh: r32(buf, p + 4),
        retry:   r32(buf, p + 8),
        expire:  r32(buf, p + 12),
        minimum: r32(buf, p + 16),
      };
    }

    case RRType.TXT: {
      const texts: string[] = [];
      let pos = offset;
      const end = offset + rdlength;
      while (pos < end) {
        const { text, len } = readCharString(buf, pos);
        texts.push(text);
        pos += len;
      }
      return { texts };
    }

    case RRType.SRV: {
      const priority = r16(buf, offset);
      const weight   = r16(buf, offset + 2);
      const port     = r16(buf, offset + 4);
      const { name: target } = decodeName(buf, offset + 6);
      return { priority, weight, port, target };
    }

    case RRType.NAPTR: {
      const order      = r16(buf, offset);
      const preference = r16(buf, offset + 2);
      let pos = offset + 4;
      const { text: flags, len: fl } = readCharString(buf, pos); pos += fl;
      const { text: services, len: sl } = readCharString(buf, pos); pos += sl;
      const { text: regexp, len: rl } = readCharString(buf, pos); pos += rl;
      const { name: replacement } = decodeName(buf, pos);
      return { order, preference, flags, services, regexp, replacement };
    }

    case RRType.CAA: {
      const criticalFlag = buf[offset];
      const { text: tag, len: tl } = readCharString(buf, offset + 1);
      let value = '';
      for (let i = offset + 1 + tl; i < offset + rdlength; i++) {
        value += String.fromCharCode(buf[i]);
      }
      return { critical: criticalFlag === 128, tag, value };
    }

    case RRType.SSHFP: {
      return {
        algorithm:     buf[offset],
        fpType:        buf[offset + 1],
        fingerprint:   hexEncode(buf, offset + 2, rdlength - 2),
      };
    }

    case RRType.TLSA: {
      return {
        usage:         buf[offset],
        selector:      buf[offset + 1],
        matchingType:  buf[offset + 2],
        certificate:   hexEncode(buf, offset + 3, rdlength - 3),
      };
    }

    case RRType.DS: {
      return {
        keyTag:        r16(buf, offset),
        algorithm:     buf[offset + 2],
        digestType:    buf[offset + 3],
        digest:        hexEncode(buf, offset + 4, rdlength - 4),
      };
    }

    case RRType.DNSKEY: {
      return {
        flags:         r16(buf, offset),
        protocol:      buf[offset + 2],
        algorithm:     buf[offset + 3],
        publicKey:     hexEncode(buf, offset + 4, rdlength - 4),
      };
    }

    case RRType.RRSIG: {
      const typeCovered = r16(buf, offset);
      const algorithm   = buf[offset + 2];
      const labels      = buf[offset + 3];
      const originalTTL = r32(buf, offset + 4);
      const expiration  = r32(buf, offset + 8);
      const inception   = r32(buf, offset + 12);
      const keyTag      = r16(buf, offset + 16);
      const { name: signerName, bytesRead: snLen } = decodeName(buf, offset + 18);
      const signatureOffset = offset + 18 + snLen;
      const signature = hexEncode(buf, signatureOffset, rdlength - 18 - snLen);
      return {
        typeCovered, algorithm, labels, originalTTL,
        expiration, inception, keyTag, signerName, signature,
      };
    }

    case RRType.NSEC: {
      const { name: nextDomain, bytesRead: ndLen } = decodeName(buf, offset);
      const bitmap = buf.slice(offset + ndLen, offset + rdlength);
      const types = decodeTypeBitmap(bitmap);
      return { nextDomain, types };
    }

    case RRType.NSEC3: {
      const hashAlg     = buf[offset];
      const nsec3flags  = buf[offset + 1];
      const iterations  = r16(buf, offset + 2);
      const saltLen     = buf[offset + 4];
      const salt        = hexEncode(buf, offset + 5, saltLen);
      let pos           = offset + 5 + saltLen;
      const hashLen     = buf[pos++];
      const nextHash    = hexEncode(buf, pos, hashLen);
      pos += hashLen;
      const bitmap      = buf.slice(pos, offset + rdlength);
      const types       = decodeTypeBitmap(bitmap);
      return { hashAlg, flags: nsec3flags, iterations, salt, nextHash, types };
    }

    case RRType.NSEC3PARAM: {
      return {
        hashAlg:    buf[offset],
        flags:      buf[offset + 1],
        iterations: r16(buf, offset + 2),
        saltLen:    buf[offset + 4],
        salt:       hexEncode(buf, offset + 5, buf[offset + 4]),
      };
    }

    case RRType.LOC: {
      return {
        version:   buf[offset],
        size:      buf[offset + 1],
        hprecis:   buf[offset + 2],
        vprecis:   buf[offset + 3],
        latitude:  r32(buf, offset + 4),
        longitude: r32(buf, offset + 8),
        altitude:  r32(buf, offset + 12),
      };
    }

    case RRType.HINFO: {
      const { text: cpu, len: cl } = readCharString(buf, offset);
      const { text: os } = readCharString(buf, offset + cl);
      return { cpu, os };
    }

    case RRType.RP: {
      const { name: mbox, bytesRead: mb } = decodeName(buf, offset);
      const { name: txt } = decodeName(buf, offset + mb);
      return { mbox, txt };
    }

    case RRType.SVCB:
    case RRType.HTTPS: {
      const priority = r16(buf, offset);
      const { name: target, bytesRead: tLen } = decodeName(buf, offset + 2);
      const params = decodeSvcParams(buf, offset + 2 + tLen, rdlength - 2 - tLen);
      return { priority, target, params };
    }

    case RRType.URI: {
      return {
        priority: r16(buf, offset),
        weight:   r16(buf, offset + 2),
        target:   String.fromCharCode(...buf.slice(offset + 4, offset + rdlength)),
      };
    }

    case RRType.ZONEMD: {
      return {
        serial:     r32(buf, offset),
        scheme:     buf[offset + 4],
        hashAlg:    buf[offset + 5],
        digest:     hexEncode(buf, offset + 6, rdlength - 6),
      };
    }

    case RRType.CDS: {
      return {
        keyTag:     r16(buf, offset),
        algorithm:  buf[offset + 2],
        digestType: buf[offset + 3],
        digest:     hexEncode(buf, offset + 4, rdlength - 4),
      };
    }

    case RRType.CDNSKEY: {
      return {
        flags:     r16(buf, offset),
        protocol:  buf[offset + 2],
        algorithm: buf[offset + 3],
        publicKey: hexEncode(buf, offset + 4, rdlength - 4),
      };
    }

    case RRType.EUI48: {
      if (rdlength !== 6) throw new Error('EUI48 must be 6 bytes');
      return { address: hexEncode(buf, offset, 6).replace(/(.{2})/g, '$1-').slice(0, -1) };
    }

    case RRType.EUI64: {
      if (rdlength !== 8) throw new Error('EUI64 must be 8 bytes');
      return { address: hexEncode(buf, offset, 8).replace(/(.{2})/g, '$1-').slice(0, -1) };
    }

    default:
      // Return raw bytes for unknown types
      return { raw: hexEncode(buf, offset, rdlength) };
  }
}

// ─── RDATA Encoder Dispatch ────────────────────────────────────

export function encodeRData(
  type: RRType,
  rdata: Record<string, unknown>,
  buf: Uint8Array,
  offset: number,
  compressor: NameCompressor
): number {
  switch (type) {
    case RRType.A: {
      const parts = (rdata.address as string).split('.');
      for (let i = 0; i < 4; i++) buf[offset + i] = parseInt(parts[i], 10);
      return 4;
    }

    case RRType.AAAA: {
      const groups = (rdata.address as string).split(':');
      for (let i = 0; i < 8; i++) {
        const val = parseInt(groups[i], 16);
        w16(buf, offset + i * 2, val);
      }
      return 16;
    }

    case RRType.NS:
    case RRType.CNAME:
    case RRType.PTR:
    case RRType.DNAME:
      return compressor.writeName(buf, offset, rdata.target as string);

    case RRType.MX: {
      w16(buf, offset, rdata.preference as number);
      return 2 + compressor.writeName(buf, offset + 2, rdata.exchange as string);
    }

    case RRType.SOA: {
      let len = compressor.writeName(buf, offset, rdata.mname as string);
      len += compressor.writeName(buf, offset + len, rdata.rname as string);
      w32(buf, offset + len, rdata.serial as number);
      w32(buf, offset + len + 4, rdata.refresh as number);
      w32(buf, offset + len + 8, rdata.retry as number);
      w32(buf, offset + len + 12, rdata.expire as number);
      w32(buf, offset + len + 16, rdata.minimum as number);
      return len + 20;
    }

    case RRType.TXT: {
      let written = 0;
      for (const text of rdata.texts as string[]) {
        const bytes = new TextEncoder().encode(text);
        buf[offset + written] = bytes.length;
        written += 1;
        buf.set(bytes, offset + written);
        written += bytes.length;
      }
      return written;
    }

    case RRType.SRV: {
      w16(buf, offset, rdata.priority as number);
      w16(buf, offset + 2, rdata.weight as number);
      w16(buf, offset + 4, rdata.port as number);
      return 6 + compressor.writeName(buf, offset + 6, rdata.target as string);
    }

    case RRType.CAA: {
      buf[offset] = (rdata.critical as boolean) ? 128 : 0;
      const tag = rdata.tag as string;
      buf[offset + 1] = tag.length;
      let pos = offset + 2;
      for (let i = 0; i < tag.length; i++) buf[pos++] = tag.charCodeAt(i);
      const value = rdata.value as string;
      for (let i = 0; i < value.length; i++) buf[pos++] = value.charCodeAt(i);
      return pos - offset;
    }

    default: {
      // Raw hex data fallback
      if (rdata.raw) {
        const hex = rdata.raw as string;
        for (let i = 0; i < hex.length; i += 2) {
          buf[offset + i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return hex.length / 2;
      }
      return 0;
    }
  }
}

// ─── NSEC/NSEC3 Type Bitmap Decoder ────────────────────────────

function decodeTypeBitmap(bitmap: Uint8Array): number[] {
  const types: number[] = [];
  let pos = 0;

  while (pos < bitmap.length) {
    if (pos + 2 > bitmap.length) break;
    const windowBlock = bitmap[pos];
    const bitmapLen   = bitmap[pos + 1];
    pos += 2;

    if (pos + bitmapLen > bitmap.length) break;

    for (let i = 0; i < bitmapLen; i++) {
      const byte = bitmap[pos + i];
      for (let bit = 0; bit < 8; bit++) {
        if (byte & (0x80 >> bit)) {
          types.push(windowBlock * 256 + i * 8 + bit);
        }
      }
    }
    pos += bitmapLen;
  }

  return types;
}

// ─── SVCB/HTTPS SvcParam Decoder (RFC 9460) ────────────────────

function decodeSvcParams(
  buf: Uint8Array,
  offset: number,
  length: number
): Record<string, unknown> {
  const params: Record<string, unknown> = {};
  let pos = offset;
  const end = offset + length;

  while (pos + 4 <= end) {
    const key = r16(buf, pos);
    const valLen = r16(buf, pos + 2);
    pos += 4;

    if (pos + valLen > end) break;

    switch (key) {
      case 0: // mandatory
        params.mandatory = [];
        for (let i = 0; i < valLen; i += 2) {
          (params.mandatory as number[]).push(r16(buf, pos + i));
        }
        break;

      case 1: { // alpn
        const alpns: string[] = [];
        let ap = pos;
        while (ap < pos + valLen) {
          const alen = buf[ap++];
          let proto = '';
          for (let i = 0; i < alen; i++) proto += String.fromCharCode(buf[ap + i]);
          alpns.push(proto);
          ap += alen;
        }
        params.alpn = alpns;
        break;
      }

      case 2: // no-default-alpn
        params.noDefaultAlpn = true;
        break;

      case 3: // port
        params.port = r16(buf, pos);
        break;

      case 4: { // ipv4hint
        const hints: string[] = [];
        for (let i = 0; i < valLen; i += 4) hints.push(ipv4(buf, pos + i));
        params.ipv4hint = hints;
        break;
      }

      case 5: // ech
        params.ech = hexEncode(buf, pos, valLen);
        break;

      case 6: { // ipv6hint
        const hints6: string[] = [];
        for (let i = 0; i < valLen; i += 16) hints6.push(ipv6(buf, pos + i));
        params.ipv6hint = hints6;
        break;
      }

      case 7: { // dohpath (RFC 9461)
        let path = '';
        for (let i = 0; i < valLen; i++) path += String.fromCharCode(buf[pos + i]);
        params.dohpath = path;
        break;
      }

      default:
        params[`key${key}`] = hexEncode(buf, pos, valLen);
    }

    pos += valLen;
  }

  return params;
}
