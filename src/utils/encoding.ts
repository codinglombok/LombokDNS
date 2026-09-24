/**
 * LombokDNS — Encoding Utilities
 * Zero-dependency implementations of hex, base64, base64url
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 */

// ─── Random ────────────────────────────────────────────────────

/**
 * Generate a random 16-bit DNS message ID.
 */
export function generateId(): number {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    const arr = new Uint16Array(1);
    globalThis.crypto.getRandomValues(arr);
    return arr[0];
  }
  // Fallback (non-cryptographic, for environments without Web Crypto)
  return Math.floor(Math.random() * 0xFFFF);
}

/**
 * Generate random bytes.
 */
export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < length; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  return buf;
}

// ─── Hex ───────────────────────────────────────────────────────

const HEX_CHARS = '0123456789abcdef';

/**
 * Convert bytes to hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += HEX_CHARS[bytes[i] >> 4];
    hex += HEX_CHARS[bytes[i] & 0x0F];
  }
  return hex;
}

/**
 * Convert hex string to bytes.
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleaned = hex.replace(/\s/g, '');
  if (cleaned.length % 2 !== 0) {
    throw new RangeError('Hex string must have even length');
  }

  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    const high = parseHexDigit(cleaned.charCodeAt(i));
    const low  = parseHexDigit(cleaned.charCodeAt(i + 1));
    if (high === -1 || low === -1) {
      throw new RangeError(`Invalid hex character at position ${i}`);
    }
    bytes[i / 2] = (high << 4) | low;
  }
  return bytes;
}

function parseHexDigit(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;       // 0-9
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;  // A-F
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;  // a-f
  return -1;
}

// ─── Base64 (RFC 4648 §4) ──────────────────────────────────────

const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Encode bytes to standard Base64.
 */
export function base64Encode(bytes: Uint8Array): string {
  let result = '';
  const len = bytes.length;

  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;

    const triplet = (b0 << 16) | (b1 << 8) | b2;

    result += B64_CHARS[(triplet >> 18) & 0x3F];
    result += B64_CHARS[(triplet >> 12) & 0x3F];
    result += (i + 1 < len) ? B64_CHARS[(triplet >> 6) & 0x3F] : '=';
    result += (i + 2 < len) ? B64_CHARS[triplet & 0x3F] : '=';
  }

  return result;
}

/**
 * Decode standard Base64 to bytes.
 */
export function base64Decode(str: string): Uint8Array {
  const cleaned = str.replace(/[\s\r\n]/g, '');
  const padless = cleaned.replace(/=+$/, '');

  const outputLen = Math.floor(padless.length * 3 / 4);
  const bytes = new Uint8Array(outputLen);
  let byteIdx = 0;

  for (let i = 0; i < padless.length; i += 4) {
    const c0 = b64Val(padless.charCodeAt(i));
    const c1 = b64Val(padless.charCodeAt(i + 1));
    const c2 = i + 2 < padless.length ? b64Val(padless.charCodeAt(i + 2)) : 0;
    const c3 = i + 3 < padless.length ? b64Val(padless.charCodeAt(i + 3)) : 0;

    const triplet = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;

    if (byteIdx < outputLen) bytes[byteIdx++] = (triplet >> 16) & 0xFF;
    if (byteIdx < outputLen) bytes[byteIdx++] = (triplet >> 8) & 0xFF;
    if (byteIdx < outputLen) bytes[byteIdx++] = triplet & 0xFF;
  }

  return bytes;
}

function b64Val(code: number): number {
  if (code >= 65 && code <= 90) return code - 65;       // A-Z
  if (code >= 97 && code <= 122) return code - 97 + 26; // a-z
  if (code >= 48 && code <= 57) return code - 48 + 52;  // 0-9
  if (code === 43) return 62; // +
  if (code === 47) return 63; // /
  return 0;
}

// ─── Base64URL (RFC 4648 §5) — used by DoH ────────────────────

/**
 * Encode bytes to Base64URL (no padding, URL-safe alphabet).
 * Used by DNS-over-HTTPS (RFC 8484 §6).
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decode Base64URL to bytes.
 */
export function base64UrlDecode(str: string): Uint8Array {
  let padded = str
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  // Add padding
  const mod = padded.length % 4;
  if (mod === 2) padded += '==';
  else if (mod === 3) padded += '=';

  return base64Decode(padded);
}

// ─── DNS-specific encoding ─────────────────────────────────────

/**
 * Encode an IPv4 address string to 4 bytes.
 */
export function ipv4ToBytes(addr: string): Uint8Array {
  const parts = addr.split('.');
  if (parts.length !== 4) throw new RangeError('Invalid IPv4 address');
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const val = parseInt(parts[i], 10);
    if (isNaN(val) || val < 0 || val > 255) throw new RangeError(`Invalid IPv4 octet: ${parts[i]}`);
    bytes[i] = val;
  }
  return bytes;
}

/**
 * Decode 4 bytes to an IPv4 address string.
 */
export function bytesToIpv4(bytes: Uint8Array, offset = 0): string {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

/**
 * Encode an IPv6 address string to 16 bytes.
 * Supports :: shorthand expansion.
 */
export function ipv6ToBytes(addr: string): Uint8Array {
  const bytes = new Uint8Array(16);

  // Handle :: expansion
  let expanded = addr;
  if (expanded.includes('::')) {
    const parts = expanded.split('::');
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const fill = 8 - left.length - right.length;
    const middle = Array(fill).fill('0');
    expanded = [...left, ...middle, ...right].join(':');
  }

  const groups = expanded.split(':');
  if (groups.length !== 8) throw new RangeError('Invalid IPv6 address');

  for (let i = 0; i < 8; i++) {
    const val = parseInt(groups[i], 16);
    if (isNaN(val) || val < 0 || val > 0xFFFF) {
      throw new RangeError(`Invalid IPv6 group: ${groups[i]}`);
    }
    bytes[i * 2] = (val >> 8) & 0xFF;
    bytes[i * 2 + 1] = val & 0xFF;
  }

  return bytes;
}

/**
 * Decode 16 bytes to an IPv6 address string (no :: compression).
 */
export function bytesToIpv6(bytes: Uint8Array, offset = 0): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((bytes[offset + i] << 8) | bytes[offset + i + 1]).toString(16));
  }
  return groups.join(':');
}
