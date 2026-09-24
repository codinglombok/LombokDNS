/**
 * LombokDNS — Domain Name Encoding/Decoding
 * RFC 1035 §4.1.4: Message Compression
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 */

import {
  MAX_LABEL_LENGTH,
  MAX_NAME_LENGTH,
  COMPRESSION_POINTER_MASK,
  COMPRESSION_OFFSET_MASK,
  MAX_COMPRESSION_POINTERS,
} from './types.js';

/**
 * Encode a domain name to wire format (label sequence ending with 0x00).
 * Does NOT apply compression — compression requires a full message context.
 *
 * "example.com" → [7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0]
 *
 * @param name  Fully-qualified domain name (trailing dot optional)
 * @returns     Wire-format bytes
 * @throws      If any label exceeds 63 octets or total exceeds 253 chars
 */
export function encodeName(name: string): Uint8Array {
  // Root domain
  if (name === '' || name === '.') {
    return new Uint8Array([0]);
  }

  // Strip trailing dot if present
  const normalized = name.endsWith('.') ? name.slice(0, -1) : name;

  if (normalized.length > MAX_NAME_LENGTH) {
    throw new RangeError(
      `Domain name exceeds ${MAX_NAME_LENGTH} characters: "${normalized.slice(0, 40)}..."`
    );
  }

  const labels = normalized.split('.');
  // Calculate total wire length: sum(1 + label.length) + 1 terminator
  let wireLen = 1; // terminating zero
  for (const label of labels) {
    if (label.length === 0) {
      throw new RangeError('Empty label in domain name');
    }
    if (label.length > MAX_LABEL_LENGTH) {
      throw new RangeError(
        `Label exceeds ${MAX_LABEL_LENGTH} octets: "${label.slice(0, 20)}..."`
      );
    }
    wireLen += 1 + label.length;
  }

  const buf = new Uint8Array(wireLen);
  let offset = 0;

  for (const label of labels) {
    buf[offset++] = label.length;
    for (let i = 0; i < label.length; i++) {
      const code = label.charCodeAt(i);
      if (code > 0x7F) {
        throw new RangeError(
          `Non-ASCII character in label at position ${i}: 0x${code.toString(16)}`
        );
      }
      buf[offset++] = code;
    }
  }

  buf[offset] = 0; // terminating zero-length label
  return buf;
}

/**
 * Result of decoding a name from a DNS message.
 */
export interface DecodedName {
  /** The decoded domain name string (without trailing dot) */
  name: string;
  /** Number of bytes consumed from the CURRENT position (not following pointers) */
  bytesRead: number;
}

/**
 * Decode a domain name from a DNS message buffer, supporting compression pointers.
 *
 * RFC 1035 §4.1.4: A pointer is indicated by the two high-order bits of the
 * first byte being 11. The OFFSET field specifies an offset from the start
 * of the message.
 *
 * @param buf     Full DNS message buffer
 * @param offset  Starting position in the buffer
 * @returns       Decoded name and bytes consumed
 * @throws        On malformed names, pointer loops, or out-of-bounds reads
 */
export function decodeName(buf: Uint8Array, offset: number): DecodedName {
  const labels: string[] = [];
  let pos = offset;
  let bytesRead = 0;
  let jumped = false;
  let pointerCount = 0;

  while (pos < buf.length) {
    const len = buf[pos];

    // End of name
    if (len === 0) {
      if (!jumped) bytesRead += 1;
      break;
    }

    // Compression pointer (two high bits = 11)
    if ((len & COMPRESSION_POINTER_MASK) === COMPRESSION_POINTER_MASK) {
      if (pos + 1 >= buf.length) {
        throw new RangeError('Compression pointer extends past buffer');
      }

      // Loop protection
      if (++pointerCount > MAX_COMPRESSION_POINTERS) {
        throw new Error('Compression pointer loop detected');
      }

      const pointerOffset = ((len & ~COMPRESSION_POINTER_MASK) << 8) | buf[pos + 1];

      if (pointerOffset >= buf.length) {
        throw new RangeError(
          `Compression pointer offset ${pointerOffset} exceeds buffer length ${buf.length}`
        );
      }

      // Forward pointers are valid per RFC, but self-referencing is not
      if (pointerOffset === pos) {
        throw new Error('Self-referencing compression pointer');
      }

      if (!jumped) {
        bytesRead += 2; // Only count pointer bytes once
        jumped = true;
      }

      pos = pointerOffset;
      continue;
    }

    // Extended label types (RFC 2671) — 01 and 10 are reserved
    if ((len & COMPRESSION_POINTER_MASK) !== 0) {
      throw new Error(`Unsupported label type: 0x${len.toString(16)}`);
    }

    // Normal label
    if (pos + 1 + len > buf.length) {
      throw new RangeError(
        `Label at offset ${pos} extends past buffer (need ${len} bytes, have ${buf.length - pos - 1})`
      );
    }

    let label = '';
    for (let i = 0; i < len; i++) {
      label += String.fromCharCode(buf[pos + 1 + i]);
    }
    labels.push(label);

    pos += 1 + len;
    if (!jumped) bytesRead += 1 + len;
  }

  // Check if we ran off the end without finding terminator
  if (pos >= buf.length && !jumped && buf[pos - 1] !== 0) {
    throw new RangeError('Name extends past end of buffer');
  }

  return {
    name: labels.join('.'),
    bytesRead,
  };
}

/**
 * Compression-aware name writer that maintains a compression table.
 * Used when encoding a full DNS message.
 */
export class NameCompressor {
  private table = new Map<string, number>();

  /**
   * Write a domain name with compression into a buffer at the given offset.
   *
   * @param buf     Target buffer (must be large enough)
   * @param offset  Write position
   * @param name    Domain name to write
   * @returns       Number of bytes written
   */
  writeName(buf: Uint8Array, offset: number, name: string): number {
    if (name === '' || name === '.') {
      buf[offset] = 0;
      return 1;
    }

    const normalized = name.endsWith('.') ? name.slice(0, -1) : name;
    const labels = normalized.split('.');
    let written = 0;

    for (let i = 0; i < labels.length; i++) {
      const suffix = labels.slice(i).join('.');

      // Check if this suffix is already in the compression table
      const existing = this.table.get(suffix.toLowerCase());
      if (existing !== undefined && existing < 0x3FFF) {
        // Write pointer
        buf[offset + written] = COMPRESSION_POINTER_MASK | (existing >> 8);
        buf[offset + written + 1] = existing & 0xFF;
        written += 2;
        return written;
      }

      // Record this suffix position for future compression
      const currentPos = offset + written;
      if (currentPos < 0x3FFF) {
        this.table.set(suffix.toLowerCase(), currentPos);
      }

      // Write label
      const label = labels[i];
      buf[offset + written] = label.length;
      written += 1;

      for (let j = 0; j < label.length; j++) {
        buf[offset + written + j] = label.charCodeAt(j);
      }
      written += label.length;
    }

    // Terminating zero
    buf[offset + written] = 0;
    written += 1;

    return written;
  }

  /** Reset compression table (use between messages) */
  reset(): void {
    this.table.clear();
  }
}

/**
 * Compare two domain names case-insensitively (RFC 4343).
 */
export function namesEqual(a: string, b: string): boolean {
  const na = a.endsWith('.') ? a.slice(0, -1) : a;
  const nb = b.endsWith('.') ? b.slice(0, -1) : b;
  return na.toLowerCase() === nb.toLowerCase();
}

/**
 * Check if `child` is a subdomain of `parent` (or equal).
 */
export function isSubdomain(child: string, parent: string): boolean {
  const c = (child.endsWith('.') ? child.slice(0, -1) : child).toLowerCase();
  const p = (parent.endsWith('.') ? parent.slice(0, -1) : parent).toLowerCase();

  if (c === p) return true;
  return c.endsWith('.' + p);
}

/**
 * Get the parent domain (strip leftmost label).
 * "sub.example.com" → "example.com"
 * "com" → ""
 */
export function parentDomain(name: string): string {
  const normalized = name.endsWith('.') ? name.slice(0, -1) : name;
  const dot = normalized.indexOf('.');
  if (dot === -1) return '';
  return normalized.slice(dot + 1);
}

/**
 * Count labels in a domain name.
 * "example.com" → 2
 * "." → 0 (root)
 */
export function labelCount(name: string): number {
  if (name === '' || name === '.') return 0;
  const normalized = name.endsWith('.') ? name.slice(0, -1) : name;
  return normalized.split('.').length;
}

/**
 * Validate a domain name for RFC compliance.
 * Returns null if valid, or an error message string.
 */
export function validateName(name: string): string | null {
  if (name === '' || name === '.') return null; // root is valid

  const normalized = name.endsWith('.') ? name.slice(0, -1) : name;

  if (normalized.length > MAX_NAME_LENGTH) {
    return `Name exceeds ${MAX_NAME_LENGTH} characters`;
  }

  const labels = normalized.split('.');
  for (const label of labels) {
    if (label.length === 0) return 'Empty label';
    if (label.length > MAX_LABEL_LENGTH) {
      return `Label "${label.slice(0, 20)}..." exceeds ${MAX_LABEL_LENGTH} octets`;
    }
    // RFC 952/1123: LDH rule (letters, digits, hyphens)
    // We check this loosely — internationalized names (IDN) use Punycode
    if (label.startsWith('-') || label.endsWith('-')) {
      return `Label "${label}" starts or ends with hyphen`;
    }
  }

  return null;
}
