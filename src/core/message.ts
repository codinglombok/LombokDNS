/**
 * LombokDNS — DNS Message Codec (Pack / Unpack)
 * RFC 1035 §4.1: Format of DNS Messages
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 */

import {
  type DNSHeader,
  type DNSQuestion,
  type DNSResourceRecord,
  type DNSMessage,
  RRType,
  RRClass,
  Opcode,
  RCode,
  HeaderFlags,
  DNS_HEADER_SIZE,
} from './types.js';
import { decodeName, NameCompressor } from './name.js';
import { decodeRData, encodeRData } from './rdata.js';

// ─── Binary Helpers (no Buffer dependency) ─────────────────────

function readU16(buf: Uint8Array, off: number): number {
  return (buf[off] << 8) | buf[off + 1];
}

function readU32(buf: Uint8Array, off: number): number {
  return ((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]) >>> 0;
}

function writeU16(buf: Uint8Array, off: number, val: number): void {
  buf[off]     = (val >> 8) & 0xFF;
  buf[off + 1] = val & 0xFF;
}

function writeU32(buf: Uint8Array, off: number, val: number): void {
  buf[off]     = (val >>> 24) & 0xFF;
  buf[off + 1] = (val >>> 16) & 0xFF;
  buf[off + 2] = (val >>> 8) & 0xFF;
  buf[off + 3] = val & 0xFF;
}

// ─── Header ────────────────────────────────────────────────────

export function decodeHeader(buf: Uint8Array): DNSHeader {
  if (buf.length < DNS_HEADER_SIZE) {
    throw new RangeError(`Buffer too short for DNS header: need ${DNS_HEADER_SIZE}, have ${buf.length}`);
  }
  return {
    id:      readU16(buf, 0),
    flags:   readU16(buf, 2),
    qdcount: readU16(buf, 4),
    ancount: readU16(buf, 6),
    nscount: readU16(buf, 8),
    arcount: readU16(buf, 10),
  };
}

export function encodeHeader(header: DNSHeader, buf: Uint8Array, off: number): void {
  writeU16(buf, off,     header.id);
  writeU16(buf, off + 2, header.flags);
  writeU16(buf, off + 4, header.qdcount);
  writeU16(buf, off + 6, header.ancount);
  writeU16(buf, off + 8, header.nscount);
  writeU16(buf, off + 10, header.arcount);
}

// ─── Header Flag Helpers ───────────────────────────────────────

export function isResponse(flags: number): boolean {
  return (flags & HeaderFlags.QR) !== 0;
}

export function isAuthoritative(flags: number): boolean {
  return (flags & HeaderFlags.AA) !== 0;
}

export function isTruncated(flags: number): boolean {
  return (flags & HeaderFlags.TC) !== 0;
}

export function isRecursionDesired(flags: number): boolean {
  return (flags & HeaderFlags.RD) !== 0;
}

export function isRecursionAvailable(flags: number): boolean {
  return (flags & HeaderFlags.RA) !== 0;
}

export function isAuthenticData(flags: number): boolean {
  return (flags & HeaderFlags.AD) !== 0;
}

export function isCheckingDisabled(flags: number): boolean {
  return (flags & HeaderFlags.CD) !== 0;
}

export function getOpcode(flags: number): Opcode {
  return ((flags >> 11) & 0x0F) as Opcode;
}

export function getRcode(flags: number): RCode {
  return (flags & 0x000F) as RCode;
}

export function buildFlags(opts: {
  qr?: boolean;
  opcode?: Opcode;
  aa?: boolean;
  tc?: boolean;
  rd?: boolean;
  ra?: boolean;
  ad?: boolean;
  cd?: boolean;
  rcode?: RCode;
}): number {
  let flags = 0;
  if (opts.qr)     flags |= HeaderFlags.QR;
  if (opts.opcode) flags |= (opts.opcode & 0x0F) << 11;
  if (opts.aa)     flags |= HeaderFlags.AA;
  if (opts.tc)     flags |= HeaderFlags.TC;
  if (opts.rd)     flags |= HeaderFlags.RD;
  if (opts.ra)     flags |= HeaderFlags.RA;
  if (opts.ad)     flags |= HeaderFlags.AD;
  if (opts.cd)     flags |= HeaderFlags.CD;
  if (opts.rcode)  flags |= opts.rcode & 0x0F;
  return flags;
}

// ─── Question Section ──────────────────────────────────────────

function decodeQuestion(buf: Uint8Array, offset: number): { question: DNSQuestion; bytesRead: number } {
  const { name, bytesRead: nameLen } = decodeName(buf, offset);
  const pos = offset + nameLen;

  if (pos + 4 > buf.length) {
    throw new RangeError('Buffer too short for question type+class');
  }

  return {
    question: {
      name,
      type: readU16(buf, pos) as RRType,
      class: readU16(buf, pos + 2) as RRClass,
    },
    bytesRead: nameLen + 4,
  };
}

// ─── Resource Record Section ───────────────────────────────────

function decodeRR(buf: Uint8Array, offset: number): { rr: DNSResourceRecord; bytesRead: number } {
  const { name, bytesRead: nameLen } = decodeName(buf, offset);
  let pos = offset + nameLen;

  if (pos + 10 > buf.length) {
    throw new RangeError('Buffer too short for RR fixed fields');
  }

  const type     = readU16(buf, pos) as RRType;
  const rrclass  = readU16(buf, pos + 2) as RRClass;
  const ttl      = readU32(buf, pos + 4);
  const rdlength = readU16(buf, pos + 8);
  pos += 10;

  if (pos + rdlength > buf.length) {
    throw new RangeError(`RDATA extends past buffer: need ${rdlength} bytes at offset ${pos}`);
  }

  const rawRdata = buf.slice(pos, pos + rdlength);

  // Try to decode known RDATA; fall back to raw bytes
  let rdata: Uint8Array | Record<string, unknown>;
  try {
    rdata = decodeRData(type, buf, pos, rdlength);
  } catch {
    rdata = rawRdata;
  }

  return {
    rr: {
      name,
      type,
      class: rrclass,
      ttl,
      rdlength,
      rdata,
    },
    bytesRead: nameLen + 10 + rdlength,
  };
}

// ─── Full Message Decode ───────────────────────────────────────

/**
 * Decode a complete DNS message from wire format.
 *
 * @param buf  Raw DNS message bytes
 * @returns    Parsed DNSMessage
 * @throws     On malformed messages
 */
export function unpack(buf: Uint8Array): DNSMessage {
  const header = decodeHeader(buf);
  let offset = DNS_HEADER_SIZE;

  // Decode questions
  const questions: DNSQuestion[] = [];
  for (let i = 0; i < header.qdcount; i++) {
    const { question, bytesRead } = decodeQuestion(buf, offset);
    questions.push(question);
    offset += bytesRead;
  }

  // Decode answers
  const answers: DNSResourceRecord[] = [];
  for (let i = 0; i < header.ancount; i++) {
    const { rr, bytesRead } = decodeRR(buf, offset);
    answers.push(rr);
    offset += bytesRead;
  }

  // Decode authorities
  const authorities: DNSResourceRecord[] = [];
  for (let i = 0; i < header.nscount; i++) {
    const { rr, bytesRead } = decodeRR(buf, offset);
    authorities.push(rr);
    offset += bytesRead;
  }

  // Decode additionals
  const additionals: DNSResourceRecord[] = [];
  for (let i = 0; i < header.arcount; i++) {
    const { rr, bytesRead } = decodeRR(buf, offset);
    additionals.push(rr);
    offset += bytesRead;
  }

  return { header, questions, answers, authorities, additionals };
}

// ─── Full Message Encode ───────────────────────────────────────

/**
 * Encode a complete DNS message to wire format.
 *
 * @param msg  DNS message to encode
 * @returns    Wire-format bytes
 */
export function pack(msg: DNSMessage): Uint8Array {
  // Pre-allocate generous buffer (resize if needed)
  const buf = new Uint8Array(65535);
  const compressor = new NameCompressor();
  let offset = DNS_HEADER_SIZE;

  // Encode questions
  for (const q of msg.questions) {
    offset += compressor.writeName(buf, offset, q.name);
    writeU16(buf, offset, q.type);
    writeU16(buf, offset + 2, q.class);
    offset += 4;
  }

  // Encode resource records for each section
  const encodeSection = (rrs: DNSResourceRecord[]) => {
    for (const rr of rrs) {
      offset += compressor.writeName(buf, offset, rr.name);
      writeU16(buf, offset, rr.type);
      writeU16(buf, offset + 2, rr.class);
      writeU32(buf, offset + 4, rr.ttl);
      // Reserve 2 bytes for RDLENGTH, encode RDATA, then patch
      const rdlengthPos = offset + 8;
      offset += 10;

      let rdataLen: number;
      if (rr.rdata instanceof Uint8Array) {
        // Raw RDATA
        buf.set(rr.rdata, offset);
        rdataLen = rr.rdata.length;
      } else {
        // Structured RDATA → encode
        rdataLen = encodeRData(rr.type, rr.rdata, buf, offset, compressor);
      }

      writeU16(buf, rdlengthPos, rdataLen);
      offset += rdataLen;
    }
  };

  encodeSection(msg.answers);
  encodeSection(msg.authorities);
  encodeSection(msg.additionals);

  // Write header (with correct counts)
  const header: DNSHeader = {
    ...msg.header,
    qdcount: msg.questions.length,
    ancount: msg.answers.length,
    nscount: msg.authorities.length,
    arcount: msg.additionals.length,
  };
  encodeHeader(header, buf, 0);

  return buf.slice(0, offset);
}

// ─── Builder Pattern ───────────────────────────────────────────

/**
 * Fluent builder for constructing DNS messages.
 */
export class MessageBuilder {
  private msg: DNSMessage;

  constructor() {
    this.msg = {
      header: {
        id: Math.floor(Math.random() * 0xFFFF),
        flags: 0,
        qdcount: 0,
        ancount: 0,
        nscount: 0,
        arcount: 0,
      },
      questions: [],
      answers: [],
      authorities: [],
      additionals: [],
    };
  }

  /** Set message ID */
  id(id: number): this {
    this.msg.header.id = id & 0xFFFF;
    return this;
  }

  /** Set header flags */
  flags(flags: number): this {
    this.msg.header.flags = flags;
    return this;
  }

  /** Set as query with recursion desired */
  query(): this {
    this.msg.header.flags = buildFlags({ rd: true });
    return this;
  }

  /** Set as response */
  response(rcode: RCode = RCode.NOERROR): this {
    this.msg.header.flags = buildFlags({ qr: true, ra: true, rcode });
    return this;
  }

  /** Add a question */
  question(name: string, type: RRType = RRType.A, rrclass: RRClass = RRClass.IN): this {
    this.msg.questions.push({ name, type, class: rrclass });
    return this;
  }

  /** Add an answer record */
  answer(rr: DNSResourceRecord): this {
    this.msg.answers.push(rr);
    return this;
  }

  /** Add an authority record */
  authority(rr: DNSResourceRecord): this {
    this.msg.authorities.push(rr);
    return this;
  }

  /** Add an additional record */
  additional(rr: DNSResourceRecord): this {
    this.msg.additionals.push(rr);
    return this;
  }

  /** Build the message object */
  build(): DNSMessage {
    return { ...this.msg };
  }

  /** Build and pack to wire format */
  pack(): Uint8Array {
    return pack(this.build());
  }
}

/**
 * Create a response message from a request.
 * Copies the ID, question section, and sets QR=1.
 */
export function createResponse(request: DNSMessage, rcode: RCode = RCode.NOERROR): DNSMessage {
  return {
    header: {
      id: request.header.id,
      flags: buildFlags({
        qr: true,
        opcode: getOpcode(request.header.flags),
        rd: isRecursionDesired(request.header.flags),
        ra: true,
        rcode,
      }),
      qdcount: request.questions.length,
      ancount: 0,
      nscount: 0,
      arcount: 0,
    },
    questions: [...request.questions],
    answers: [],
    authorities: [],
    additionals: [],
  };
}
