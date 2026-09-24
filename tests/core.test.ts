/**
 * LombokDNS — Core Test Suite
 * Tests wire codec, name encoding, EDNS, zone file, and round-trip integrity
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 *
 * Run: node --test tests/core.test.ts (via tsx or tsc+node)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  encodeName, decodeName, NameCompressor, namesEqual,
  isSubdomain, parentDomain, labelCount, validateName,
} from '../src/core/name.js';

import {
  pack, unpack, MessageBuilder, createResponse,
  buildFlags, isResponse, getRcode, getOpcode,
} from '../src/core/message.js';

import {
  RRType, RRClass, RCode, Opcode, HeaderFlags,
  DNS_HEADER_SIZE, MAX_LABEL_LENGTH, MAX_NAME_LENGTH,
} from '../src/core/types.js';

import {
  EDECode, EDNSOptionCode,
} from '../src/core/types.js';

import {
  buildEDNS, parseEDNS, defaultEDNS, buildEDE, parseEDE,
  buildCookie, parseCookie, buildPadding, describeEDE,
} from '../src/core/edns.js';

import {
  parseZoneFile, serializeZoneFile, typeNameToEnum, typeEnumToName,
} from '../src/zone/zonefile.js';

import {
  generateId, randomBytes, hexToBytes, bytesToHex,
  base64Encode, base64Decode, base64UrlEncode, base64UrlDecode,
  ipv4ToBytes, bytesToIpv4, ipv6ToBytes, bytesToIpv6,
} from '../src/utils/encoding.js';

// ════════════════════════════════════════════════════════════════
// 1. Name Encoding / Decoding
// ════════════════════════════════════════════════════════════════

describe('Name Encoding', () => {
  it('encodes "example.com" correctly', () => {
    const wire = encodeName('example.com');
    // 7 e x a m p l e 3 c o m 0
    assert.equal(wire[0], 7);
    assert.equal(wire[8], 3);
    assert.equal(wire[12], 0);
    assert.equal(wire.length, 13);
  });

  it('encodes root domain', () => {
    const wire = encodeName('.');
    assert.deepEqual(wire, new Uint8Array([0]));
  });

  it('handles trailing dot', () => {
    const a = encodeName('example.com');
    const b = encodeName('example.com.');
    assert.deepEqual(a, b);
  });

  it('rejects labels > 63 octets', () => {
    const longLabel = 'a'.repeat(64) + '.com';
    assert.throws(() => encodeName(longLabel), /exceeds 63/);
  });

  it('rejects names > 253 chars', () => {
    // Create a name with many labels that exceeds 253 chars total
    const labels = [];
    for (let i = 0; i < 50; i++) labels.push('abcde');
    const longName = labels.join('.');
    if (longName.length > MAX_NAME_LENGTH) {
      assert.throws(() => encodeName(longName), /exceeds 253/);
    }
  });

  it('round-trips encode → decode', () => {
    const names = [
      'example.com',
      'sub.domain.example.org',
      'a.b.c.d.e.f.g.h.i.j.com',
      'xn--nxasmq6b.example', // Punycode
    ];

    for (const name of names) {
      const wire = encodeName(name);
      const { name: decoded } = decodeName(wire, 0);
      assert.equal(decoded, name, `Round-trip failed for "${name}"`);
    }
  });
});

describe('Name Decompression', () => {
  it('follows compression pointers', () => {
    // Build a buffer: header + name "example.com" at offset 12,
    // then a pointer to it at offset 25
    const buf = new Uint8Array(30);
    // Name at offset 0: 7 "example" 3 "com" 0
    buf[0] = 7;
    'example'.split('').forEach((c, i) => buf[1 + i] = c.charCodeAt(0));
    buf[8] = 3;
    'com'.split('').forEach((c, i) => buf[9 + i] = c.charCodeAt(0));
    buf[12] = 0;

    // Pointer at offset 13 → offset 0
    buf[13] = 0xC0;
    buf[14] = 0x00;

    const { name, bytesRead } = decodeName(buf, 13);
    assert.equal(name, 'example.com');
    assert.equal(bytesRead, 2); // Only pointer bytes counted
  });

  it('detects pointer loops', () => {
    const buf = new Uint8Array(4);
    buf[0] = 0xC0; buf[1] = 0x02;
    buf[2] = 0xC0; buf[3] = 0x00;
    assert.throws(() => decodeName(buf, 0), /loop/i);
  });

  it('detects self-referencing pointer', () => {
    const buf = new Uint8Array(2);
    buf[0] = 0xC0; buf[1] = 0x00;
    assert.throws(() => decodeName(buf, 0), /self-referencing/i);
  });
});

describe('Name Utilities', () => {
  it('namesEqual is case-insensitive', () => {
    assert.ok(namesEqual('Example.COM', 'example.com'));
    assert.ok(namesEqual('A.B.C.', 'a.b.c'));
    assert.ok(!namesEqual('a.com', 'b.com'));
  });

  it('isSubdomain works', () => {
    assert.ok(isSubdomain('sub.example.com', 'example.com'));
    assert.ok(isSubdomain('example.com', 'example.com'));
    assert.ok(!isSubdomain('example.com', 'other.com'));
  });

  it('parentDomain strips leftmost label', () => {
    assert.equal(parentDomain('sub.example.com'), 'example.com');
    assert.equal(parentDomain('example.com'), 'com');
    assert.equal(parentDomain('com'), '');
  });

  it('labelCount is correct', () => {
    assert.equal(labelCount('.'), 0);
    assert.equal(labelCount('com'), 1);
    assert.equal(labelCount('example.com'), 2);
    assert.equal(labelCount('sub.example.com.'), 3);
  });

  it('validateName catches errors', () => {
    assert.equal(validateName('.'), null); // root = valid
    assert.equal(validateName('example.com'), null);
    assert.ok(validateName('-bad.com')?.includes('hyphen'));
    assert.ok(validateName('a'.repeat(64) + '.com')?.includes('63'));
  });
});

describe('Name Compressor', () => {
  it('compresses repeated suffixes', () => {
    const compressor = new NameCompressor();
    const buf = new Uint8Array(100);

    const len1 = compressor.writeName(buf, 0, 'www.example.com');
    const len2 = compressor.writeName(buf, len1, 'mail.example.com');

    // Second name should use pointer for "example.com"
    assert.ok(len2 < encodeName('mail.example.com').length,
      'Compressed name should be shorter');

    // Verify second name decodes correctly
    const { name } = decodeName(buf, len1);
    assert.equal(name, 'mail.example.com');
  });
});

// ════════════════════════════════════════════════════════════════
// 2. Message Pack / Unpack
// ════════════════════════════════════════════════════════════════

describe('Message Codec', () => {
  it('round-trips a simple A query', () => {
    const msg = new MessageBuilder()
      .id(0x1234)
      .query()
      .question('example.com', RRType.A)
      .build();

    const wire = pack(msg);
    const decoded = unpack(wire);

    assert.equal(decoded.header.id, 0x1234);
    assert.ok(isResponse(decoded.header.flags) === false);
    assert.equal(decoded.questions.length, 1);
    assert.equal(decoded.questions[0].name, 'example.com');
    assert.equal(decoded.questions[0].type, RRType.A);
    assert.equal(decoded.questions[0].class, RRClass.IN);
  });

  it('round-trips a response with A record', () => {
    const msg = new MessageBuilder()
      .id(0x5678)
      .response()
      .question('example.com', RRType.A)
      .answer({
        name: 'example.com',
        type: RRType.A,
        class: RRClass.IN,
        ttl: 300,
        rdlength: 4,
        rdata: { address: '93.184.216.34' },
      })
      .build();

    const wire = pack(msg);
    const decoded = unpack(wire);

    assert.ok(isResponse(decoded.header.flags));
    assert.equal(getRcode(decoded.header.flags), RCode.NOERROR);
    assert.equal(decoded.answers.length, 1);

    const rdata = decoded.answers[0].rdata as Record<string, unknown>;
    assert.equal(rdata.address, '93.184.216.34');
  });

  it('round-trips MX record', () => {
    const msg = new MessageBuilder()
      .id(0xABCD)
      .response()
      .question('example.com', RRType.MX)
      .answer({
        name: 'example.com',
        type: RRType.MX,
        class: RRClass.IN,
        ttl: 3600,
        rdlength: 0,
        rdata: { preference: 10, exchange: 'mail.example.com' },
      })
      .build();

    const wire = pack(msg);
    const decoded = unpack(wire);

    const rdata = decoded.answers[0].rdata as Record<string, unknown>;
    assert.equal(rdata.preference, 10);
    assert.equal(rdata.exchange, 'mail.example.com');
  });

  it('round-trips TXT record', () => {
    const msg = new MessageBuilder()
      .id(0x1111)
      .response()
      .question('example.com', RRType.TXT)
      .answer({
        name: 'example.com',
        type: RRType.TXT,
        class: RRClass.IN,
        ttl: 300,
        rdlength: 0,
        rdata: { texts: ['v=spf1 include:_spf.google.com ~all'] },
      })
      .build();

    const wire = pack(msg);
    const decoded = unpack(wire);

    const rdata = decoded.answers[0].rdata as Record<string, unknown>;
    assert.deepEqual(rdata.texts, ['v=spf1 include:_spf.google.com ~all']);
  });

  it('round-trips SOA record', () => {
    const msg = new MessageBuilder()
      .id(0x2222)
      .response()
      .question('example.com', RRType.SOA)
      .answer({
        name: 'example.com',
        type: RRType.SOA,
        class: RRClass.IN,
        ttl: 86400,
        rdlength: 0,
        rdata: {
          mname: 'ns1.example.com',
          rname: 'hostmaster.example.com',
          serial: 2024010101,
          refresh: 3600,
          retry: 900,
          expire: 604800,
          minimum: 86400,
        },
      })
      .build();

    const wire = pack(msg);
    const decoded = unpack(wire);

    const rdata = decoded.answers[0].rdata as Record<string, unknown>;
    assert.equal(rdata.mname, 'ns1.example.com');
    assert.equal(rdata.serial, 2024010101);
  });

  it('round-trips AAAA record', () => {
    const msg = new MessageBuilder()
      .id(0x3333)
      .response()
      .question('example.com', RRType.AAAA)
      .answer({
        name: 'example.com',
        type: RRType.AAAA,
        class: RRClass.IN,
        ttl: 300,
        rdlength: 16,
        rdata: { address: '2606:2800:220:1:248:1893:25c8:1946' },
      })
      .build();

    const wire = pack(msg);
    const decoded = unpack(wire);

    const rdata = decoded.answers[0].rdata as Record<string, unknown>;
    assert.equal(rdata.address, '2606:2800:220:1:248:1893:25c8:1946');
  });

  it('round-trips SRV record', () => {
    const msg = new MessageBuilder()
      .id(0x4444)
      .response()
      .question('_http._tcp.example.com', RRType.SRV)
      .answer({
        name: '_http._tcp.example.com',
        type: RRType.SRV,
        class: RRClass.IN,
        ttl: 300,
        rdlength: 0,
        rdata: { priority: 10, weight: 60, port: 80, target: 'www.example.com' },
      })
      .build();

    const wire = pack(msg);
    const decoded = unpack(wire);

    const rdata = decoded.answers[0].rdata as Record<string, unknown>;
    assert.equal(rdata.priority, 10);
    assert.equal(rdata.weight, 60);
    assert.equal(rdata.port, 80);
    assert.equal(rdata.target, 'www.example.com');
  });

  it('createResponse copies ID and questions', () => {
    const request = new MessageBuilder()
      .id(0x9999)
      .query()
      .question('test.example.com', RRType.A)
      .build();

    const response = createResponse(request, RCode.NXDOMAIN);
    assert.equal(response.header.id, 0x9999);
    assert.ok(isResponse(response.header.flags));
    assert.equal(getRcode(response.header.flags), RCode.NXDOMAIN);
    assert.equal(response.questions.length, 1);
    assert.equal(response.questions[0].name, 'test.example.com');
  });

  it('handles multiple questions and answers', () => {
    const msg = new MessageBuilder()
      .id(0x5555)
      .response()
      .question('a.example.com', RRType.A)
      .question('b.example.com', RRType.AAAA)
      .answer({
        name: 'a.example.com', type: RRType.A, class: RRClass.IN,
        ttl: 300, rdlength: 4, rdata: { address: '1.2.3.4' },
      })
      .answer({
        name: 'b.example.com', type: RRType.AAAA, class: RRClass.IN,
        ttl: 300, rdlength: 16, rdata: { address: '2001:db8:0:0:0:0:0:1' },
      })
      .build();

    const wire = pack(msg);
    const decoded = unpack(wire);

    assert.equal(decoded.questions.length, 2);
    assert.equal(decoded.answers.length, 2);
  });

  it('rejects buffer too short for header', () => {
    assert.throws(() => unpack(new Uint8Array(6)), /too short/);
  });
});

// ════════════════════════════════════════════════════════════════
// 3. EDNS(0)
// ════════════════════════════════════════════════════════════════

describe('EDNS(0)', () => {
  it('builds and parses default EDNS OPT', () => {
    const edns = defaultEDNS({ udpSize: 4096, dnssecOK: true });
    const rr = buildEDNS(edns);
    const parsed = parseEDNS(rr);

    assert.equal(parsed.udpSize, 4096);
    assert.equal(parsed.version, 0);
    assert.equal(parsed.flags & 0x8000, 0x8000); // DO bit
  });

  it('round-trips EDE option', () => {
    const ede = buildEDE(EDECode.STALE_ANSWER, 'cached 30s ago');
    const edns = defaultEDNS({ options: [ede] });
    const rr = buildEDNS(edns);
    const parsed = parseEDNS(rr);

    assert.equal(parsed.options.length, 1);
    const edeResult = parseEDE(parsed.options[0]);
    assert.equal(edeResult.code, EDECode.STALE_ANSWER);
    assert.equal(edeResult.text, 'cached 30s ago');
  });

  it('round-trips Cookie option', () => {
    const clientCookie = randomBytes(8);
    const serverCookie = randomBytes(16);
    const opt = buildCookie(clientCookie, serverCookie);

    const edns = defaultEDNS({ options: [opt] });
    const rr = buildEDNS(edns);
    const parsed = parseEDNS(rr);
    const cookie = parseCookie(parsed.options[0]);

    assert.deepEqual(cookie.clientCookie, clientCookie);
    assert.deepEqual(cookie.serverCookie, serverCookie);
  });

  it('builds padding option', () => {
    const pad = buildPadding(128);
    assert.equal(pad.code, EDNSOptionCode.PADDING);
    assert.equal(pad.data.length, 128);
    assert.ok(pad.data.every(b => b === 0));
  });

  it('describeEDE returns human-readable text', () => {
    assert.equal(describeEDE(EDECode.BLOCKED), 'Blocked');
    assert.equal(describeEDE(EDECode.DNSSEC_BOGUS), 'DNSSEC validation failure');
    assert.ok(describeEDE(999 as EDECode).includes('Unknown'));
  });
});

// ════════════════════════════════════════════════════════════════
// 4. Zone File Parser
// ════════════════════════════════════════════════════════════════

describe('Zone File Parser', () => {
  const SAMPLE_ZONE = `
$ORIGIN example.com.
$TTL 86400

@       IN  SOA     ns1.example.com. hostmaster.example.com. (
                    2024010101  ; Serial
                    3600        ; Refresh
                    900         ; Retry
                    604800      ; Expire
                    86400 )     ; Minimum TTL

@       IN  NS      ns1.example.com.
@       IN  NS      ns2.example.com.

@       IN  A       93.184.216.34
@       IN  AAAA    2606:2800:220:1:248:1893:25c8:1946

www     IN  A       93.184.216.34
mail    IN  A       93.184.216.35

@       IN  MX  10  mail.example.com.
@       IN  TXT     "v=spf1 include:_spf.google.com ~all"

_http._tcp  IN  SRV 10 60 80 www.example.com.
`;

  it('parses $ORIGIN and $TTL', () => {
    const zone = parseZoneFile(SAMPLE_ZONE);
    assert.equal(zone.origin, 'example.com.');
    assert.equal(zone.defaultTTL, 86400);
  });

  it('parses SOA record', () => {
    const zone = parseZoneFile(SAMPLE_ZONE);
    const soa = zone.entries.find(e => e.type === RRType.SOA);
    assert.ok(soa, 'SOA record not found');
    assert.equal(soa!.rdata.serial, 2024010101);
    assert.equal(soa!.rdata.mname, 'ns1.example.com.');
  });

  it('parses A records', () => {
    const zone = parseZoneFile(SAMPLE_ZONE);
    const aRecords = zone.entries.filter(e => e.type === RRType.A);
    assert.ok(aRecords.length >= 3);

    const www = aRecords.find(e => e.name.startsWith('www'));
    assert.ok(www);
    assert.equal(www!.rdata.address, '93.184.216.34');
  });

  it('parses MX record', () => {
    const zone = parseZoneFile(SAMPLE_ZONE);
    const mx = zone.entries.find(e => e.type === RRType.MX);
    assert.ok(mx);
    assert.equal(mx!.rdata.preference, 10);
  });

  it('parses TXT record', () => {
    const zone = parseZoneFile(SAMPLE_ZONE);
    const txt = zone.entries.find(e => e.type === RRType.TXT);
    assert.ok(txt);
    const texts = txt!.rdata.texts as string[];
    assert.ok(texts[0].includes('spf1'));
  });

  it('parses SRV record', () => {
    const zone = parseZoneFile(SAMPLE_ZONE);
    const srv = zone.entries.find(e => e.type === RRType.SRV);
    assert.ok(srv);
    assert.equal(srv!.rdata.priority, 10);
    assert.equal(srv!.rdata.port, 80);
  });

  it('serializes back to text', () => {
    const zone = parseZoneFile(SAMPLE_ZONE);
    const text = serializeZoneFile(zone);
    assert.ok(text.includes('$ORIGIN example.com.'));
    assert.ok(text.includes('93.184.216.34'));
  });

  it('typeNameToEnum and typeEnumToName round-trip', () => {
    assert.equal(typeNameToEnum('A'), RRType.A);
    assert.equal(typeNameToEnum('HTTPS'), RRType.HTTPS);
    assert.equal(typeEnumToName(RRType.SVCB), 'SVCB');
    assert.equal(typeEnumToName(RRType.AAAA), 'AAAA');
  });
});

// ════════════════════════════════════════════════════════════════
// 5. Encoding Utilities
// ════════════════════════════════════════════════════════════════

describe('Encoding Utilities', () => {
  it('hex round-trip', () => {
    const original = new Uint8Array([0x00, 0xFF, 0xAB, 0x12, 0x34]);
    const hex = bytesToHex(original);
    assert.equal(hex, '00ffab1234');
    const back = hexToBytes(hex);
    assert.deepEqual(back, original);
  });

  it('base64 round-trip', () => {
    const data = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const b64 = base64Encode(data);
    assert.equal(b64, 'SGVsbG8=');
    const back = base64Decode(b64);
    assert.deepEqual(back, data);
  });

  it('base64url round-trip (DoH)', () => {
    const data = new Uint8Array([0xFF, 0xFE, 0xFD]);
    const encoded = base64UrlEncode(data);
    assert.ok(!encoded.includes('+'));
    assert.ok(!encoded.includes('/'));
    assert.ok(!encoded.includes('='));
    const back = base64UrlDecode(encoded);
    assert.deepEqual(back, data);
  });

  it('IPv4 encode/decode', () => {
    const bytes = ipv4ToBytes('192.168.1.1');
    assert.deepEqual(bytes, new Uint8Array([192, 168, 1, 1]));
    assert.equal(bytesToIpv4(bytes), '192.168.1.1');
  });

  it('IPv6 encode/decode', () => {
    const bytes = ipv6ToBytes('2001:db8::1');
    assert.equal(bytes.length, 16);
    const decoded = bytesToIpv6(bytes);
    assert.ok(decoded.startsWith('2001:db8:'));
  });

  it('generateId produces 16-bit values', () => {
    for (let i = 0; i < 100; i++) {
      const id = generateId();
      assert.ok(id >= 0 && id <= 0xFFFF);
    }
  });

  it('randomBytes produces correct length', () => {
    assert.equal(randomBytes(0).length, 0);
    assert.equal(randomBytes(32).length, 32);
    assert.equal(randomBytes(1024).length, 1024);
  });
});

// ════════════════════════════════════════════════════════════════
// 6. Header Flag Helpers
// ════════════════════════════════════════════════════════════════

describe('Header Flags', () => {
  it('buildFlags produces correct bit patterns', () => {
    const flags = buildFlags({
      qr: true,
      opcode: Opcode.QUERY,
      aa: true,
      rd: true,
      ra: true,
      rcode: RCode.NOERROR,
    });

    assert.ok(isResponse(flags));
    assert.ok((flags & HeaderFlags.AA) !== 0);
    assert.ok((flags & HeaderFlags.RD) !== 0);
    assert.ok((flags & HeaderFlags.RA) !== 0);
    assert.equal(getRcode(flags), RCode.NOERROR);
  });

  it('opcode extraction works', () => {
    const flags = buildFlags({ opcode: Opcode.NOTIFY });
    // getOpcode imported at top of file from message.js
    const extracted = getOpcode(flags);
    assert.equal(extracted, Opcode.NOTIFY);
  });
});

// ════════════════════════════════════════════════════════════════
// 7. Stress: random round-trip fuzz
// ════════════════════════════════════════════════════════════════

describe('Round-trip Fuzz (200 random queries)', () => {
  it('all survive pack → unpack', () => {
    const RECORD_TYPES = [RRType.A, RRType.AAAA, RRType.NS, RRType.CNAME,
                          RRType.MX, RRType.TXT, RRType.SRV, RRType.PTR];

    for (let trial = 0; trial < 200; trial++) {
      const id = generateId();
      const type = RECORD_TYPES[trial % RECORD_TYPES.length];
      const labels = [];
      const labelCount = 2 + (trial % 4);
      for (let l = 0; l < labelCount; l++) {
        const len = 3 + (trial % 10);
        let label = '';
        for (let c = 0; c < len; c++) {
          label += String.fromCharCode(97 + ((trial + c) % 26));
        }
        labels.push(label);
      }
      const name = labels.join('.');

      const builder = new MessageBuilder().id(id).query().question(name, type);
      const wire = pack(builder.build());
      const decoded = unpack(wire);

      assert.equal(decoded.header.id, id, `Trial ${trial}: ID mismatch`);
      assert.equal(decoded.questions.length, 1, `Trial ${trial}: question count`);
      assert.equal(decoded.questions[0].type, type, `Trial ${trial}: type mismatch`);
      assert.equal(decoded.questions[0].name, name, `Trial ${trial}: name mismatch`);
    }
  });
});
