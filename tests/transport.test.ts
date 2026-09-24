/**
 * LombokDNS — Transport Layer Tests
 * Tests for all DNS transport types: UDP, TCP, DoT, DoH, DoQ
 * Plus the high-level DNSClient
 */

import { describe, it, before, after, mock } from 'node:test';
import * as assert from 'node:assert/strict';
import * as net from 'node:net';
import * as dgram from 'node:dgram';

// ─── Core imports ────────────────────────────────────────────
import {
  MessageBuilder,
  pack,
  unpack,
  buildFlags,
  RRType,
  RRClass,
  HeaderFlags,
  type DNSMessage,
} from '../src/index.js';

// ─── Transport imports ───────────────────────────────────────
import {
  TransportProtocol,
  DEFAULT_PORTS,
  DNSTransportError,
  DNSTimeoutError,
  DNSTruncatedError,
} from '../src/transport/types.js';
import { frameTCP, deframeTCP, TCPTransport } from '../src/transport/tcp.js';
import { UDPTransport } from '../src/transport/udp.js';
import { DoTTransport } from '../src/transport/dot.js';
import { DoHTransport, DoHEndpoints } from '../src/transport/doh.js';
import { DoQTransport } from '../src/transport/doq.js';
import { DNSClient, resolve, resolveDoH, resolveDoT } from '../src/transport/client.js';

// ─── Helpers ─────────────────────────────────────────────────

/** Build a minimal DNS response to a query */
function buildResponse(query: Uint8Array, answers: { name: string; type: RRType; rdata: Uint8Array }[] = []): Uint8Array {
  const queryMsg = unpack(query);
  const builder = new MessageBuilder()
    .id(queryMsg.header.id)
    .flags(buildFlags({ qr: true, rd: true, ra: true }));

  for (const q of queryMsg.questions) {
    builder.question(q.name, q.type, q.class);
  }

  for (const a of answers) {
    builder.answer({
      name: a.name,
      type: a.type,
      class: RRClass.IN,
      ttl: 300,
      rdlength: a.rdata.length,
      rdata: a.rdata,
    });
  }

  return builder.pack();
}

/** Build a truncated response (TC bit set) */
function buildTruncatedResponse(query: Uint8Array): Uint8Array {
  const queryMsg = unpack(query);
  const builder = new MessageBuilder()
    .id(queryMsg.header.id)
    .flags(buildFlags({ qr: true, rd: true, ra: true, tc: true }));

  for (const q of queryMsg.questions) {
    builder.question(q.name, q.type, q.class);
  }

  return builder.pack();
}

/** Create a simple A record response (127.0.0.1) */
function buildARecordResponse(query: Uint8Array, name = 'example.com'): Uint8Array {
  return buildResponse(query, [{
    name,
    type: RRType.A,
    rdata: new Uint8Array([127, 0, 0, 1]),
  }]);
}

// ═══════════════════════════════════════════════════════════════
// TCP Framing
// ═══════════════════════════════════════════════════════════════

describe('TCP Framing', () => {
  it('frameTCP prepends 2-byte length prefix', () => {
    const data = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
    const framed = frameTCP(data);

    assert.equal(framed.length, 6);
    assert.equal(framed[0], 0x00); // high byte of length
    assert.equal(framed[1], 0x04); // low byte of length
    assert.deepStrictEqual(framed.slice(2), data);
  });

  it('frameTCP handles empty message', () => {
    const data = new Uint8Array(0);
    const framed = frameTCP(data);

    assert.equal(framed.length, 2);
    assert.equal(framed[0], 0x00);
    assert.equal(framed[1], 0x00);
  });

  it('frameTCP handles large messages (near 64KB)', () => {
    const data = new Uint8Array(65535);
    data[0] = 0xAA;
    data[65534] = 0xBB;
    const framed = frameTCP(data);

    assert.equal(framed.length, 65537);
    assert.equal(framed[0], 0xFF);
    assert.equal(framed[1], 0xFF);
    assert.equal(framed[2], 0xAA);
    assert.equal(framed[65536], 0xBB);
  });

  it('deframeTCP parses single complete message', () => {
    const data = new Uint8Array([0xDE, 0xAD]);
    const framed = frameTCP(data);

    const { messages, remaining } = deframeTCP(framed);

    assert.equal(messages.length, 1);
    assert.deepStrictEqual(messages[0], data);
    assert.equal(remaining.length, 0);
  });

  it('deframeTCP parses multiple messages', () => {
    const msg1 = new Uint8Array([0x01, 0x02]);
    const msg2 = new Uint8Array([0x03, 0x04, 0x05]);
    const framed1 = frameTCP(msg1);
    const framed2 = frameTCP(msg2);

    const combined = new Uint8Array(framed1.length + framed2.length);
    combined.set(framed1);
    combined.set(framed2, framed1.length);

    const { messages, remaining } = deframeTCP(combined);

    assert.equal(messages.length, 2);
    assert.deepStrictEqual(messages[0], msg1);
    assert.deepStrictEqual(messages[1], msg2);
    assert.equal(remaining.length, 0);
  });

  it('deframeTCP handles incomplete messages', () => {
    // 2-byte length says 10 bytes, but only 3 data bytes present
    const partial = new Uint8Array([0x00, 0x0A, 0x01, 0x02, 0x03]);

    const { messages, remaining } = deframeTCP(partial);

    assert.equal(messages.length, 0);
    assert.deepStrictEqual(remaining, partial);
  });

  it('deframeTCP handles complete + incomplete', () => {
    const msg1 = new Uint8Array([0xAA, 0xBB]);
    const framed1 = frameTCP(msg1);
    // Append incomplete second message
    const partial = new Uint8Array([0x00, 0x05, 0x01]);

    const combined = new Uint8Array(framed1.length + partial.length);
    combined.set(framed1);
    combined.set(partial, framed1.length);

    const { messages, remaining } = deframeTCP(combined);

    assert.equal(messages.length, 1);
    assert.deepStrictEqual(messages[0], msg1);
    assert.deepStrictEqual(remaining, partial);
  });

  it('deframeTCP handles empty buffer', () => {
    const { messages, remaining } = deframeTCP(new Uint8Array(0));
    assert.equal(messages.length, 0);
    assert.equal(remaining.length, 0);
  });

  it('deframeTCP handles single length byte (no complete header)', () => {
    const { messages, remaining } = deframeTCP(new Uint8Array([0x00]));
    assert.equal(messages.length, 0);
    assert.equal(remaining.length, 1);
  });

  it('round-trips frameTCP → deframeTCP', () => {
    const original = new Uint8Array(512);
    for (let i = 0; i < 512; i++) original[i] = i & 0xFF;

    const framed = frameTCP(original);
    const { messages } = deframeTCP(framed);

    assert.equal(messages.length, 1);
    assert.deepStrictEqual(messages[0], original);
  });
});

// ═══════════════════════════════════════════════════════════════
// Transport Protocol Enum & Constants
// ═══════════════════════════════════════════════════════════════

describe('Transport Types & Constants', () => {
  it('TransportProtocol enum has all 5 protocols', () => {
    assert.equal(TransportProtocol.UDP, 'udp');
    assert.equal(TransportProtocol.TCP, 'tcp');
    assert.equal(TransportProtocol.DOT, 'dot');
    assert.equal(TransportProtocol.DOH, 'doh');
    assert.equal(TransportProtocol.DOQ, 'doq');
  });

  it('DEFAULT_PORTS has correct values', () => {
    assert.equal(DEFAULT_PORTS[TransportProtocol.UDP], 53);
    assert.equal(DEFAULT_PORTS[TransportProtocol.TCP], 53);
    assert.equal(DEFAULT_PORTS[TransportProtocol.DOT], 853);
    assert.equal(DEFAULT_PORTS[TransportProtocol.DOH], 443);
    assert.equal(DEFAULT_PORTS[TransportProtocol.DOQ], 853);
  });

  it('DNSTransportError includes protocol and server info', () => {
    const err = new DNSTransportError(
      'test error',
      TransportProtocol.UDP,
      '8.8.8.8',
      53,
    );

    assert.equal(err.name, 'DNSTransportError');
    assert.equal(err.protocol, TransportProtocol.UDP);
    assert.equal(err.server, '8.8.8.8');
    assert.equal(err.port, 53);
    assert.ok(err.message.includes('test error'));
    assert.ok(err.message.includes('udp'));
    assert.ok(err.message.includes('8.8.8.8'));
    assert.ok(err instanceof Error);
  });

  it('DNSTimeoutError includes timeout duration', () => {
    const err = new DNSTimeoutError(
      TransportProtocol.TCP,
      '1.1.1.1',
      53,
      5000,
    );

    assert.equal(err.name, 'DNSTimeoutError');
    assert.equal(err.timeoutMs, 5000);
    assert.ok(err.message.includes('5000'));
    assert.ok(err instanceof DNSTransportError);
  });

  it('DNSTruncatedError includes truncated response', () => {
    const response = new Uint8Array([0x01, 0x02]);
    const err = new DNSTruncatedError('8.8.8.8', 53, response);

    assert.equal(err.name, 'DNSTruncatedError');
    assert.equal(err.protocol, TransportProtocol.UDP);
    assert.deepStrictEqual(err.truncatedResponse, response);
    assert.ok(err.message.includes('truncated'));
    assert.ok(err instanceof DNSTransportError);
  });

  it('DNSTransportError preserves cause', () => {
    const cause = new Error('original');
    const err = new DNSTransportError(
      'wrapper',
      TransportProtocol.DOH,
      'dns.google',
      443,
      cause,
    );

    assert.equal(err.cause, cause);
  });
});

// ═══════════════════════════════════════════════════════════════
// DoH Endpoints
// ═══════════════════════════════════════════════════════════════

describe('DoH Endpoints', () => {
  it('has standard endpoint URLs', () => {
    assert.equal(DoHEndpoints.GOOGLE, 'https://dns.google/dns-query');
    assert.equal(DoHEndpoints.CLOUDFLARE, 'https://cloudflare-dns.com/dns-query');
    assert.equal(DoHEndpoints.QUAD9, 'https://dns.quad9.net/dns-query');
    assert.ok(DoHEndpoints.OPENDNS.startsWith('https://'));
    assert.ok(DoHEndpoints.ADGUARD.startsWith('https://'));
    assert.ok(DoHEndpoints.NEXTDNS.startsWith('https://'));
    assert.ok(DoHEndpoints.MULLVAD.startsWith('https://'));
    assert.ok(DoHEndpoints.CONTROLD.startsWith('https://'));
  });

  it('all endpoints use HTTPS', () => {
    for (const [name, url] of Object.entries(DoHEndpoints)) {
      assert.ok(url.startsWith('https://'), `${name} should use HTTPS: ${url}`);
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// UDP Transport with local server
// ═══════════════════════════════════════════════════════════════

describe('UDP Transport', () => {
  let udpServer: dgram.Socket;
  let serverPort: number;

  before(async () => {
    udpServer = dgram.createSocket('udp4');
    await new Promise<void>((resolve) => {
      udpServer.bind(0, '127.0.0.1', () => {
        serverPort = udpServer.address().port;
        resolve();
      });
    });

    // Echo back a valid DNS response
    udpServer.on('message', (msg: Buffer, rinfo: dgram.RemoteInfo) => {
      const query = new Uint8Array(msg);
      const response = buildARecordResponse(query);
      udpServer.send(Buffer.from(response), rinfo.port, rinfo.address);
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      udpServer.close(() => resolve());
    });
  });

  it('resolves a query over UDP', async () => {
    const transport = new UDPTransport({
      server: '127.0.0.1',
      port: serverPort,
    });

    const query = new MessageBuilder()
      .query()
      .question('example.com', RRType.A)
      .pack();

    const result = await transport.query(query);

    assert.equal(result.protocol, TransportProtocol.UDP);
    assert.equal(result.server, '127.0.0.1');
    assert.equal(result.port, serverPort);
    assert.ok(result.rtt >= 0);
    assert.ok(result.responseSize > 0);
    assert.equal(result.response.answers.length, 1);
    assert.equal(result.response.answers[0]!.type, RRType.A);

    await transport.close();
  });

  it('times out when server does not respond', async () => {
    // Bind a server that never responds
    const silentServer = dgram.createSocket('udp4');
    const silentPort = await new Promise<number>((resolve) => {
      silentServer.bind(0, '127.0.0.1', () => {
        resolve(silentServer.address().port);
      });
    });

    const transport = new UDPTransport({
      server: '127.0.0.1',
      port: silentPort,
      timeout: 200,
      retries: 0,
    });

    const query = new MessageBuilder()
      .query()
      .question('timeout.test', RRType.A)
      .pack();

    await assert.rejects(
      () => transport.query(query, { timeout: 200, retries: 0 }),
      (err: Error) => {
        assert.ok(err instanceof DNSTimeoutError);
        return true;
      },
    );

    await transport.close();
    await new Promise<void>((r) => silentServer.close(() => r()));
  });

  it('supports abort signal', async () => {
    const silentServer = dgram.createSocket('udp4');
    const silentPort = await new Promise<number>((resolve) => {
      silentServer.bind(0, '127.0.0.1', () => {
        resolve(silentServer.address().port);
      });
    });

    const transport = new UDPTransport({
      server: '127.0.0.1',
      port: silentPort,
      timeout: 30000,
      retries: 0,
    });

    const query = new MessageBuilder()
      .query()
      .question('abort.test', RRType.A)
      .pack();

    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);

    await assert.rejects(
      () => transport.query(query, { signal: controller.signal, retries: 0 }),
      (err: Error) => {
        assert.ok(err instanceof DNSTransportError);
        assert.ok(err.message.includes('aborted'));
        return true;
      },
    );

    await transport.close();
    await new Promise<void>((r) => silentServer.close(() => r()));
  });

  it('validates query ID in response', async () => {
    // Server that returns a response with wrong ID
    const badIdServer = dgram.createSocket('udp4');
    const badIdPort = await new Promise<number>((resolve) => {
      badIdServer.bind(0, '127.0.0.1', () => {
        resolve(badIdServer.address().port);
      });
    });

    badIdServer.on('message', (msg: Buffer, rinfo: dgram.RemoteInfo) => {
      const response = buildARecordResponse(new Uint8Array(msg));
      // Corrupt the ID
      const corrupted = new Uint8Array(response);
      corrupted[0] = (corrupted[0]! + 1) & 0xFF;
      badIdServer.send(Buffer.from(corrupted), rinfo.port, rinfo.address);
    });

    const transport = new UDPTransport({
      server: '127.0.0.1',
      port: badIdPort,
      timeout: 500,
      retries: 0,
    });

    const query = new MessageBuilder()
      .query()
      .question('badid.test', RRType.A)
      .pack();

    await assert.rejects(
      () => transport.query(query, { timeout: 500, retries: 0 }),
      (err: Error) => {
        assert.ok(err instanceof DNSTransportError);
        return true;
      },
    );

    await transport.close();
    await new Promise<void>((r) => badIdServer.close(() => r()));
  });

  it('correctly sets protocol property', () => {
    const transport = new UDPTransport({ server: '127.0.0.1' });
    assert.equal(transport.protocol, TransportProtocol.UDP);
  });
});

// ═══════════════════════════════════════════════════════════════
// TCP Transport with local server
// ═══════════════════════════════════════════════════════════════

describe('TCP Transport', () => {
  let tcpServer: net.Server;
  let serverPort: number;

  before(async () => {
    tcpServer = net.createServer((socket) => {
      let buffer = new Uint8Array(0);

      socket.on('data', (chunk: Buffer) => {
        const newBuf = new Uint8Array(buffer.length + chunk.length);
        newBuf.set(buffer);
        newBuf.set(new Uint8Array(chunk), buffer.length);
        buffer = newBuf;

        // Deframe and respond
        const { messages, remaining } = deframeTCP(buffer);
        buffer = new Uint8Array(remaining);

        for (const msg of messages) {
          const response = buildARecordResponse(msg);
          const framed = frameTCP(response);
          socket.write(Buffer.from(framed));
        }
      });
    });

    serverPort = await new Promise<number>((resolve) => {
      tcpServer.listen(0, '127.0.0.1', () => {
        const addr = tcpServer.address() as net.AddressInfo;
        resolve(addr.port);
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      tcpServer.close(() => resolve());
    });
  });

  it('resolves a query over TCP', async () => {
    const transport = new TCPTransport({
      server: '127.0.0.1',
      port: serverPort,
    });

    const query = new MessageBuilder()
      .query()
      .question('example.com', RRType.A)
      .pack();

    const result = await transport.query(query);

    assert.equal(result.protocol, TransportProtocol.TCP);
    assert.equal(result.server, '127.0.0.1');
    assert.equal(result.port, serverPort);
    assert.ok(result.rtt >= 0);
    assert.ok(result.responseSize > 0);
    assert.equal(result.response.answers.length, 1);
    assert.equal(result.response.answers[0]!.type, RRType.A);

    await transport.close();
  });

  it('reuses connections for multiple queries', async () => {
    const transport = new TCPTransport({
      server: '127.0.0.1',
      port: serverPort,
      keepAlive: true,
    });

    const query1 = new MessageBuilder()
      .query()
      .question('first.com', RRType.A)
      .pack();

    const query2 = new MessageBuilder()
      .query()
      .question('second.com', RRType.A)
      .pack();

    const result1 = await transport.query(query1);
    const result2 = await transport.query(query2);

    assert.equal(result1.response.answers.length, 1);
    assert.equal(result2.response.answers.length, 1);

    await transport.close();
  });

  it('handles connection timeout', async () => {
    // Try connecting to a port that doesn't exist (should fail fast)
    const transport = new TCPTransport({
      server: '127.0.0.1',
      port: 1, // privileged port, unlikely to be listening
      timeout: 200,
      retries: 0,
    });

    const query = new MessageBuilder()
      .query()
      .question('timeout.test', RRType.A)
      .pack();

    await assert.rejects(
      () => transport.query(query, { timeout: 200, retries: 0 }),
      (err: Error) => {
        assert.ok(err instanceof DNSTransportError);
        return true;
      },
    );

    await transport.close();
  });

  it('correctly sets protocol property', () => {
    const transport = new TCPTransport({ server: '127.0.0.1' });
    assert.equal(transport.protocol, TransportProtocol.TCP);
  });

  it('close rejects pending queries', async () => {
    const silentServer = net.createServer((socket) => {
      // Accept connection but never respond to DNS queries
      socket.on('data', () => { /* swallow */ });
    });
    const silentPort = await new Promise<number>((resolve) => {
      silentServer.listen(0, '127.0.0.1', () => {
        resolve((silentServer.address() as net.AddressInfo).port);
      });
    });

    const transport = new TCPTransport({
      server: '127.0.0.1',
      port: silentPort,
      timeout: 5000,
      retries: 0,
    });

    const query = new MessageBuilder()
      .query()
      .question('close.test', RRType.A)
      .pack();

    const queryPromise = transport.query(query, { retries: 0, timeout: 5000 });

    // Give it a moment to connect and send
    await new Promise((r) => setTimeout(r, 200));

    // Close transport while query is pending
    await transport.close();

    await assert.rejects(
      () => queryPromise,
      (err: Error) => {
        assert.ok(err instanceof DNSTransportError);
        return true;
      },
    );

    await new Promise<void>((r) => silentServer.close(() => r()));
  });
});

// ═══════════════════════════════════════════════════════════════
// UDP Truncation + TCP Fallback
// ═══════════════════════════════════════════════════════════════

describe('UDP Truncation + TCP Fallback', () => {
  let udpTruncServer: dgram.Socket;
  let tcpFallbackServer: net.Server;
  let port: number;

  before(async () => {
    // UDP server that returns truncated responses
    udpTruncServer = dgram.createSocket('udp4');

    // TCP server that returns full responses
    tcpFallbackServer = net.createServer((socket) => {
      let buffer = new Uint8Array(0);
      socket.on('data', (chunk: Buffer) => {
        const newBuf = new Uint8Array(buffer.length + chunk.length);
        newBuf.set(buffer);
        newBuf.set(new Uint8Array(chunk), buffer.length);
        buffer = newBuf;

        const { messages, remaining } = deframeTCP(buffer);
        buffer = new Uint8Array(remaining);

        for (const msg of messages) {
          const response = buildARecordResponse(msg, 'example.com');
          const framed = frameTCP(response);
          socket.write(Buffer.from(framed));
        }
      });
    });

    // Both listen on the same port (different protocols)
    port = await new Promise<number>((resolve) => {
      tcpFallbackServer.listen(0, '127.0.0.1', () => {
        const addr = tcpFallbackServer.address() as net.AddressInfo;
        resolve(addr.port);
      });
    });

    await new Promise<void>((resolve) => {
      udpTruncServer.bind(port, '127.0.0.1', () => resolve());
    });

    udpTruncServer.on('message', (msg: Buffer, rinfo: dgram.RemoteInfo) => {
      const query = new Uint8Array(msg);
      const response = buildTruncatedResponse(query);
      udpTruncServer.send(Buffer.from(response), rinfo.port, rinfo.address);
    });
  });

  after(async () => {
    await new Promise<void>((r) => udpTruncServer.close(() => r()));
    await new Promise<void>((r) => tcpFallbackServer.close(() => r()));
  });

  it('falls back to TCP on truncation', async () => {
    const transport = new UDPTransport({
      server: '127.0.0.1',
      port,
    });

    const query = new MessageBuilder()
      .query()
      .question('example.com', RRType.A)
      .pack();

    const result = await transport.query(query, { tcpFallback: true });

    // Should get the full TCP response
    assert.equal(result.response.answers.length, 1);
    assert.equal(result.tcpFallback, true);

    await transport.close();
  });

  it('throws DNSTruncatedError when fallback disabled', async () => {
    const transport = new UDPTransport({
      server: '127.0.0.1',
      port,
    });

    const query = new MessageBuilder()
      .query()
      .question('example.com', RRType.A)
      .pack();

    await assert.rejects(
      () => transport.query(query, { tcpFallback: false, retries: 0 }),
      (err: Error) => {
        assert.ok(err instanceof DNSTruncatedError);
        assert.ok(err.truncatedResponse.length > 0);
        return true;
      },
    );

    await transport.close();
  });
});

// ═══════════════════════════════════════════════════════════════
// DoT Transport
// ═══════════════════════════════════════════════════════════════

describe('DoT Transport', () => {
  it('correctly sets protocol property', () => {
    const transport = new DoTTransport({ server: '1.1.1.1' });
    assert.equal(transport.protocol, TransportProtocol.DOT);
  });

  it('uses correct default port', () => {
    assert.equal(DEFAULT_PORTS[TransportProtocol.DOT], 853);
  });
});

// ═══════════════════════════════════════════════════════════════
// DoH Transport
// ═══════════════════════════════════════════════════════════════

describe('DoH Transport', () => {
  it('correctly sets protocol property', () => {
    const transport = new DoHTransport({
      server: 'dns.google',
      url: DoHEndpoints.GOOGLE,
    });
    assert.equal(transport.protocol, TransportProtocol.DOH);
  });

  it('uses correct default port', () => {
    assert.equal(DEFAULT_PORTS[TransportProtocol.DOH], 443);
  });
});

// ═══════════════════════════════════════════════════════════════
// DoQ Transport
// ═══════════════════════════════════════════════════════════════

describe('DoQ Transport', () => {
  it('correctly sets protocol property', () => {
    const transport = new DoQTransport({ server: '1.1.1.1' });
    assert.equal(transport.protocol, TransportProtocol.DOQ);
  });

  it('uses correct default port', () => {
    assert.equal(DEFAULT_PORTS[TransportProtocol.DOQ], 853);
  });

  it('throws clear error when QUIC is unavailable', async () => {
    const transport = new DoQTransport({ server: '1.1.1.1' });

    const query = new MessageBuilder()
      .query()
      .question('example.com', RRType.A)
      .pack();

    await assert.rejects(
      () => transport.query(query),
      (err: Error) => {
        assert.ok(err instanceof DNSTransportError);
        assert.ok(err.message.includes('QUIC not available'));
        return true;
      },
    );

    await transport.close();
  });
});

// ═══════════════════════════════════════════════════════════════
// DNSClient (high-level)
// ═══════════════════════════════════════════════════════════════

describe('DNSClient', () => {
  let udpServer: dgram.Socket;
  let serverPort: number;

  before(async () => {
    udpServer = dgram.createSocket('udp4');
    await new Promise<void>((resolve) => {
      udpServer.bind(0, '127.0.0.1', () => {
        serverPort = udpServer.address().port;
        resolve();
      });
    });

    udpServer.on('message', (msg: Buffer, rinfo: dgram.RemoteInfo) => {
      const query = new Uint8Array(msg);
      const response = buildARecordResponse(query);
      udpServer.send(Buffer.from(response), rinfo.port, rinfo.address);
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      udpServer.close(() => resolve());
    });
  });

  it('resolves with default options', async () => {
    const client = new DNSClient({
      server: '127.0.0.1',
      port: serverPort,
    });

    const result = await client.resolve('example.com');

    assert.equal(result.response.answers.length, 1);
    assert.equal(result.protocol, TransportProtocol.UDP);

    await client.close();
  });

  it('resolves with explicit RRType', async () => {
    const client = new DNSClient({
      server: '127.0.0.1',
      port: serverPort,
    });

    const result = await client.resolve('example.com', RRType.A);

    assert.equal(result.response.answers.length, 1);
    assert.equal(result.response.questions[0]!.type, RRType.A);

    await client.close();
  });

  it('sends EDNS by default', async () => {
    let capturedQuery: Uint8Array | null = null;
    const ednsServer = dgram.createSocket('udp4');
    const ednsPort = await new Promise<number>((resolve) => {
      ednsServer.bind(0, '127.0.0.1', () => resolve(ednsServer.address().port));
    });

    ednsServer.on('message', (msg: Buffer, rinfo: dgram.RemoteInfo) => {
      capturedQuery = new Uint8Array(msg);
      const response = buildARecordResponse(capturedQuery);
      ednsServer.send(Buffer.from(response), rinfo.port, rinfo.address);
    });

    const client = new DNSClient({
      server: '127.0.0.1',
      port: ednsPort,
      edns: true,
    });

    await client.resolve('example.com');

    // Parse the captured query to verify EDNS OPT record
    assert.ok(capturedQuery);
    const parsed = unpack(capturedQuery!);
    assert.ok(parsed.additionals.length > 0, 'should have OPT record in additionals');
    assert.equal(parsed.additionals[0]!.type, RRType.OPT, 'additional should be OPT');

    await client.close();
    await new Promise<void>((r) => ednsServer.close(() => r()));
  });

  it('sends raw query', async () => {
    const client = new DNSClient({
      server: '127.0.0.1',
      port: serverPort,
    });

    const rawQuery = new MessageBuilder()
      .query()
      .question('raw.test', RRType.A)
      .pack();

    const result = await client.rawQuery(rawQuery);

    assert.equal(result.response.answers.length, 1);

    await client.close();
  });

  it('uses TCP protocol', async () => {
    const tcpServer = net.createServer((socket) => {
      let buffer = new Uint8Array(0);
      socket.on('data', (chunk: Buffer) => {
        const newBuf = new Uint8Array(buffer.length + chunk.length);
        newBuf.set(buffer);
        newBuf.set(new Uint8Array(chunk), buffer.length);
        buffer = newBuf;

        const { messages, remaining } = deframeTCP(buffer);
        buffer = new Uint8Array(remaining);

        for (const msg of messages) {
          const response = buildARecordResponse(msg);
          socket.write(Buffer.from(frameTCP(response)));
        }
      });
    });

    const tcpPort = await new Promise<number>((resolve) => {
      tcpServer.listen(0, '127.0.0.1', () => {
        resolve((tcpServer.address() as net.AddressInfo).port);
      });
    });

    const client = new DNSClient({
      server: '127.0.0.1',
      port: tcpPort,
      protocol: TransportProtocol.TCP,
    });

    const result = await client.resolve('example.com');

    assert.equal(result.protocol, TransportProtocol.TCP);
    assert.equal(result.response.answers.length, 1);

    await client.close();
    await new Promise<void>((r) => tcpServer.close(() => r()));
  });
});

// ═══════════════════════════════════════════════════════════════
// MessageBuilder integration with transports
// ═══════════════════════════════════════════════════════════════

describe('MessageBuilder transport integration', () => {
  it('builds query suitable for transport', () => {
    const query = new MessageBuilder()
      .query()
      .question('example.com', RRType.A)
      .pack();

    // Must be at least header (12 bytes) + question
    assert.ok(query.length >= 12);

    // Parse it back
    const parsed = unpack(query);
    assert.equal(parsed.questions.length, 1);
    assert.equal(parsed.questions[0]!.name, 'example.com');
    assert.equal(parsed.questions[0]!.type, RRType.A);

    // RD flag should be set
    assert.ok(parsed.header.flags & HeaderFlags.RD);

    // QR flag should NOT be set (it's a query)
    assert.equal(parsed.header.flags & HeaderFlags.QR, 0);
  });

  it('builds multi-question query', () => {
    const query = new MessageBuilder()
      .query()
      .question('example.com', RRType.A)
      .question('example.com', RRType.AAAA)
      .question('example.com', RRType.MX)
      .pack();

    const parsed = unpack(query);
    assert.equal(parsed.questions.length, 3);
    assert.equal(parsed.questions[0]!.type, RRType.A);
    assert.equal(parsed.questions[1]!.type, RRType.AAAA);
    assert.equal(parsed.questions[2]!.type, RRType.MX);
  });
});
