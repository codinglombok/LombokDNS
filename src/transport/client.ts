/**
 * LombokDNS — High-Level DNS Client
 * Apache-2.0 | github.com/codinglombok/LombokDNS
 *
 * Convenience client that wraps all transports with a simple API.
 * Handles transport selection, message building, and response parsing.
 */

import { MessageBuilder } from '../core/message.js';
import { pack } from '../core/message.js';
import { RRType, RRClass } from '../core/types.js';
import { defaultEDNS, buildEDNS } from '../core/edns.js';
import { UDPTransport } from './udp.js';
import { TCPTransport } from './tcp.js';
import { DoTTransport } from './dot.js';
import { DoHTransport, DoHEndpoints } from './doh.js';
import { DoQTransport } from './doq.js';
import {
  type DNSTransport,
  type TransportResult,
  type QueryOptions,
  TransportProtocol,
} from './types.js';

// ─── Client Options ───────────────────────────────────────────

export interface DNSClientOptions {
  /** DNS server address (default: 8.8.8.8) */
  server?: string;
  /** Server port (protocol-dependent default) */
  port?: number;
  /** Transport protocol (default: UDP) */
  protocol?: TransportProtocol;
  /** Query timeout in ms (default: 5000) */
  timeout?: number;
  /** Retries (default: 2) */
  retries?: number;
  /** Auto TCP fallback on truncation (default: true, UDP only) */
  tcpFallback?: boolean;
  /** Enable EDNS(0) with default options (default: true) */
  edns?: boolean;
  /** EDNS UDP buffer size (default: 4096) */
  ednsUdpSize?: number;
  /** Request DNSSEC validation (DO flag) (default: false) */
  dnssec?: boolean;

  // DoH-specific
  /** DoH endpoint URL */
  dohUrl?: string;
  /** DoH HTTP method */
  dohMethod?: 'POST' | 'GET';

  // TLS-specific (DoT/DoQ)
  /** TLS server name */
  servername?: string;
  /** Custom CA */
  ca?: string | string[];
}

// ─── DNS Client ───────────────────────────────────────────────

export class DNSClient {
  private transport: DNSTransport;
  private readonly edns: boolean;
  private readonly ednsUdpSize: number;
  private readonly dnssec: boolean;
  private readonly timeout: number;

  constructor(options: DNSClientOptions = {}) {
    const protocol = options.protocol ?? TransportProtocol.UDP;
    this.edns = options.edns ?? true;
    this.ednsUdpSize = options.ednsUdpSize ?? 4096;
    this.dnssec = options.dnssec ?? false;
    this.timeout = options.timeout ?? 5000;

    this.transport = this.createTransport(protocol, options);
  }

  private createTransport(
    protocol: TransportProtocol,
    options: DNSClientOptions,
  ): DNSTransport {
    const server = options.server ?? '8.8.8.8';
    const baseConfig = {
      server,
      port: options.port,
      timeout: options.timeout,
      retries: options.retries,
    };

    switch (protocol) {
      case TransportProtocol.UDP:
        return new UDPTransport(baseConfig);

      case TransportProtocol.TCP:
        return new TCPTransport(baseConfig);

      case TransportProtocol.DOT:
        return new DoTTransport({
          ...baseConfig,
          servername: options.servername,
          ca: options.ca,
        });

      case TransportProtocol.DOH:
        return new DoHTransport({
          ...baseConfig,
          url: options.dohUrl ?? DoHEndpoints.CLOUDFLARE,
          method: options.dohMethod,
        });

      case TransportProtocol.DOQ:
        return new DoQTransport({
          ...baseConfig,
          servername: options.servername,
          ca: options.ca,
        });
    }
  }

  /**
   * Resolve a domain name.
   *
   * @example
   * ```ts
   * const client = new DNSClient();
   * const result = await client.resolve('example.com', RRType.A);
   * console.log(result.response.answers);
   * ```
   */
  async resolve(
    name: string,
    type: RRType = RRType.A,
    rrClass: RRClass = RRClass.IN,
    options?: QueryOptions,
  ): Promise<TransportResult> {
    const builder = new MessageBuilder()
      .query()
      .question(name, type, rrClass);

    if (this.edns) {
      const edns = defaultEDNS({
        udpSize: this.ednsUdpSize,
        dnssecOK: this.dnssec,
      });
      builder.additional(buildEDNS(edns));
    }

    const message = builder.build();
    const packed = pack(message);
    return this.transport.query(packed, {
      timeout: options?.timeout ?? this.timeout,
      ...options,
    });
  }

  /**
   * Send a raw pre-built DNS query.
   */
  async rawQuery(
    message: Uint8Array,
    options?: QueryOptions,
  ): Promise<TransportResult> {
    return this.transport.query(message, options);
  }

  /**
   * Close the client and release transport resources.
   */
  async close(): Promise<void> {
    await this.transport.close();
  }
}

// ─── Quick Resolve Shorthand ──────────────────────────────────

/**
 * Quick one-shot DNS resolution.
 *
 * @example
 * ```ts
 * import { resolve } from 'lombokdns';
 * const result = await resolve('example.com');
 * ```
 */
export async function resolve(
  name: string,
  type: RRType = RRType.A,
  options?: DNSClientOptions & QueryOptions,
): Promise<TransportResult> {
  const client = new DNSClient(options);
  try {
    return await client.resolve(name, type, RRClass.IN, options);
  } finally {
    await client.close();
  }
}

/**
 * Quick DoH resolution via Cloudflare DNS.
 */
export async function resolveDoH(
  name: string,
  type: RRType = RRType.A,
  endpoint?: string,
): Promise<TransportResult> {
  return resolve(name, type, {
    protocol: TransportProtocol.DOH,
    dohUrl: endpoint ?? DoHEndpoints.CLOUDFLARE,
  });
}

/**
 * Quick DoT resolution.
 */
export async function resolveDoT(
  name: string,
  type: RRType = RRType.A,
  server = '1.1.1.1',
): Promise<TransportResult> {
  return resolve(name, type, {
    protocol: TransportProtocol.DOT,
    server,
  });
}
